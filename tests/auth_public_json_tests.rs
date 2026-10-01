use rustscript_agent::RunCancellation;
use rustscript_agent::auth::{
    host::{AuthHost, auth_host_catalog, auth_host_module},
    oauth::{
        OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
        ScriptedHttpsTransport,
    },
};
use rustscript_agent::runtime::{AuthCommandInput, AuthEntryRunner};
use rustscript_vm::{
    CapabilityProfile, CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm,
    VmStatus, compile_source_with_flavor_and_options,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const AUTH_ENTRY_TRANSPORT_PROOF_RSS: &str = r#"
pub fn run(home: resource<auth.host_home>, command: map) -> map {
    let snapshot_result = config::load_snapshot(&home);
    let policy_generation = snapshot_result.policy_generation;
    let request = {
        policy_handle: snapshot_result.policy_handle,
        credential_id: "fixture-codex",
        method: "GET",
        path: "/oauth/token",
        public_headers: [{name: "accept", value: "application/json"}],
        public_body: ""
    };
    let usage = {kind: "none"};
    let response = oauth::transport(&request, &usage);
    let body = response.body_without_secret_fields;
    let field_policy = config::load_snapshot(&home).policy_handle;
    let public_name = oauth::public_json_field(&field_policy, body.copy(), "/profile/name");
    let public_generation = oauth::public_json_field(&field_policy, body.copy(), "/profile/generation");
    let access_token_field = oauth::public_json_field(&field_policy, body.copy(), "/access_token");
    let refresh_token_field = oauth::public_json_field(&field_policy, body, "/refresh_token");
    let sanitized_secrets_missing = access_token_field.kind == "missing"
        && refresh_token_field.kind == "missing";
    if public_name.string_value.copy() != null && public_generation.int_value.copy() != null && sanitized_secrets_missing => {
        let name: string = public_name.string_value;
        let generation: int = public_generation.int_value;
        {
            ok: response.ok && sanitized_secrets_missing,
            operation: command.operation,
            credential_id: command.credential_id,
            generation: generation,
            status: name,
            error: null
        }
    } else => {
        {
            ok: false,
            operation: command.operation,
            credential_id: command.credential_id,
            generation: policy_generation,
            status: "public_fields_missing",
            error: "public_fields_missing"
        }
    }
}
"#;

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new() -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned temp"));
        let home = root.join(format!(
            "auth-public-json-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&home).expect("private auth home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), home.join("config.yaml"))
            .expect("copy config fixture");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read auth fixture")
            .replace("1788440000000", "1900000000000");
        fs::write(home.join("auth.yaml"), auth).expect("write auth fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                    .expect("file mode");
            }
        }
        Self(home)
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

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected result map, got {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing result field {name}"))
}

fn assert_envelope_shape(value: &Value) {
    let Value::Map(entries) = value else {
        panic!("expected named envelope, got {value:?}");
    };
    let mut fields = entries
        .iter()
        .filter_map(|(key, _)| match key {
            Value::String(key) => Some(key.as_ref().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "bool_value",
            "float_value",
            "int_value",
            "kind",
            "length",
            "string_value",
        ]
    );
}

fn bound_vm(home: &FixtureHome) -> (Vm, AuthHost, Value, Value) {
    let source = include_str!("../rss/auth/public_json_contract.rss");
    let catalog = auth_host_catalog();
    let compiled = compile_source_with_flavor_and_options(
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile exact auth RSS catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("synthetic auth host");
    auth.register(&mut registry, catalog.as_ref())
        .expect("register exact auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted registry");
    assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
    let bound = auth.bind_vm(&mut vm).expect("bind synthetic host home");
    let host_home = field(&bound, "host_home").clone();
    let snapshot = vm
        .resolve_exported_callable("snapshot")
        .expect("RSS snapshot");
    let policy = vm
        .invoke_callable(snapshot, std::slice::from_ref(&host_home))
        .expect("RSS policy snapshot");
    (vm, auth, policy, host_home)
}

fn vm_with_public_json_policy(auth: &AuthHost) -> (Vm, Value) {
    let source = include_str!("../rss/auth/public_json_contract.rss");
    let catalog = auth_host_catalog();
    let compiled = compile_source_with_flavor_and_options(
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile exact auth RSS catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog.as_ref())
        .expect("register exact auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted registry");
    assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
    let bound = auth.bind_vm(&mut vm).expect("bind synthetic host home");
    let host_home = field(&bound, "host_home").clone();
    let snapshot = vm
        .resolve_exported_callable("snapshot")
        .expect("RSS snapshot");
    let policy = vm
        .invoke_callable(snapshot, std::slice::from_ref(&host_home))
        .expect("RSS policy snapshot");
    (vm, policy)
}

#[test]
fn runner_reads_nested_sanitized_public_json_fields() {
    let source = format!(
        "{}\n{}",
        include_str!("../rss/auth/public_json_contract.rss"),
        AUTH_ENTRY_TRANSPORT_PROOF_RSS
    );
    compile_source_with_flavor_and_options(
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(auth_host_catalog()),
    )
    .unwrap_or_else(|error| panic!("compile against exact auth catalog: {error}"));
    let runner = AuthEntryRunner::from_source(&source).expect("compile auth JSON RSS entry");
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        r#"{"access_token":"SYNTHETIC_ACCESS_TOKEN","refresh_token":"SYNTHETIC_REFRESH_TOKEN","profile":{"name":"synthetic-account","generation":23}}"#,
    );
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(15));
    let result = runner
        .run(
            home.0.clone(),
            AuthCommandInput {
                operation: "public_json".into(),
                provider: None,
                credential_id: Some("fixture-codex".into()),
            },
            &cancellation,
            Some(oauth),
        )
        .expect("run sanitized transport through confined AuthEntryRunner");
    assert_eq!(field(&result, "ok"), &Value::Bool(true));
    assert_eq!(field(&result, "operation"), &Value::string("public_json"));
    assert_eq!(
        field(&result, "credential_id"),
        &Value::string("fixture-codex")
    );
    assert_eq!(field(&result, "generation"), &Value::Int(23));
    assert_eq!(
        field(&result, "status"),
        &Value::string("synthetic-account")
    );
    for secret in ["SYNTHETIC_ACCESS_TOKEN", "SYNTHETIC_REFRESH_TOKEN"] {
        assert!(!format!("{result:?}").contains(secret));
    }
    assert_eq!(transport.take_sent().len(), 1);
    assert!(!cancellation.watcher_is_armed());
}

#[test]
fn public_json_field_reports_only_object_and_array_lengths() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let json = r#"{"nested":{"name":"public","count":4},"items":[1,2,3]}"#;
    let initial_count = vm.host_context().resource_count();
    assert_eq!(initial_count, 2, "home and policy resources only");
    for (pointer, kind, length) in [("/nested", "object", 2), ("/items", "array", 3)] {
        let value = vm
            .invoke_callable(
                field_call.clone(),
                &[policy.clone(), Value::string(json), Value::string(pointer)],
            )
            .expect("container facts");
        assert_eq!(field(&value, "kind"), &Value::string(kind));
        assert_eq!(field(&value, "length"), &Value::Int(length));
        assert!(matches!(field(&value, "string_value"), Value::Null));
        assert!(matches!(field(&value, "int_value"), Value::Null));
        assert!(matches!(field(&value, "float_value"), Value::Null));
        assert!(matches!(field(&value, "bool_value"), Value::Null));
        assert_eq!(vm.host_context().resource_count(), initial_count);
    }
}

#[test]
fn public_json_field_preserves_boolean_scalar_type() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let value = vm
        .invoke_callable(
            field_call,
            &[
                policy,
                Value::string(r#"{"enabled":true}"#),
                Value::string("/enabled"),
            ],
        )
        .expect("boolean scalar");
    assert_eq!(field(&value, "kind"), &Value::string("bool"));
    assert_eq!(field(&value, "bool_value"), &Value::Bool(true));
    for name in ["string_value", "int_value", "float_value", "length"] {
        assert!(matches!(field(&value, name), Value::Null), "{name}");
    }
}

#[test]
fn public_json_field_distinguishes_json_null_from_missing() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let json = r#"{"present":null}"#;
    let initial_count = vm.host_context().resource_count();
    for (pointer, expected_kind) in [("/present", "null"), ("/absent", "missing")] {
        let value = vm
            .invoke_callable(
                field_call.clone(),
                &[policy.clone(), Value::string(json), Value::string(pointer)],
            )
            .expect("null or missing fact");
        assert_eq!(field(&value, "kind"), &Value::string(expected_kind));
        for name in [
            "string_value",
            "int_value",
            "float_value",
            "bool_value",
            "length",
        ] {
            assert!(matches!(field(&value, name), Value::Null), "{name}");
        }
        assert_eq!(vm.host_context().resource_count(), initial_count);
    }
}

#[test]
fn public_json_field_preserves_finite_float_scalar_type() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let value = vm
        .invoke_callable(
            field_call,
            &[
                policy,
                Value::string(r#"{"ratio":1.25}"#),
                Value::string("/ratio"),
            ],
        )
        .expect("finite float scalar");
    assert_eq!(field(&value, "kind"), &Value::string("float"));
    assert_eq!(field(&value, "float_value"), &Value::Float(1.25));
    for name in ["string_value", "int_value", "bool_value", "length"] {
        assert!(matches!(field(&value, name), Value::Null), "{name}");
    }
}

#[test]
fn public_json_field_preserves_zero_mantissa_with_nonzero_exponents() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let json = r#"{"positive_zero":0.0e1,"negative_zero":-0.0e-9,"tiny":1e-4000,"sibling":23}"#;
    for (pointer, negative) in [("/positive_zero", false), ("/negative_zero", true)] {
        let value = vm
            .invoke_callable(
                field_call.clone(),
                &[policy.clone(), Value::string(json), Value::string(pointer)],
            )
            .expect("zero mantissa remains a finite float");
        assert_eq!(field(&value, "kind"), &Value::string("float"));
        let Value::Float(actual) = field(&value, "float_value") else {
            panic!("zero mantissa float carrier");
        };
        assert_eq!(*actual, 0.0);
        assert_eq!(actual.is_sign_negative(), negative);
    }

    let underflow = vm
        .invoke_callable(
            field_call.clone(),
            &[policy.clone(), Value::string(json), Value::string("/tiny")],
        )
        .expect_err("nonzero underflow remains out of range");
    assert!(
        underflow
            .to_string()
            .contains("public_json_number_out_of_range")
    );

    let sibling = vm
        .invoke_callable(
            field_call,
            &[policy, Value::string(json), Value::string("/sibling")],
        )
        .expect("unaffected sibling field remains readable");
    assert_eq!(field(&sibling, "kind"), &Value::string("int"));
    assert_eq!(field(&sibling, "int_value"), &Value::Int(23));
}

#[test]
fn public_json_field_rejects_duplicate_and_escaped_equivalent_keys() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let initial_count = vm.host_context().resource_count();
    let duplicate_json = r#"{"k":1,"k":2}"#;
    let escaped_duplicate_json = format!(r#"{{"k":1,"{}u006b":2}}"#, char::from(92));
    for json in [duplicate_json.to_owned(), escaped_duplicate_json] {
        let failure = vm
            .invoke_callable(
                field_call.clone(),
                &[
                    policy.clone(),
                    Value::string(json.as_str()),
                    Value::string("/k"),
                ],
            )
            .expect_err("duplicate object keys must be rejected");
        let rendered = failure.to_string();
        assert!(rendered.contains("public_json_invalid"), "{rendered}");
        assert!(
            !rendered.contains(json.as_str()),
            "input leaked: {rendered}"
        );
        assert_eq!(vm.host_context().resource_count(), initial_count);
    }
}

#[test]
fn public_json_field_rejects_invalid_bounded_pointer_syntax() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let invalid = [
        "plain".to_owned(),
        "/bad~2escape".to_owned(),
        "/dangling~".to_owned(),
        "/a".repeat(65),
        format!("/{}", "x".repeat(2048)),
    ];
    let initial_count = vm.host_context().resource_count();
    for pointer in invalid {
        let failure = vm
            .invoke_callable(
                field_call.clone(),
                &[
                    policy.clone(),
                    Value::string(r#"{"x":1}"#),
                    Value::string(pointer.as_str()),
                ],
            )
            .expect_err("invalid JSON Pointer");
        let rendered = failure.to_string();
        assert!(
            rendered.contains("public_json_pointer_invalid"),
            "{rendered}"
        );
        assert!(!rendered.contains(&pointer), "pointer leaked: {rendered}");
        assert_eq!(vm.host_context().resource_count(), initial_count);
    }
}

#[test]
fn public_json_field_enforces_json_byte_boundary() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let at_limit = format!("\"{}\"", "x".repeat(65_534));
    assert_eq!(at_limit.len(), 65_536);
    let value = vm
        .invoke_callable(
            field_call.clone(),
            &[policy.clone(), Value::string(at_limit), Value::string("")],
        )
        .expect("exact JSON byte limit");
    assert_eq!(field(&value, "kind"), &Value::string("string"));
    let Value::String(selected) = field(&value, "string_value") else {
        panic!("selected string carrier");
    };
    assert_eq!(selected.len(), 65_534);
    let too_large = format!("\"{}\"", "x".repeat(65_535));
    assert_eq!(too_large.len(), 65_537);
    let failure = vm
        .invoke_callable(
            field_call,
            &[policy, Value::string(too_large), Value::string("")],
        )
        .expect_err("JSON over byte limit");
    assert!(failure.to_string().contains("public_json_too_large"));
}

#[test]
fn public_json_field_enforces_decoded_depth_boundary() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let initial_count = vm.host_context().resource_count();
    let at_limit = format!("{}0{}", "[".repeat(63), "]".repeat(63));
    let value = vm
        .invoke_callable(
            field_call.clone(),
            &[policy.clone(), Value::string(at_limit), Value::string("")],
        )
        .expect("root depth 1 through leaf depth 64");
    assert_eq!(field(&value, "kind"), &Value::string("array"));
    assert_eq!(field(&value, "length"), &Value::Int(1));
    assert_eq!(vm.host_context().resource_count(), initial_count);
    let too_deep = format!("{}0{}", "[".repeat(64), "]".repeat(64));
    let failure = vm
        .invoke_callable(
            field_call.clone(),
            &[policy.clone(), Value::string(too_deep), Value::string("")],
        )
        .expect_err("depth above 64");
    assert!(failure.to_string().contains("public_json_too_deep"));
    let parser_limit = format!("{}0{}", "[".repeat(129), "]".repeat(129));
    let failure = vm
        .invoke_callable(
            field_call,
            &[policy, Value::string(parser_limit), Value::string("")],
        )
        .expect_err("serde recursion limit");
    assert!(failure.to_string().contains("public_json_invalid"));
    assert_eq!(vm.host_context().resource_count(), initial_count);
}

#[test]
fn public_json_field_uses_rfc6901_and_canonical_array_index_rules() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let json = r#"{"a/b":"slash","m~n":"tilde","":"empty","items":[17]}"#;
    let initial_count = vm.host_context().resource_count();
    for (pointer, kind, string_value, int_value, length) in [
        ("/a~1b", "string", Some("slash"), None, None),
        ("/m~0n", "string", Some("tilde"), None, None),
        ("/", "string", Some("empty"), None, None),
        ("/items/0", "int", None, Some(17), None),
        ("/items/01", "missing", None, None, None),
        ("/items/-", "missing", None, None, None),
        ("/items/9", "missing", None, None, None),
        ("/items/0/name", "missing", None, None, None),
        ("", "object", None, None, Some(4)),
    ] {
        let value = vm
            .invoke_callable(
                field_call.clone(),
                &[policy.clone(), Value::string(json), Value::string(pointer)],
            )
            .expect("RFC6901 pointer result");
        assert_envelope_shape(&value);
        assert_eq!(field(&value, "kind"), &Value::string(kind), "{pointer}");
        assert_eq!(
            field(&value, "string_value"),
            &string_value.map(Value::string).unwrap_or(Value::Null),
            "{pointer}"
        );
        assert_eq!(
            field(&value, "int_value"),
            &int_value.map(Value::Int).unwrap_or(Value::Null),
            "{pointer}"
        );
        assert_eq!(
            field(&value, "length"),
            &length.map(Value::Int).unwrap_or(Value::Null),
            "{pointer}"
        );
        assert!(
            matches!(field(&value, "float_value"), Value::Null),
            "{pointer}"
        );
        assert!(
            matches!(field(&value, "bool_value"), Value::Null),
            "{pointer}"
        );
        assert_eq!(vm.host_context().resource_count(), initial_count);
    }
}

#[test]
fn public_json_field_keeps_integer_range_exact() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    for (number, expected) in [
        ("9223372036854775807", i64::MAX),
        ("-9223372036854775808", i64::MIN),
    ] {
        let json = format!("{{\"n\":{number}}}");
        let value = vm
            .invoke_callable(
                field_call.clone(),
                &[policy.clone(), Value::string(json), Value::string("/n")],
            )
            .expect("i64 boundary value");
        assert_eq!(field(&value, "kind"), &Value::string("int"));
        assert_eq!(field(&value, "int_value"), &Value::Int(expected));
    }
    for number in ["9223372036854775808", "-9223372036854775809"] {
        let json = format!("{{\"n\":{number}}}");
        let failure = vm
            .invoke_callable(
                field_call.clone(),
                &[policy.clone(), Value::string(json), Value::string("/n")],
            )
            .expect_err("integer outside i64 range");
        let rendered = failure.to_string();
        assert!(
            rendered.contains("public_json_number_out_of_range"),
            "{rendered}"
        );
        assert!(!rendered.contains(number), "number leaked: {rendered}");
    }
}

#[test]
fn public_json_field_rejects_unrepresentable_selected_float() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    for (json, expected_float) in [
        (r#"{"n":1e400}"#, None),
        (r#"{"n":1e-4000}"#, None),
        (r#"{"bad":1e400,"n":1.25}"#, Some(1.25)),
    ] {
        let result = vm.invoke_callable(
            field_call.clone(),
            &[policy.clone(), Value::string(json), Value::string("/n")],
        );
        if let Some(expected_float) = expected_float {
            let value = result.expect("unselected out-of-range float is ignored");
            assert_eq!(field(&value, "kind"), &Value::string("float"));
            assert_eq!(field(&value, "float_value"), &Value::Float(expected_float));
        } else {
            let failure = result.expect_err("non-finite or underflowed selected float");
            let rendered = failure.to_string();
            assert!(
                rendered.contains("public_json_number_out_of_range"),
                "{rendered}"
            );
            assert!(!rendered.contains(json), "number leaked: {rendered}");
        }
    }
}

#[test]
fn public_json_field_only_errors_for_the_selected_out_of_range_number() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let json = r#"{"selected":{"name":"public"},"unrelated":[9223372036854775808,1e400,1e-4000]}"#;
    let initial_count = vm.host_context().resource_count();

    let selected = vm
        .invoke_callable(
            field_call.clone(),
            &[
                policy.clone(),
                Value::string(json),
                Value::string("/selected/name"),
            ],
        )
        .expect("unselected range failures do not block nested string selection");
    assert_eq!(field(&selected, "kind"), &Value::string("string"));
    assert_eq!(field(&selected, "string_value"), &Value::string("public"));
    assert_eq!(vm.host_context().resource_count(), initial_count);

    for pointer in ["/unrelated/0", "/unrelated/1", "/unrelated/2"] {
        let failure = vm
            .invoke_callable(
                field_call.clone(),
                &[policy.clone(), Value::string(json), Value::string(pointer)],
            )
            .expect_err("selected out-of-range numeric value is rejected");
        assert!(
            failure
                .to_string()
                .contains("public_json_number_out_of_range")
        );
        assert_eq!(vm.host_context().resource_count(), initial_count);
    }
}

#[test]
fn public_json_field_rejects_invalid_json_and_trailing_data_redacted() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let initial_count = vm.host_context().resource_count();
    for json in ["{\"value\":", "{} trailing", "{\"value\":01}"] {
        let failure = vm
            .invoke_callable(
                field_call.clone(),
                &[policy.clone(), Value::string(json), Value::string("/value")],
            )
            .expect_err("malformed or trailing JSON");
        let rendered = failure.to_string();
        assert!(rendered.contains("public_json_invalid"), "{rendered}");
        assert!(!rendered.contains(json), "input leaked: {rendered}");
        assert_eq!(vm.host_context().resource_count(), initial_count);
    }
}

#[test]
fn public_json_field_rejects_revoked_policy_without_resource_changes() {
    let home = FixtureHome::new();
    let (mut vm, auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let initial_count = vm.host_context().resource_count();
    auth.revoke();
    let failure = vm
        .invoke_callable(
            field_call,
            &[
                policy,
                Value::string(r#"{"value":"public"}"#),
                Value::string("/value"),
            ],
        )
        .expect_err("revoked policy is inactive");
    assert!(failure.to_string().contains("policy_inactive"));
    assert_eq!(vm.host_context().resource_count(), initial_count);
}

#[test]
fn public_json_field_rejects_wrong_resource_class_without_leaks() {
    let home = FixtureHome::new();
    let (mut vm, _auth, _policy, host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let initial_count = vm.host_context().resource_count();
    let failure = vm
        .invoke_callable(
            field_call,
            &[
                host_home,
                Value::string(r#"{"value":"public"}"#),
                Value::string("/value"),
            ],
        )
        .expect_err("host home is not a policy resource");
    assert!(!failure.to_string().contains("public"));
    assert_eq!(vm.host_context().resource_count(), initial_count);
}

#[test]
fn public_json_field_rejects_stale_policy_after_vm_reset_without_leaks() {
    let home = FixtureHome::new();
    let (mut vm, _auth, stale_policy, _host_home) = bound_vm(&home);
    vm.reset_for_reuse().expect("reset resource arena");
    assert!(matches!(
        vm.run().expect("RSS root after reset"),
        VmStatus::Halted
    ));
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let initial_count = vm.host_context().resource_count();
    let failure = vm
        .invoke_callable(
            field_call,
            &[
                stale_policy,
                Value::string(r#"{"value":"public"}"#),
                Value::string("/value"),
            ],
        )
        .expect_err("stale policy handle must reject");
    assert!(!failure.to_string().contains("public"));
    assert_eq!(vm.host_context().resource_count(), initial_count);
}

#[test]
fn public_json_field_accepts_exact_pointer_byte_and_token_limits() {
    let home = FixtureHome::new();
    let (mut vm, _auth, policy, _host_home) = bound_vm(&home);
    let field_call = vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let max_bytes = format!("/{}", "x".repeat(2047));
    let max_tokens = "/x".repeat(64);
    assert_eq!(max_bytes.len(), 2048);
    assert_eq!(max_tokens.matches('/').count(), 64);
    let initial_count = vm.host_context().resource_count();
    for pointer in [max_bytes, max_tokens] {
        let value = vm
            .invoke_callable(
                field_call.clone(),
                &[
                    policy.clone(),
                    Value::string("{}"),
                    Value::string(pointer.as_str()),
                ],
            )
            .expect("exact pointer limits are accepted");
        assert_eq!(field(&value, "kind"), &Value::string("missing"));
        assert_eq!(vm.host_context().resource_count(), initial_count);
    }
}

#[test]
fn public_json_field_rejects_foreign_vm_policy_without_resource_changes() {
    let home = FixtureHome::new();
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("synthetic auth host");
    let (_origin_vm, foreign_policy) = vm_with_public_json_policy(&auth);
    let (mut target_vm, _target_policy) = vm_with_public_json_policy(&auth);
    let field_call = target_vm
        .resolve_exported_callable("field")
        .expect("RSS field wrapper");
    let initial_count = target_vm.host_context().resource_count();
    let failure = target_vm
        .invoke_callable(
            field_call,
            &[
                foreign_policy,
                Value::string(r#"{"value":"public"}"#),
                Value::string("/value"),
            ],
        )
        .expect_err("foreign policy handle must not cross VM arenas");
    assert!(!failure.to_string().contains("public"));
    assert_eq!(target_vm.host_context().resource_count(), initial_count);
}

#[test]
fn auth_entry_runner_denies_non_auth_import_roots() {
    for root in ["json", "http", "fs", "sqlite"] {
        let source = format!("use {root}; pub fn run() -> string {{ \"ok\" }}");
        let error = match AuthEntryRunner::from_source(&source) {
            Err(error) => error,
            Ok(_) => panic!("non-auth root {root} must be denied"),
        };
        assert_eq!(error.code(), "auth_import_denied", "{root}");
    }
}

#[test]
fn restricted_auth_binding_does_not_authorize_standard_json_builtin() {
    let source = "use json; pub fn invoke() -> string { json::encode(1) }";
    let home = FixtureHome::new();
    let (_base_vm, auth, _policy, _host_home) = bound_vm(&home);
    let catalog = auth_host_catalog();
    let compiled = compile_source_with_flavor_and_options(
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile against catalog metadata");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::empty();
    registry.set_capability_profile(CapabilityProfile::deny_all());
    auth.register(&mut registry, catalog.as_ref())
        .expect("register exact auth descriptors");
    registry.set_capability_profile(CapabilityProfile::deny_all());
    for descriptor in auth_host_module().descriptors() {
        registry.authorize_registered_builtin_import(&descriptor.schema.name);
    }
    let rejected = registry.bind_vm_cached(&mut vm).is_err()
        || vm.run().is_err()
        || vm
            .resolve_exported_callable("invoke")
            .map(|callable| vm.invoke_callable(callable, &[]).is_err())
            .unwrap_or(true);
    assert!(
        rejected,
        "standard json builtin must remain unavailable to the restricted auth registry"
    );
}
