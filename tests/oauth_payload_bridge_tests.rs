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
use std::{fs, path::PathBuf, sync::Arc, time::Duration};

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new() -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP"));
        let path = root.join(format!("oauth-payload-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).expect("private fixture home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml")).expect("copy config");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read synthetic auth")
            .replace("1788440000000", "1900000000000");
        fs::write(path.join("auth.yaml"), auth).expect("copy synthetic auth");
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
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn vm_for(auth: &AuthHost) -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/payload_contract.rss");
    let source = fs::read_to_string(&path).expect("real payload contract RSS");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile actual payload contract against auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog.as_ref())
        .expect("register exact auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted catalog");
    assert!(matches!(vm.run().expect("run RSS root"), VmStatus::Halted));
    vm
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected named record, got {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing field {name} in {value:?}"))
}

fn record(fields: Vec<(&str, Value)>) -> Value {
    Value::map(
        fields
            .into_iter()
            .map(|(name, value)| (Value::string(name), value))
            .collect(),
    )
}

fn call_result(vm: &mut Vm, name: &str, args: &[Value]) -> Result<Value, rustscript_vm::VmError> {
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args)
}

fn call(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    call_result(vm, name, args).expect("RSS call")
}

fn payload(encoding: &str, secret_fields: &str, selector: Option<(&str, &str)>) -> Value {
    let mut fields = vec![
        ("encoding", Value::string(encoding)),
        ("secret_fields", Value::string(secret_fields)),
    ];
    if let Some((name, value)) = selector {
        fields.push((name, Value::string(value)));
    }
    record(fields)
}

fn request(policy: Value, body: &str) -> Value {
    request_for_credential(policy, "fixture-codex", body)
}

fn request_for_credential(policy: Value, credential_id: &str, body: &str) -> Value {
    request_with_headers_for_credential(
        policy,
        credential_id,
        body,
        vec![("content-type", "application/json")],
    )
}

fn request_with_content_type(policy: Value, body: &str, content_type: Option<&str>) -> Value {
    let headers = content_type
        .map(|content_type| vec![("content-type", content_type)])
        .unwrap_or_default();
    request_with_headers_for_credential(policy, "fixture-codex", body, headers)
}

fn request_with_headers(policy: Value, body: &str, headers: Vec<(&str, &str)>) -> Value {
    request_with_headers_for_credential(policy, "fixture-codex", body, headers)
}

fn request_with_headers_for_credential(
    policy: Value,
    credential_id: &str,
    body: &str,
    headers: Vec<(&str, &str)>,
) -> Value {
    record(vec![
        ("policy_handle", policy),
        ("credential_id", Value::string(credential_id)),
        ("method", Value::string("POST")),
        ("path", Value::string("/oauth/token")),
        (
            "public_headers",
            Value::array(
                headers
                    .into_iter()
                    .map(|(name, value)| {
                        record(vec![
                            ("name", Value::string(name)),
                            ("value", Value::string(value)),
                        ])
                    })
                    .collect(),
            ),
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

#[cfg(feature = "config-fixture")]
fn callback_pair(
    auth: &AuthHost,
    vm: &mut Vm,
    policy: &Value,
    intent: &Value,
    code: &str,
) -> (Value, Value) {
    let begun = call(vm, "begin", &[policy.clone(), intent.clone()]);
    let callback = field(&begun, "callback_handle");
    let verifier = field(&begun, "verifier_handle");
    auth.fixture_inject_matching_callback(vm, &callback, code)
        .expect("inject synthetic callback code");
    let waited = call(vm, "wait", &[callback]);
    assert!(!format!("{waited:?}").contains(code));
    (field(&waited, "code_handle"), verifier)
}

#[test]
fn malformed_payload_selector_does_not_send_and_live_device_can_retry() {
    const DEVICE_ID: &str = "PAYLOAD_RETRY_DEVICE_PRIVATE_28a4";

    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(scripted_oauth(transport.clone()));
    let mut vm = vm_for(&auth);
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let snapshot = call(&mut vm, "snapshot", &[field(&owner, "host_home")]);
    let policy = field(&snapshot, "policy_handle");

    transport.push_raw(
        200,
        &format!(r#"{{"device_code":"{DEVICE_ID}","public":"started"}}"#),
    );
    let started = call(&mut vm, "start_device", std::slice::from_ref(&policy));
    let device = field(&started, "device_handle");
    assert_eq!(transport.take_sent().len(), 1);

    let call_args = [
        request(policy.clone(), "{}"),
        record(vec![
            ("kind", Value::string("device_session")),
            ("device_handle", device.clone()),
        ]),
        payload(
            "json_object",
            "device",
            Some(("device_field", "attacker_field")),
        ),
    ];
    transport.push_raw(200, r#"{"status":"waiting"}"#);
    let failure = call_result(&mut vm, "selected", &call_args)
        .expect_err("arbitrary device-field names are rejected");
    assert!(failure.to_string().contains("payload_intent_invalid"));
    assert!(!failure.to_string().contains(DEVICE_ID));
    assert!(
        transport.take_sent().is_empty(),
        "invalid selectors must fail before I/O"
    );
    assert_eq!(vm.host_context().resource_count(), 3);

    transport.push_raw(200, r#"{"status":"waiting"}"#);
    let retried = call(
        &mut vm,
        "selected",
        &[
            request(policy, "{}"),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device.clone()),
            ]),
            payload(
                "json_object",
                "device",
                Some(("device_field", "device_auth_id")),
            ),
        ],
    );
    assert_eq!(field(&retried, "status"), Value::Int(200));
    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        1,
        "only the corrected request reaches native I/O"
    );
    let body: serde_json::Value = serde_json::from_str(&sent[0].body).expect("JSON body");
    assert_eq!(body["device_auth_id"], DEVICE_ID);
    assert_eq!(vm.host_context().resource_count(), 3);
}

#[test]
fn real_rss_selected_device_auth_id_json_poll_injects_native_secret() {
    const DEVICE_ID: &str = "PAYLOAD_BRIDGE_DEVICE_PRIVATE_8c31";

    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let oauth = scripted_oauth(transport.clone());
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(oauth);
    let mut vm = vm_for(&auth);
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let snapshot = call(&mut vm, "snapshot", &[field(&owner, "host_home")]);
    let policy = field(&snapshot, "policy_handle");

    transport.push_raw(
        200,
        &format!(r#"{{"device_code":"{DEVICE_ID}","public":"started"}}"#),
    );
    let started = call(&mut vm, "start_device", std::slice::from_ref(&policy));
    assert_eq!(field(&started, "status"), Value::Int(200));
    let device = field(&started, "device_handle");
    assert!(matches!(device, Value::Int(_)));
    let public_start = format!("{started:?}");
    assert!(
        !public_start.contains(DEVICE_ID),
        "device id escaped in start result"
    );

    transport.push_raw(200, r#"{"status":"waiting"}"#);
    let public_body = r#"{"grant_type":"device_code","note":"literal &code=plain","n":9007199254740993,"wide":18446744073709551615,"larger":18446744073709551616,"decimal":1.2300,"negative_zero":-0,"exp":1.25e+30}"#;
    let polled = call(
        &mut vm,
        "selected",
        &[
            request(policy, public_body),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device.clone()),
            ]),
            payload(
                "json_object",
                "device",
                Some(("device_field", "device_auth_id")),
            ),
        ],
    );
    assert_eq!(field(&polled, "status"), Value::Int(200));
    let public_poll = format!("{polled:?}");
    assert!(
        !public_poll.contains(DEVICE_ID),
        "device id escaped in poll result"
    );
    assert_eq!(
        field(&polled, "body_without_secret_fields"),
        Value::string(r#"{"status":"waiting"}"#)
    );

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].body, "{}");
    assert_eq!(
        sent[0].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    let wire: serde_json::Value =
        serde_json::from_str(&sent[1].body).expect("selected JSON wire body");
    assert_eq!(wire["device_auth_id"], DEVICE_ID);
    assert_eq!(wire["grant_type"], "device_code");
    assert_eq!(wire["note"], "literal &code=plain");
    assert_eq!(wire["n"].to_string(), "9007199254740993");
    assert_eq!(wire["wide"].to_string(), "18446744073709551615");
    assert_eq!(wire["exp"].to_string(), "1.25e+30");
    for lexical_number in ["18446744073709551616", "1.2300", "-0", "1.25e+30"] {
        assert!(sent[1].body.contains(lexical_number), "{lexical_number}");
    }
    assert_eq!(
        sent[1].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );

    call(&mut vm, "close_device", &[device]);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn payload_catalog_exposes_named_intent_by_value_after_two_borrowed_inputs() {
    use rustscript_vm::{HostParamPassing, HostTypeSchema};

    let catalog = auth_host_catalog();
    let descriptor = catalog
        .functions()
        .iter()
        .find(|function| function.name == "oauth::transport_payload")
        .expect("selected transport function");
    assert_eq!(descriptor.params.len(), 3);
    assert_eq!(descriptor.params[0].passing, HostParamPassing::Borrow);
    assert_eq!(descriptor.params[1].passing, HostParamPassing::Borrow);
    assert_eq!(descriptor.params[2].passing, HostParamPassing::Value);
    let HostTypeSchema::Named { name, fields } = &descriptor.params[2].ty else {
        panic!("payload intent remains a named public struct");
    };
    assert_eq!(name, "TransportPayloadIntent");
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0].name, "encoding");
    assert_eq!(fields[0].ty, HostTypeSchema::String);
    assert_eq!(fields[1].name, "secret_fields");
    assert_eq!(fields[1].ty, HostTypeSchema::String);
    for field in [&fields[2], &fields[3]] {
        assert!(
            matches!(&field.ty, HostTypeSchema::Optional(inner) if **inner == HostTypeSchema::String)
        );
    }
}

#[test]
fn all_device_selector_aliases_use_native_json_or_form_body_injection() {
    const DEVICE_ID: &str = "PAYLOAD_ALIAS_PRIVATE_34bd";
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(scripted_oauth(transport.clone()));
    let mut vm = vm_for(&auth);
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let snapshot = call(&mut vm, "snapshot", &[field(&owner, "host_home")]);
    let policy = field(&snapshot, "policy_handle");

    transport.push_raw(200, &format!(r#"{{"device_code":"{DEVICE_ID}"}}"#));
    let started = call(&mut vm, "start_device", std::slice::from_ref(&policy));
    let device = field(&started, "device_handle");
    assert_eq!(transport.take_sent().len(), 1);

    for (encoding, selector, content_type, body) in [
        (
            "form",
            "device_code",
            Some("application/x-www-form-urlencoded"),
            "grant_type=device_code&note=literal+%26code%3Dplain",
        ),
        (
            "json_object",
            "device_id",
            None,
            r#"{"grant_type":"device_code","note":"literal &code=plain"}"#,
        ),
    ] {
        transport.push_raw(200, r#"{"status":"waiting"}"#);
        let response = call(
            &mut vm,
            "selected",
            &[
                request_with_content_type(policy.clone(), body, content_type),
                record(vec![
                    ("kind", Value::string("device_session")),
                    ("device_handle", device.clone()),
                ]),
                payload(encoding, "device", Some(("device_field", selector))),
            ],
        );
        assert_eq!(field(&response, "status"), Value::Int(200));
        assert!(!format!("{response:?}").contains(DEVICE_ID));
        let sent = transport.take_sent();
        assert_eq!(sent.len(), 1);
        let expected_type = if encoding == "form" {
            "application/x-www-form-urlencoded"
        } else {
            "application/json"
        };
        assert_eq!(
            sent[0].headers.get("content-type").map(String::as_str),
            Some(expected_type)
        );
        if encoding == "form" {
            assert!(sent[0].body.contains(&format!("device_code={DEVICE_ID}")));
            assert!(sent[0].body.contains("note=literal%20%26code%3Dplain"));
        } else {
            let wire: serde_json::Value = serde_json::from_str(&sent[0].body).expect("JSON wire");
            assert_eq!(wire["device_id"], DEVICE_ID);
            assert_eq!(wire["note"], "literal &code=plain");
        }
    }
    call(&mut vm, "close_device", &[device]);
}

#[test]
fn malformed_typed_payload_is_value_free_and_keeps_live_device_retryable() {
    const DEVICE_ID: &str = "PAYLOAD_PARSER_PRIVATE_764e";
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(scripted_oauth(transport.clone()));
    let mut vm = vm_for(&auth);
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let snapshot = call(&mut vm, "snapshot", &[field(&owner, "host_home")]);
    let policy = field(&snapshot, "policy_handle");
    transport.push_raw(200, &format!(r#"{{"device_code":"{DEVICE_ID}"}}"#));
    let started = call(&mut vm, "start_device", std::slice::from_ref(&policy));
    let device = field(&started, "device_handle");
    assert_eq!(transport.take_sent().len(), 1);
    let wrong_type = record(vec![
        ("encoding", Value::string("json_object")),
        ("secret_fields", Value::string("device")),
        ("device_field", Value::Int(1)),
    ]);
    let unknown_field = record(vec![
        ("encoding", Value::string("json_object")),
        ("secret_fields", Value::string("device")),
        ("device_field", Value::string("device_code")),
        ("arbitrary", Value::string("attacker")),
    ]);
    let missing_selector = payload("json_object", "device", None);
    let conflicting_selectors = record(vec![
        ("encoding", Value::string("json_object")),
        ("secret_fields", Value::string("device")),
        ("device_field", Value::string("device_code")),
        ("code_field", Value::string("code")),
    ]);
    let none_with_selector = record(vec![
        ("encoding", Value::string("json_object")),
        ("secret_fields", Value::string("none")),
        ("device_field", Value::string("device_code")),
    ]);
    let invalid_encoding = payload("json", "none", None);
    let control = payload("json_object\n", "none", None);
    let oversized = payload(&"x".repeat(65), "none", None);
    let unicode_oversized = payload(&"雪".repeat(22), "none", None);
    let missing_required = record(vec![("encoding", Value::string("json_object"))]);
    let shape_invalid = [wrong_type, unknown_field, missing_required];
    for (index, malformed) in shape_invalid.into_iter().enumerate() {
        let failure = call_result(
            &mut vm,
            "selected",
            &[
                request(policy.clone(), "{}"),
                record(vec![
                    ("kind", Value::string("device_session")),
                    ("device_handle", device.clone()),
                ]),
                malformed,
            ],
        )
        .expect_err("typed record shape rejected");
        let public_error = format!("{failure:?} {failure}");
        assert!(!public_error.contains(DEVICE_ID));
        let sent = transport.take_sent();
        assert!(sent.is_empty(), "shape-invalid case {index} sent {sent:?}");
        assert_eq!(vm.host_context().resource_count(), 3);
    }

    let parser_invalid = [
        missing_selector,
        conflicting_selectors,
        none_with_selector,
        invalid_encoding,
        control,
        oversized,
        unicode_oversized,
        payload("json_object", "unsupported", None),
        payload(
            "json_object",
            "device",
            Some(("device_field", "attacker_field")),
        ),
        payload(
            "json_object",
            "authorization_code",
            Some(("code_field", "bad_code")),
        ),
    ];
    for malformed in parser_invalid {
        let failure = call_result(
            &mut vm,
            "selected",
            &[
                request(policy.clone(), "{}"),
                record(vec![
                    ("kind", Value::string("device_session")),
                    ("device_handle", device.clone()),
                ]),
                malformed,
            ],
        )
        .expect_err("malformed selector rejected");
        let public_error = format!("{failure:?} {failure}");
        assert!(
            public_error.contains("payload_intent_invalid"),
            "{public_error}"
        );
        assert!(!public_error.contains(DEVICE_ID));
        assert!(transport.take_sent().is_empty());
        assert_eq!(vm.host_context().resource_count(), 3);
    }

    transport.push_raw(200, r#"{"status":"waiting"}"#);
    let response = call(
        &mut vm,
        "selected",
        &[
            request(policy, "{}"),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device.clone()),
            ]),
            payload("json_object", "device", Some(("device_field", "device_id"))),
        ],
    );
    assert_eq!(field(&response, "status"), Value::Int(200));
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    let wire: serde_json::Value = serde_json::from_str(&sent[0].body).expect("JSON wire");
    assert_eq!(wire["device_id"], DEVICE_ID);
    call(&mut vm, "close_device", &[device]);
}

#[test]
fn selected_form_without_content_type_is_canonicalized_and_none_keeps_public_body() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(scripted_oauth(transport.clone()));
    let mut vm = vm_for(&auth);
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let snapshot = call(&mut vm, "snapshot", &[field(&owner, "host_home")]);
    let policy = field(&snapshot, "policy_handle");
    transport.push_raw(200, r#"{"public":"accepted"}"#);
    let response = call(
        &mut vm,
        "selected",
        &[
            request_with_content_type(
                policy,
                "client_id=public-client&note=literal+%26code%3Dplain",
                None,
            ),
            record(vec![("kind", Value::string("none"))]),
            record(vec![
                ("encoding", Value::string("form")),
                ("secret_fields", Value::string("none")),
                ("device_field", Value::Null),
                ("code_field", Value::Null),
            ]),
        ],
    );
    assert_eq!(field(&response, "status"), Value::Int(200));
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].body.contains("client_id=public-client"));
    assert!(sent[0].body.contains("note=literal%20%26code%3Dplain"));
    assert_eq!(
        sent[0].headers.get("content-type").map(String::as_str),
        Some("application/x-www-form-urlencoded")
    );
}

#[test]
fn selected_native_header_and_retry_denials_keep_credentials_private() {
    const DEVICE_ID: &str = "PAYLOAD_DENIAL_PRIVATE_b95a";
    const ACCESS_TOKEN: &str = "SYNTHETIC_ACCESS_TOKEN";
    const HEADER_MARKER: &str = "PUBLIC_AUTHORIZATION_MARKER";
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(scripted_oauth(transport.clone()));
    let mut vm = vm_for(&auth);
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let snapshot = call(&mut vm, "snapshot", &[field(&owner, "host_home")]);
    let policy = field(&snapshot, "policy_handle");

    let access_envelope = call(&mut vm, "access_handle", std::slice::from_ref(&policy));
    let access = field(&access_envelope, "handle");
    transport.push_raw(200, r#"{"public":"accepted"}"#);
    let access_response = call(
        &mut vm,
        "selected",
        &[
            request(policy.clone(), r#"{"public":true}"#),
            record(vec![
                ("kind", Value::string("access")),
                ("access_handle", access.clone()),
            ]),
            payload("json_object", "none", None),
        ],
    );
    assert_eq!(field(&access_response, "status"), Value::Int(200));
    assert!(!format!("{access_response:?}").contains(ACCESS_TOKEN));
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some("Bearer SYNTHETIC_ACCESS_TOKEN")
    );
    assert!(!format!("{access_response:?}").contains("authorization"));
    transport.push_raw(200, &format!(r#"{{"device_code":"{DEVICE_ID}"}}"#));
    let started = call(&mut vm, "start_device", std::slice::from_ref(&policy));
    let device = field(&started, "device_handle");
    assert_eq!(transport.take_sent().len(), 1);

    for bad_request in [
        request_with_content_type(policy.clone(), "{}", Some("text/plain")),
        request_with_headers(
            policy.clone(),
            "{}",
            vec![
                ("content-type", "application/json"),
                ("authorization", HEADER_MARKER),
            ],
        ),
    ] {
        let failure = call_result(
            &mut vm,
            "selected",
            &[
                bad_request,
                record(vec![
                    ("kind", Value::string("device_session")),
                    ("device_handle", device.clone()),
                ]),
                payload(
                    "json_object",
                    "device",
                    Some(("device_field", "device_code")),
                ),
            ],
        )
        .expect_err("native content-type or header policy denial");
        let public_error = format!("{failure:?} {failure}");
        assert!(!public_error.contains(DEVICE_ID));
        assert!(!public_error.contains(HEADER_MARKER));
        assert!(transport.take_sent().is_empty());
        assert_eq!(vm.host_context().resource_count(), 3);
    }

    transport.push_raw(200, r#"{"status":"waiting"}"#);
    let response = call(
        &mut vm,
        "selected",
        &[
            request(policy.clone(), "{}"),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device.clone()),
            ]),
            payload(
                "json_object",
                "device",
                Some(("device_field", "device_code")),
            ),
        ],
    );
    assert_eq!(field(&response, "status"), Value::Int(200));
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "valid retry reaches the native transport");
    let wire: serde_json::Value = serde_json::from_str(&sent[0].body).expect("JSON wire");
    assert_eq!(wire["device_code"], DEVICE_ID);
    call(&mut vm, "close_device", std::slice::from_ref(&device));
    let replay = call_result(
        &mut vm,
        "selected",
        &[
            request(policy, "{}"),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device),
            ]),
            payload(
                "json_object",
                "device",
                Some(("device_field", "device_code")),
            ),
        ],
    )
    .expect_err("closed device handle replay rejected");
    assert!(!format!("{replay:?} {replay}").contains(DEVICE_ID));
    assert!(transport.take_sent().is_empty());
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn selected_transport_rejects_cross_vm_and_credential_mismatch_before_io() {
    const DEVICE_ID: &str = "PAYLOAD_OWNER_PRIVATE_66fe";
    const SIBLING_ID: &str = "PAYLOAD_SIBLING_PRIVATE_08d1";
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(scripted_oauth(transport.clone()));

    let mut first_vm = vm_for(&auth);
    let first_owner = auth.bind_vm(&mut first_vm).expect("bind first VM");
    let first_snapshot = call(
        &mut first_vm,
        "snapshot",
        &[field(&first_owner, "host_home")],
    );
    let first_policy = field(&first_snapshot, "policy_handle");
    transport.push_raw(200, &format!(r#"{{"device_code":"{DEVICE_ID}"}}"#));
    let started = call(
        &mut first_vm,
        "start_device",
        std::slice::from_ref(&first_policy),
    );
    let device = field(&started, "device_handle");
    assert_eq!(transport.take_sent().len(), 1);

    let mut second_vm = vm_for(&auth);
    let second_owner = auth.bind_vm(&mut second_vm).expect("bind second VM");
    let second_snapshot = call(
        &mut second_vm,
        "snapshot",
        &[field(&second_owner, "host_home")],
    );
    let second_policy = field(&second_snapshot, "policy_handle");
    let cross_vm = call_result(
        &mut second_vm,
        "selected",
        &[
            request(second_policy, "{}"),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device.clone()),
            ]),
            payload(
                "json_object",
                "device",
                Some(("device_field", "device_code")),
            ),
        ],
    )
    .expect_err("foreign VM device resource rejected");
    assert!(!format!("{cross_vm:?} {cross_vm}").contains(DEVICE_ID));
    assert!(transport.take_sent().is_empty());
    assert_eq!(first_vm.host_context().resource_count(), 3);
    assert_eq!(second_vm.host_context().resource_count(), 2);

    let wrong_credential = call_result(
        &mut first_vm,
        "selected",
        &[
            request_for_credential(first_policy.clone(), "not-admitted", "{}"),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device.clone()),
            ]),
            payload(
                "json_object",
                "device",
                Some(("device_field", "device_code")),
            ),
        ],
    )
    .expect_err("credential mismatch rejected");
    assert!(
        wrong_credential
            .to_string()
            .contains("credential_not_admitted")
    );
    assert!(transport.take_sent().is_empty());
    assert_eq!(first_vm.host_context().resource_count(), 3);

    transport.push_raw(200, r#"{"status":"waiting"}"#);
    let retried = call(
        &mut first_vm,
        "selected",
        &[
            request(first_policy.clone(), "{}"),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device.clone()),
            ]),
            payload(
                "json_object",
                "device",
                Some(("device_field", "device_code")),
            ),
        ],
    );
    assert_eq!(field(&retried, "status"), Value::Int(200));
    assert_eq!(transport.take_sent().len(), 1);

    transport.push_raw(200, &format!(r#"{{"device_code":"{SIBLING_ID}"}}"#));
    let sibling_started = call(
        &mut first_vm,
        "start_device",
        std::slice::from_ref(&first_policy),
    );
    let _sibling_device = field(&sibling_started, "device_handle");
    assert_eq!(transport.take_sent().len(), 1);
    assert_eq!(first_vm.host_context().resource_count(), 4);

    auth.revoke();
    assert_eq!(transport.take_sent().len(), 0);
    let cancelled = call_result(
        &mut first_vm,
        "selected",
        &[
            request(first_policy, "{}"),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device),
            ]),
            payload(
                "json_object",
                "device",
                Some(("device_field", "device_code")),
            ),
        ],
    )
    .expect_err("revoked owner rejects selected request");
    assert!(cancelled.to_string().contains("policy_inactive"));
    assert!(!format!("{cancelled:?} {cancelled}").contains(DEVICE_ID));
    assert_eq!(first_vm.host_context().resource_count(), 3);
    assert_eq!(second_vm.host_context().resource_count(), 2);
    assert_eq!(first_vm.host_context().resource_count(), 3);
}

#[cfg(feature = "config-fixture")]
#[test]
fn callback_code_exchange_selects_both_labels_and_encodings_through_real_rss() {
    const CODE: &str = "PAYLOAD_CALLBACK_CODE_PRIVATE_11c2";
    const SIBLING_CODE: &str = "PAYLOAD_CALLBACK_SIBLING_PRIVATE_87a0";
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(scripted_oauth(transport.clone()))
    .with_oauth_callback_fixture();
    let mut vm = vm_for(&auth);
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let snapshot = call(&mut vm, "snapshot", &[field(&owner, "host_home")]);
    let policy = field(&snapshot, "policy_handle");
    let oauth_intent = record(vec![
        ("credential_id", Value::string("fixture-codex")),
        ("path", Value::string("/codex/device")),
        ("flow", Value::string("authorization_code_pkce")),
        ("callback_mode", Value::string("manual")),
        (
            "scopes",
            Value::array(vec![Value::string("scope.synthetic")]),
        ),
        (
            "public_query",
            Value::array(vec![record(vec![
                ("name", Value::string("client_id")),
                ("value", Value::string("public-client-id")),
            ])]),
        ),
    ]);

    for (encoding, selector) in [
        ("json_object", "code"),
        ("form", "code"),
        ("json_object", "authorization_code"),
        ("form", "authorization_code"),
    ] {
        let (code, verifier) = callback_pair(&auth, &mut vm, &policy, &oauth_intent, CODE);
        let (sibling_code, sibling_verifier) =
            callback_pair(&auth, &mut vm, &policy, &oauth_intent, SIBLING_CODE);
        assert_eq!(
            auth.fixture_live_oauth_flow_count().expect("native flows"),
            2
        );

        let malformed = call_result(
            &mut vm,
            "selected_code",
            &[
                request(policy.clone(), "{}"),
                code.clone(),
                verifier.clone(),
                payload(
                    "json_object",
                    "authorization_code",
                    Some(("code_field", "untrusted_code_label")),
                ),
            ],
        )
        .expect_err("invalid selector leaves callback pair retryable");
        let public_error = format!("{malformed:?} {malformed}");
        assert!(public_error.contains("payload_intent_invalid"));
        assert!(!public_error.contains(CODE));
        assert!(!public_error.contains(SIBLING_CODE));
        assert!(transport.take_sent().is_empty());
        assert_eq!(
            auth.fixture_live_oauth_flow_count().expect("native flows"),
            2
        );
        assert_eq!(vm.host_context().resource_count(), 8);

        let body = if encoding == "form" {
            "grant_type=authorization_code&note=literal+%26code%3Dpublic"
        } else {
            r#"{"grant_type":"authorization_code","note":"literal &code=public"}"#
        };
        let content_type = if encoding == "form" {
            Some("application/x-www-form-urlencoded")
        } else {
            Some("application/json")
        };
        transport.push_raw(200, r#"{"public":"accepted"}"#);
        let response = call(
            &mut vm,
            "selected_code",
            &[
                request_with_content_type(policy.clone(), body, content_type),
                code,
                verifier,
                payload(
                    encoding,
                    "authorization_code",
                    Some(("code_field", selector)),
                ),
            ],
        );
        assert_eq!(field(&response, "status"), Value::Int(200));
        let public_result = format!("{response:?}");
        assert!(!public_result.contains(CODE));
        assert!(!public_result.contains("code_verifier"));
        let sent = transport.take_sent();
        assert_eq!(sent.len(), 1);
        let expected_type = if encoding == "form" {
            "application/x-www-form-urlencoded"
        } else {
            "application/json"
        };
        assert_eq!(
            sent[0].headers.get("content-type").map(String::as_str),
            Some(expected_type)
        );
        if encoding == "form" {
            let fields = url::form_urlencoded::parse(sent[0].body.as_bytes())
                .into_owned()
                .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(fields[selector], CODE);
            assert!(!fields["code_verifier"].is_empty());
            assert_eq!(fields["note"], "literal &code=public");
        } else {
            let wire: serde_json::Value = serde_json::from_str(&sent[0].body).expect("JSON wire");
            assert_eq!(wire[selector], CODE);
            assert!(
                wire["code_verifier"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
            );
            assert_eq!(wire["note"], "literal &code=public");
        }
        assert_eq!(
            auth.fixture_live_oauth_flow_count().expect("native flows"),
            1
        );
        assert_eq!(vm.host_context().resource_count(), 5);

        transport.push_raw(200, r#"{"public":"accepted"}"#);
        let sibling_response = call(
            &mut vm,
            "selected_code",
            &[
                request_with_content_type(
                    policy.clone(),
                    r#"{"note":"sibling"}"#,
                    Some("application/json"),
                ),
                sibling_code,
                sibling_verifier,
                payload(
                    "json_object",
                    "authorization_code",
                    Some(("code_field", "authorization_code")),
                ),
            ],
        );
        assert_eq!(field(&sibling_response, "status"), Value::Int(200));
        let sibling_sent = transport.take_sent();
        assert_eq!(sibling_sent.len(), 1);
        let sibling_wire: serde_json::Value =
            serde_json::from_str(&sibling_sent[0].body).expect("sibling JSON wire");
        assert_eq!(sibling_wire["authorization_code"], SIBLING_CODE);
        assert_eq!(
            auth.fixture_live_oauth_flow_count().expect("native flows"),
            0
        );
        assert_eq!(vm.host_context().resource_count(), 2);
    }
}
