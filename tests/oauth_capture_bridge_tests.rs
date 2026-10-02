#[cfg(feature = "config-fixture")]
use rustscript_agent::CancellationReason;
#[cfg(feature = "config-fixture")]
use rustscript_agent::auth::oauth::{
    BoundedHttpsTransport, OAuthError, OAuthIoContext, PreparedHttpsRequest, RawHttpsResponse,
};
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

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new() -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP"));
        let path = root.join(format!("oauth-capture-{}", uuid::Uuid::new_v4()));
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

#[cfg(feature = "config-fixture")]
struct CancelAfterCaptureResponse {
    cancellation: RunCancellation,
    calls: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "config-fixture")]
impl BoundedHttpsTransport for CancelAfterCaptureResponse {
    fn send(
        &self,
        _request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        context.check()?;
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let body: &[u8] = if call == 0 {
            br#"{"device_code":"CANCEL_DEVICE_SYNTHETIC","user_code":"SYNTHETIC-USER","verification_uri":"https://auth.example.test/device","expires_in":900,"interval":5}"#
        } else {
            self.cancellation.request(CancellationReason::Requested);
            br#"{"code":"CANCEL_CODE_SYNTHETIC","code_verifier":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_","public":"accepted"}"#
        };
        Ok(RawHttpsResponse {
            status: 200,
            headers: std::collections::BTreeMap::from([(
                "content-type".to_owned(),
                "application/json".to_owned(),
            )]),
            body: body.to_vec(),
        })
    }
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn vm_for(auth: &AuthHost) -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/capture_contract.rss");
    let source = fs::read_to_string(&path).expect("real capture contract RSS");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile actual capture contract against auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog.as_ref())
        .expect("register exact auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted auth catalog");
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
        .unwrap_or_else(|| panic!("missing field {name}"))
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
    call_result(vm, name, args).unwrap_or_else(|failure| panic!("{name} RSS call: {failure:?}"))
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

fn request(policy: Value, path: &str, public_body: &str) -> Value {
    record(vec![
        ("policy_handle", policy),
        ("credential_id", Value::string("fixture-codex")),
        ("method", Value::string("POST")),
        ("path", Value::string(path)),
        (
            "public_headers",
            Value::array(vec![record(vec![
                ("name", Value::string("content-type")),
                ("value", Value::string("application/json")),
            ])]),
        ),
        ("public_body", Value::string(public_body)),
    ])
}

#[test]
fn actual_rss_capture_contract_compiles_against_auth_catalog() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/capture_contract.rss");
    let source = fs::read_to_string(&path).expect("real capture contract RSS");
    compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(auth_host_catalog()),
    )
    .expect("capture contract compiles against exact auth catalog");
}

#[test]
fn actual_rss_capture_injects_device_secret_and_returns_opaque_exchange_pair() {
    const DEVICE_ID: &str = "CAPTURE_DEVICE_PRIVATE_8a31";
    const CODE: &str = "CAPTURE_CODE_PRIVATE_7f42";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

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
        &format!(r#"{{"device_code":"{DEVICE_ID}","user_code":"SYNTHETIC-USER-CODE","verification_uri":"https://auth.example.test/device","expires_in":900,"interval":5}}"#),
    );
    let started = call(&mut vm, "start_device", std::slice::from_ref(&policy));
    let device = field(&started, "device_handle");
    assert_eq!(transport.take_sent().len(), 1);

    let rejected = call_result(
        &mut vm,
        "capture",
        &[
            request(
                policy.clone(),
                "/oauth/token",
                r#"{"grant_type":"device_code"}"#,
            ),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device.clone()),
            ]),
            record(vec![
                ("encoding", Value::string("json_object")),
                ("secret_fields", Value::string("device")),
                ("device_field", Value::string("device_id")),
            ]),
            record(vec![
                ("code_field", Value::string("authorizationCode")),
                (
                    "redirect_uri",
                    Value::string("https://auth.example.test/callback"),
                ),
            ]),
        ],
    )
    .expect_err("unrecognized capture selector is rejected locally");
    assert!(rejected.to_string().ends_with("capture_intent_invalid"));
    assert!(transport.take_sent().is_empty());
    assert_eq!(vm.host_context().resource_count(), 3);

    transport.push_raw(
        200,
        &format!(
            r#"{{"authorization_code":"{CODE}","code_verifier":"{VERIFIER}","public":"accepted"}}"#
        ),
    );
    let captured = call(
        &mut vm,
        "capture",
        &[
            request(
                policy.clone(),
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
                    Value::string("https://auth.example.test/callback"),
                ),
            ]),
        ],
    );
    let response = field(&captured, "response");
    assert_eq!(field(&response, "status"), Value::Int(200));
    assert_eq!(
        field(&response, "body_without_secret_fields"),
        Value::string(r#"{"public":"accepted"}"#)
    );
    assert!(matches!(field(&captured, "code_handle"), Value::Int(_)));
    assert!(matches!(field(&captured, "verifier_handle"), Value::Int(_)));
    let public = format!("{captured:?}");
    for secret in [DEVICE_ID, CODE, VERIFIER] {
        assert!(!public.contains(secret), "secret escaped: {secret}");
    }
    assert_eq!(vm.host_context().resource_count(), 4);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count().expect("captured flow"),
        1
    );

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    let body: serde_json::Value =
        serde_json::from_str(&sent[0].body).expect("selected request JSON");
    assert_eq!(body["device_id"], DEVICE_ID);
    assert_eq!(
        sent[0].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );

    const ACCESS: &str = "CAPTURE_ACCESS_PRIVATE_4e18";
    const REFRESH: &str = "CAPTURE_REFRESH_PRIVATE_5d27";
    transport.push_raw(
        200,
        &format!(r#"{{"access_token":"{ACCESS}","refresh_token":"{REFRESH}","token_type":"Bearer","expires_in":3600,"public":"authorized"}}"#),
    );
    let exchanged = call(
        &mut vm,
        "exchange_selected",
        &[
            request(
                policy.clone(),
                "/oauth/token",
                r#"{"grant_type":"authorization_code"}"#,
            ),
            field(&captured, "code_handle"),
            field(&captured, "verifier_handle"),
            record(vec![
                ("encoding", Value::string("json_object")),
                ("secret_fields", Value::string("authorization_code")),
                ("code_field", Value::string("authorization_code")),
            ]),
        ],
    );
    assert_eq!(field(&exchanged, "status"), Value::Int(200));
    let exchange_public = format!("{exchanged:?}");
    for secret in [CODE, VERIFIER, ACCESS, REFRESH] {
        assert!(!exchange_public.contains(secret));
    }
    let exchange_wire = transport.take_sent();
    assert_eq!(exchange_wire.len(), 1);
    let wire: serde_json::Value =
        serde_json::from_str(&exchange_wire[0].body).expect("exchange JSON");
    assert_eq!(wire["authorization_code"], CODE);
    assert_eq!(wire["code_verifier"], VERIFIER);
    assert_eq!(wire["redirect_uri"], "https://auth.example.test/callback");

    let saved = call(
        &mut vm,
        "save_slots",
        &[
            policy,
            field(&exchanged, "access_slot"),
            field(&exchanged, "refresh_slot"),
            Value::Int(4),
        ],
    );
    assert_eq!(field(&saved, "outcome"), Value::string("committed"));
    let metadata = AuthStore::from_home(&home.0)
        .expect("fixture store")
        .load_metadata("fixture-codex")
        .expect("persisted capture exchange metadata");
    assert_eq!(metadata.generation, 5);
    assert_eq!(vm.host_context().resource_count(), 2);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("exchanged flow cleanup"),
        0
    );
}

#[test]
fn capture_catalog_has_exact_four_typed_arguments_and_nested_pair_envelope() {
    use rustscript_vm::{HostParamPassing, HostTypeSchema, ResourceTypeKey};

    let catalog = auth_host_catalog();
    let capture = catalog
        .functions()
        .iter()
        .find(|function| function.name == "oauth::transport_capture")
        .expect("opt-in capture function");
    assert_eq!(capture.params.len(), 4);
    assert_eq!(capture.params[0].name, "request");
    assert_eq!(capture.params[1].name, "credential_use");
    assert_eq!(capture.params[2].name, "payload");
    assert_eq!(capture.params[3].name, "capture");
    assert_eq!(capture.params[0].passing, HostParamPassing::Borrow);
    assert_eq!(capture.params[1].passing, HostParamPassing::Borrow);
    assert_eq!(capture.params[2].passing, HostParamPassing::Value);
    assert_eq!(capture.params[3].passing, HostParamPassing::Value);
    let HostTypeSchema::Named { name, fields } = &capture.params[3].ty else {
        panic!("capture is a closed named record");
    };
    assert_eq!(name, "TransportCaptureIntent");
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].name, "code_field");
    assert_eq!(fields[0].ty, HostTypeSchema::String);
    assert_eq!(fields[1].name, "redirect_uri");
    assert_eq!(fields[1].ty, HostTypeSchema::String);

    let HostTypeSchema::Named { name, fields } = &capture.return_type else {
        panic!("capture output is a closed named envelope");
    };
    assert_eq!(name, "TransportCaptureEnvelope");
    assert_eq!(
        fields
            .iter()
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>(),
        ["ok", "error", "response", "code_handle", "verifier_handle"]
    );
    assert!(matches!(
        &fields[3].ty,
        HostTypeSchema::Optional(inner)
            if **inner == HostTypeSchema::Resource(ResourceTypeKey::new("oauth.authorization_code").expect("code type"))
    ));
    assert!(matches!(
        &fields[4].ty,
        HostTypeSchema::Optional(inner)
            if **inner == HostTypeSchema::Resource(ResourceTypeKey::new("oauth.verifier").expect("verifier type"))
    ));

    for (name, count) in [("oauth::transport", 2), ("oauth::transport_payload", 3)] {
        let function = catalog
            .functions()
            .iter()
            .find(|function| function.name == name)
            .expect("legacy entrypoint retained");
        assert_eq!(function.params.len(), count);
    }
}

#[test]
fn invalid_capture_selectors_and_pending_response_keep_device_retryable() {
    const DEVICE_ID: &str = "CAPTURE_RETRY_DEVICE_PRIVATE_51ad";
    const CODE: &str = "CAPTURE_RETRY_CODE_PRIVATE_30ef";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

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
        &format!(r#"{{"device_code":"{DEVICE_ID}","user_code":"SYNTHETIC-USER","verification_uri":"https://auth.example.test/device","expires_in":900,"interval":5}}"#),
    );
    let started = call(&mut vm, "start_device", std::slice::from_ref(&policy));
    let device = field(&started, "device_handle");
    let _ = transport.take_sent();
    let access = call(&mut vm, "issue_access", std::slice::from_ref(&policy));
    let refresh = call(&mut vm, "issue_refresh", std::slice::from_ref(&policy));
    assert_eq!(vm.host_context().resource_count(), 5);

    let valid_payload = || {
        record(vec![
            ("encoding", Value::string("json_object")),
            ("secret_fields", Value::string("device")),
            ("device_field", Value::string("device_code")),
        ])
    };
    let valid_request = || {
        request(
            policy.clone(),
            "/oauth/token",
            r#"{"grant_type":"device_code"}"#,
        )
    };
    let good_uri = "https://auth.example.test/callback";
    let invalid_intents = [
        record(vec![
            ("code_field", Value::string("unsupported")),
            ("redirect_uri", Value::string(good_uri)),
        ]),
        record(vec![
            ("code_field", Value::string("x".repeat(65))),
            ("redirect_uri", Value::string(good_uri)),
        ]),
        record(vec![
            ("code_field", Value::string("code\n")),
            ("redirect_uri", Value::string(good_uri)),
        ]),
        record(vec![
            ("code_field", Value::string("code")),
            ("redirect_uri", Value::string("")),
        ]),
        record(vec![
            ("code_field", Value::string("code")),
            ("redirect_uri", Value::string("x".repeat(2049))),
        ]),
        record(vec![
            ("code_field", Value::string("code")),
            (
                "redirect_uri",
                Value::string("https://auth.example.test/callback\n"),
            ),
        ]),
        record(vec![
            ("code_field", Value::string("code")),
            (
                "redirect_uri",
                Value::string("https://user@auth.example.test/callback"),
            ),
        ]),
        record(vec![
            ("code_field", Value::string("code")),
            (
                "redirect_uri",
                Value::string("https://auth.example.test\\callback"),
            ),
        ]),
        Value::Int(9),
        record(vec![("code_field", Value::string("code"))]),
        record(vec![
            ("code_field", Value::string("code")),
            ("redirect_uri", Value::string(good_uri)),
            ("extra", Value::string("CAPTURE_SELECTOR_PRIVATE_MARKER")),
        ]),
        Value::map(vec![
            (Value::Int(7), Value::string("CAPTURE_KEY_PRIVATE_MARKER")),
            (Value::string("code_field"), Value::string("code")),
            (Value::string("redirect_uri"), Value::string(good_uri)),
        ]),
        record(vec![
            ("code_field", Value::Int(7)),
            ("redirect_uri", Value::string(good_uri)),
        ]),
    ];
    for intent in invalid_intents {
        let failure = call_result(
            &mut vm,
            "capture",
            &[
                valid_request(),
                record(vec![
                    ("kind", Value::string("device_session")),
                    ("device_handle", device.clone()),
                ]),
                valid_payload(),
                intent,
            ],
        )
        .expect_err("invalid capture selector rejected before send");
        assert!(!failure.to_string().contains(DEVICE_ID));
        assert!(transport.take_sent().is_empty());
        assert_eq!(vm.host_context().resource_count(), 5);
    }

    for (usage, payload) in [
        (
            record(vec![("kind", Value::string("none"))]),
            valid_payload(),
        ),
        (
            record(vec![
                ("kind", Value::string("access")),
                ("access_handle", access.clone()),
            ]),
            valid_payload(),
        ),
        (
            record(vec![
                ("kind", Value::string("refresh")),
                ("refresh_handle", refresh.clone()),
            ]),
            valid_payload(),
        ),
        (
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device.clone()),
            ]),
            record(vec![
                ("encoding", Value::string("json_object")),
                ("secret_fields", Value::string("none")),
            ]),
        ),
    ] {
        let failure = call_result(
            &mut vm,
            "capture",
            &[
                valid_request(),
                usage,
                payload,
                record(vec![
                    ("code_field", Value::string("code")),
                    ("redirect_uri", Value::string(good_uri)),
                ]),
            ],
        )
        .expect_err("capture requires matching device credential and payload selectors");
        assert!(failure.to_string().ends_with("capture_intent_invalid"));
        assert!(transport.take_sent().is_empty());
        assert_eq!(vm.host_context().resource_count(), 5);
    }

    transport.push_raw(
        200,
        r#"{"error":"authorization_pending","public":"waiting"}"#,
    );
    let pending = call(
        &mut vm,
        "capture",
        &[
            valid_request(),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device.clone()),
            ]),
            valid_payload(),
            record(vec![
                ("code_field", Value::string("code")),
                ("redirect_uri", Value::string(good_uri)),
            ]),
        ],
    );
    let nested = field(&pending, "response");
    assert_eq!(
        field(&nested, "body_without_secret_fields"),
        Value::string(r#"{"error":"authorization_pending","public":"waiting"}"#)
    );
    assert_eq!(field(&pending, "code_handle"), Value::Null);
    assert_eq!(field(&pending, "verifier_handle"), Value::Null);
    assert_eq!(vm.host_context().resource_count(), 5);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("pending device remains live"),
        1
    );
    assert_eq!(transport.take_sent().len(), 1);

    transport.push_raw(
        200,
        &format!(r#"{{"code":"{CODE}","code_verifier":"{VERIFIER}","public":"authorized"}}"#),
    );
    let captured = call(
        &mut vm,
        "capture",
        &[
            valid_request(),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device),
            ]),
            valid_payload(),
            record(vec![
                ("code_field", Value::string("code")),
                ("redirect_uri", Value::string(good_uri)),
            ]),
        ],
    );
    assert!(matches!(field(&captured, "code_handle"), Value::Int(_)));
    assert!(matches!(field(&captured, "verifier_handle"), Value::Int(_)));
    assert_eq!(vm.host_context().resource_count(), 6);
    assert_eq!(transport.take_sent().len(), 1);
    let code = field(&captured, "code_handle");
    let verifier = field(&captured, "verifier_handle");
    let incompatible = call_result(
        &mut vm,
        "capture",
        &[
            valid_request(),
            record(vec![
                ("kind", Value::string("code_verifier")),
                ("code_handle", code.clone()),
                ("verifier_handle", verifier.clone()),
            ]),
            valid_payload(),
            record(vec![
                ("code_field", Value::string("code")),
                ("redirect_uri", Value::string(good_uri)),
            ]),
        ],
    )
    .expect_err("capture never accepts code/verifier credential use");
    assert!(incompatible.to_string().ends_with("capture_intent_invalid"));
    assert!(transport.take_sent().is_empty());
    assert_eq!(vm.host_context().resource_count(), 6);

    call(&mut vm, "close_verifier", std::slice::from_ref(&verifier));
    assert_eq!(vm.host_context().resource_count(), 5);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("verifier revokes pair family"),
        0
    );
    call(&mut vm, "close_code", std::slice::from_ref(&code));
    assert_eq!(vm.host_context().resource_count(), 4);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count().expect("pair cleanup"),
        0
    );
    call(&mut vm, "close_access", std::slice::from_ref(&access));
    call(&mut vm, "close_refresh", std::slice::from_ref(&refresh));
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn resource_limit_rejects_both_capture_handles_and_reclaims_native_pair() {
    const DEVICE_ID: &str = "CAPTURE_LIMIT_DEVICE_PRIVATE_4e9c";
    const CODE: &str = "CAPTURE_LIMIT_CODE_PRIVATE_1c72";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

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
        &format!(r#"{{"device_code":"{DEVICE_ID}","user_code":"SYNTHETIC-USER","verification_uri":"https://auth.example.test/device","expires_in":900,"interval":5}}"#),
    );
    let started = call(&mut vm, "start_device", std::slice::from_ref(&policy));
    let device = field(&started, "device_handle");
    let _ = transport.take_sent();

    let mut unrelated = Vec::new();
    while vm.host_context().resource_count() < 64 {
        unrelated.push(call(&mut vm, "issue_access", std::slice::from_ref(&policy)));
    }
    assert_eq!(vm.host_context().resource_count(), 64);
    transport.push_raw(
        200,
        &format!(r#"{{"code":"{CODE}","code_verifier":"{VERIFIER}","public":"captured"}}"#),
    );
    let failure = call_result(
        &mut vm,
        "capture",
        &[
            request(policy, "/oauth/token", r#"{"grant_type":"device_code"}"#),
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
                ("code_field", Value::string("code")),
                (
                    "redirect_uri",
                    Value::string("https://auth.example.test/callback"),
                ),
            ]),
        ],
    )
    .expect_err("pair issuance cannot exceed the resource ceiling");
    assert!(failure.to_string().ends_with("resource_limit"));
    assert_eq!(transport.take_sent().len(), 1);
    assert_eq!(
        vm.host_context().resource_count(),
        63,
        "terminal device alias closes; unrelated roots remain charged"
    );
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("capture rollback"),
        0
    );
    for handle in unrelated {
        call(&mut vm, "close_access", std::slice::from_ref(&handle));
    }
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn owner_cancelled_after_capture_response_reclaims_device_before_pair_publication() {
    let home = FixtureHome::new();
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let transport = Arc::new(CancelAfterCaptureResponse {
        cancellation: cancellation.clone(),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(home.0.clone(), cancellation)
        .expect("auth host")
        .with_oauth_host(oauth);
    let mut vm = vm_for(&auth);
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let snapshot = call(&mut vm, "snapshot", &[field(&owner, "host_home")]);
    let policy = field(&snapshot, "policy_handle");
    let started = call(&mut vm, "start_device", std::slice::from_ref(&policy));
    let device = field(&started, "device_handle");
    assert_eq!(
        transport.calls.load(std::sync::atomic::Ordering::Acquire),
        1
    );
    let failure = call_result(
        &mut vm,
        "capture",
        &[
            request(policy, "/oauth/token", r#"{"grant_type":"device_code"}"#),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device),
            ]),
            record(vec![
                ("encoding", Value::string("json_object")),
                ("secret_fields", Value::string("device")),
                ("device_field", Value::string("device_code")),
            ]),
            record(vec![
                ("code_field", Value::string("code")),
                (
                    "redirect_uri",
                    Value::string("https://auth.example.test/callback"),
                ),
            ]),
        ],
    )
    .expect_err("owner cancellation wins before pair publication");
    assert!(failure.to_string().contains("policy_inactive"));
    assert_eq!(
        transport.calls.load(std::sync::atomic::Ordering::Acquire),
        2
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("cancelled flow cleanup"),
        0
    );
}
