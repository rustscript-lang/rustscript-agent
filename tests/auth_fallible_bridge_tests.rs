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
use rustscript_vm::resource::{
    CloseProgress, HostResource, ResourceCloseReason, ResourceHandle, ResourceResult,
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, HostResourceType, ResourceTypeKey,
    SourceFlavor, Value, Vm, VmError, VmStatus, compile_source_at_path_with_flavor_and_options,
};
use std::{fs, path::PathBuf, sync::Arc, time::Duration};

struct PrivateHome(PathBuf);

impl PrivateHome {
    fn new() -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned TEMP"));
        let path = root.join(format!(
            "auth-fallible-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("private home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml")).expect("config fixture");
        let config = fs::read_to_string(path.join("config.yaml"))
            .expect("read config fixture")
            .replace("auth.openai.com", "auth.example.test");
        fs::write(path.join("config.yaml"), config).expect("synthetic .test endpoint");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("auth fixture")
            .replace("1788440000000", "1900000000000");
        fs::write(path.join("auth.yaml"), auth).expect("auth fixture copy");
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
}

impl Drop for PrivateHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(fields) = value else {
        panic!("expected RSS record")
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing RSS field {name}"))
}

fn record(fields: Vec<(&str, Value)>) -> Value {
    Value::map(
        fields
            .into_iter()
            .map(|(name, value)| (Value::string(name), value))
            .collect(),
    )
}

struct UnrelatedResource;

impl HostResource for UnrelatedResource {
    fn resource_type_key() -> Option<ResourceTypeKey> {
        Some(ResourceTypeKey::new(Self::KEY).expect("unrelated key"))
    }

    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        Ok(CloseProgress::Ready)
    }
}

impl HostResourceType for UnrelatedResource {
    const KEY: &'static str = "test.unrelated";
    const DESCRIPTION: &'static str = "Unrelated resource for cleanup preservation";
}

fn issue_unrelated(vm: &mut Vm) -> ResourceHandle {
    vm.host_context()
        .push_resource(UnrelatedResource)
        .expect("insert unrelated live resource")
        .handle()
}

fn assert_unrelated_live(vm: &mut Vm, handle: ResourceHandle) {
    vm.host_context()
        .borrow_resource_with_key::<UnrelatedResource>(
            handle,
            &ResourceTypeKey::new(UnrelatedResource::KEY).expect("unrelated key"),
        )
        .expect("cleanup leaves unrelated resource live");
}

fn vm(host: &AuthHost, catalog: &rustscript_vm::HostApiCatalog) -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/fallible_contract.rss");
    let source = fs::read_to_string(&path).expect("real fallible RSS contract");
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::new(catalog.clone())),
    )
    .expect("compile RSS against exact auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    host.register(&mut registry, catalog)
        .expect("register exact auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted registry");
    assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
    vm
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Result<Value, VmError> {
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args)
}

fn request(policy: &Value) -> Value {
    record(vec![
        ("policy_handle", policy.clone()),
        ("credential_id", Value::string("fixture-codex")),
        ("method", Value::string("GET")),
        ("path", Value::string("/oauth/token")),
        (
            "public_headers",
            Value::array(vec![record(vec![
                ("name", Value::string("accept")),
                ("value", Value::string("application/json")),
            ])]),
        ),
        ("public_body", Value::string("")),
    ])
}

fn native_result_slots(vm: &mut Vm, policy: &Value) -> Value {
    let started = invoke(vm, "start_device_result", std::slice::from_ref(policy))
        .expect("native device result");
    assert_eq!(field(&started, "ok"), &Value::Bool(true));
    let device = field(field(&started, "value"), "device_handle").clone();
    let request = |body: &str, path: &str| {
        record(vec![
            ("policy_handle", policy.clone()),
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
            ("public_body", Value::string(body)),
        ])
    };
    let captured = invoke(
        vm,
        "capture_result",
        &[
            request(
                r#"{"grant_type":"device_code"}"#,
                "/api/accounts/deviceauth/token",
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
    )
    .expect("native capture result");
    assert_eq!(field(&captured, "ok"), &Value::Bool(true));
    let code = field(field(&captured, "value"), "code_handle").clone();
    let verifier = field(field(&captured, "value"), "verifier_handle").clone();
    let exchanged = invoke(
        vm,
        "exchange_selected_result",
        &[
            request(r#"{"grant_type":"authorization_code"}"#, "/oauth/token"),
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
    )
    .expect("native selected exchange result");
    assert_eq!(field(&exchanged, "ok"), &Value::Bool(true));
    field(&exchanged, "value").clone()
}

#[test]
fn actual_malformed_transport_is_readable_but_legacy_call_still_traps() {
    const RESPONSE_MARKER: &str = "AUTH_FALLIBLE_RESPONSE_PRIVATE_MARKER_4d8e";
    let private_home = PrivateHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, RESPONSE_MARKER);
    transport.push_raw(200, RESPONSE_MARKER);
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let host = AuthHost::new(private_home.0.clone(), cancellation)
        .expect("auth host")
        .with_oauth_host(oauth);
    let catalog = auth_host_catalog();
    let mut vm = vm(&host, catalog.as_ref());
    let context = host.bind_vm(&mut vm).expect("bind native owner");
    let home = field(&context, "host_home").clone();
    let policy = invoke(&mut vm, "snapshot", &[home]).expect("load native policy");
    let forged_policy = request(&Value::Int(i64::MAX));
    assert!(
        invoke(
            &mut vm,
            "transport_result",
            &[forged_policy, record(vec![("kind", Value::string("none"))])],
        )
        .is_err(),
        "Core resource validation remains a trap"
    );
    assert!(
        transport.take_sent().is_empty(),
        "forged policy causes no send"
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    let request = request(&policy);
    let usage = record(vec![("kind", Value::string("none"))]);

    let readable = invoke(
        &mut vm,
        "transport_result",
        &[request.clone(), usage.clone()],
    )
    .expect("RSS must continue with a named failure result");
    assert_eq!(field(&readable, "ok"), &Value::Bool(false));
    assert!(matches!(field(&readable, "value"), Value::Null));
    let failure = field(&readable, "error");
    assert_eq!(field(failure, "code"), &Value::string("malformed_response"));
    assert_eq!(field(failure, "cancelled"), &Value::Bool(false));
    assert_eq!(field(failure, "deadline_exceeded"), &Value::Bool(false));
    assert_eq!(field(failure, "revoked"), &Value::Bool(false));
    assert!(!format!("{readable:?}").contains(RESPONSE_MARKER));

    let legacy = invoke(&mut vm, "legacy_transport", &[request, usage])
        .expect_err("legacy transport keeps its HostError trap contract");
    assert!(matches!(&legacy, VmError::HostError(code) if code == "malformed_response"));
    assert!(!legacy.to_string().contains(RESPONSE_MARKER));
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 2, "each adapter call sends exactly once");
    assert!(
        sent.iter()
            .all(|request| request.url == "https://auth.example.test/oauth/token")
    );
}

#[test]
fn rss_cleanup_after_failure_closes_only_the_native_owner_access_handle() {
    const RESPONSE_MARKER: &str = "AUTH_CLEANUP_RESPONSE_PRIVATE_MARKER_2c7f";
    let private_home = PrivateHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, RESPONSE_MARKER);
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let host = AuthHost::new(
        private_home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(oauth);
    let catalog = auth_host_catalog();
    let mut vm = vm(&host, catalog.as_ref());
    let context = host.bind_vm(&mut vm).expect("bind native owner");
    let home = field(&context, "host_home").clone();
    let policy = invoke(&mut vm, "snapshot", &[home]).expect("load native policy");
    let access = invoke(&mut vm, "issue_access", std::slice::from_ref(&policy))
        .expect("issue native access capability");
    let unrelated = issue_unrelated(&mut vm);
    assert_eq!(vm.host_context().resource_count(), 4);
    let request = request(&policy);
    let usage = record(vec![("kind", Value::string("none"))]);

    let continued = invoke(
        &mut vm,
        "transport_result_then_cleanup",
        &[request, usage, policy.clone()],
    )
    .expect("RSS must continue from transport failure into cleanup");
    assert_eq!(field(&continued, "cleanup_completed"), &Value::Bool(true));
    let result = field(&continued, "transport");
    assert_eq!(field(result, "ok"), &Value::Bool(false));
    assert_eq!(
        field(field(result, "error"), "code"),
        &Value::string("malformed_response")
    );
    assert!(!format!("{continued:?}").contains(RESPONSE_MARKER));
    assert_eq!(
        vm.host_context().resource_count(),
        3,
        "home, policy, and unrelated resource remain"
    );
    assert_unrelated_live(&mut vm, unrelated);
    assert!(invoke(&mut vm, "close_access", &[access]).is_err());
    assert_eq!(transport.take_sent().len(), 1, "one native request");

    for _ in 0..70 {
        let _access = invoke(&mut vm, "issue_access", std::slice::from_ref(&policy))
            .expect("native access issuance after prior cleanup");
        assert_eq!(vm.host_context().resource_count(), 4);
        assert_eq!(
            invoke(&mut vm, "cleanup", std::slice::from_ref(&policy)).expect("bounded cleanup"),
            Value::Null
        );
        assert_eq!(vm.host_context().resource_count(), 3);
        assert_unrelated_live(&mut vm, unrelated);
    }
}

#[test]
fn cleanup_is_vm_owner_bound_and_closes_pairs_and_unsaved_slots() {
    const DEVICE_A: &str = "OWNER_A_DEVICE_PRIVATE_630d";
    const DEVICE_B: &str = "OWNER_B_DEVICE_PRIVATE_6e44";
    const DEVICE_B_NEXT: &str = "OWNER_B_NEXT_DEVICE_PRIVATE_9a2f";
    const CODE_B: &str = "OWNER_B_CODE_PRIVATE_161c";
    const CODE_B_NEXT: &str = "OWNER_B_NEXT_CODE_PRIVATE_27ad";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    const ACCESS: &str = "OWNER_B_UNSAVED_ACCESS_PRIVATE_3871";
    const REFRESH: &str = "OWNER_B_UNSAVED_REFRESH_PRIVATE_42c8";

    let private_home = PrivateHome::new();
    let config_path = private_home.0.join("config.yaml");
    let config = fs::read_to_string(&config_path)
        .expect("fixture config")
        .replace("auth.openai.com", "auth.example.test");
    fs::write(config_path, config).expect("synthetic .test endpoints");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"device_code":"{DEVICE_A}","user_code":"SYNTHETIC-USER","verification_uri":"https://auth.example.test/device","expires_in":900,"interval":5}}"#
        ),
    );
    transport.push_raw(
        200,
        &format!(
            r#"{{"device_code":"{DEVICE_B}","user_code":"SYNTHETIC-USER","verification_uri":"https://auth.example.test/device","expires_in":900,"interval":5}}"#
        ),
    );
    transport.push_raw(
        200,
        &format!(
            r#"{{"authorization_code":"{CODE_B}","code_verifier":"{VERIFIER}","public":"captured"}}"#
        ),
    );
    transport.push_raw(
        200,
        &format!(
            r#"{{"device_code":"{DEVICE_B_NEXT}","user_code":"SYNTHETIC-USER","verification_uri":"https://auth.example.test/device","expires_in":900,"interval":5}}"#
        ),
    );
    transport.push_raw(
        200,
        &format!(
            r#"{{"authorization_code":"{CODE_B_NEXT}","code_verifier":"{VERIFIER}","public":"captured"}}"#
        ),
    );
    transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{ACCESS}","refresh_token":"{REFRESH}","token_type":"Bearer","expires_in":3600,"public":"authorized"}}"#
        ),
    );
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let host = AuthHost::new(
        private_home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("shared auth host")
    .with_oauth_host(oauth);
    let catalog = auth_host_catalog();
    let mut vm_a = vm(&host, catalog.as_ref());
    let mut vm_b = vm(&host, catalog.as_ref());
    let context_a = host.bind_vm(&mut vm_a).expect("bind owner A");
    let context_b = host.bind_vm(&mut vm_b).expect("bind owner B");
    let policy_a = invoke(
        &mut vm_a,
        "snapshot",
        &[field(&context_a, "host_home").clone()],
    )
    .expect("owner A policy");
    let policy_b = invoke(
        &mut vm_b,
        "snapshot",
        &[field(&context_b, "host_home").clone()],
    )
    .expect("owner B policy");

    let started_a = invoke(
        &mut vm_a,
        "start_device_result",
        std::slice::from_ref(&policy_a),
    )
    .expect("native owner A flow");
    assert_eq!(field(&started_a, "ok"), &Value::Bool(true));
    let started_b = invoke(
        &mut vm_b,
        "start_device_result",
        std::slice::from_ref(&policy_b),
    )
    .expect("native owner B flow");
    let device_b = field(field(&started_b, "value"), "device_handle").clone();
    assert_eq!(vm_a.host_context().resource_count(), 3);
    assert_eq!(vm_b.host_context().resource_count(), 3);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        host.fixture_live_oauth_flow_count()
            .expect("two live native flows"),
        2
    );

    assert_eq!(
        invoke(&mut vm_a, "cleanup", std::slice::from_ref(&policy_a)).expect("cleanup owner A"),
        Value::Null
    );
    assert_eq!(vm_a.host_context().resource_count(), 2);
    assert_eq!(vm_b.host_context().resource_count(), 3);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        host.fixture_live_oauth_flow_count()
            .expect("owner B flow remains"),
        1
    );

    let request = |policy: &Value, body: &str, path: &str| {
        record(vec![
            ("policy_handle", policy.clone()),
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
            ("public_body", Value::string(body)),
        ])
    };
    let payload = || {
        record(vec![
            ("encoding", Value::string("json_object")),
            ("secret_fields", Value::string("device")),
            ("device_field", Value::string("device_id")),
        ])
    };
    let capture_intent = || {
        record(vec![
            ("code_field", Value::string("authorization_code")),
            (
                "redirect_uri",
                Value::string("https://auth.example.test/callback"),
            ),
        ])
    };
    let captured_b = invoke(
        &mut vm_b,
        "capture_result",
        &[
            request(
                &policy_b,
                r#"{"grant_type":"device_code"}"#,
                "/api/accounts/deviceauth/token",
            ),
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device_b),
            ]),
            payload(),
            capture_intent(),
        ],
    )
    .expect("owner B native pair after owner A cleanup");
    assert_eq!(field(&captured_b, "ok"), &Value::Bool(true));
    let code_b = field(field(&captured_b, "value"), "code_handle").clone();
    let verifier_b = field(field(&captured_b, "value"), "verifier_handle").clone();
    assert_eq!(vm_b.host_context().resource_count(), 4);
    assert_eq!(
        invoke(&mut vm_b, "cleanup", std::slice::from_ref(&policy_b)).expect("cleanup pair"),
        Value::Null
    );
    assert_eq!(vm_b.host_context().resource_count(), 2);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        host.fixture_live_oauth_flow_count().expect("pair closed"),
        0
    );

    let after_pair_cleanup = transport.take_sent();
    assert_eq!(after_pair_cleanup.len(), 3);
    assert!(
        invoke(
            &mut vm_b,
            "exchange_selected_result",
            &[
                request(
                    &policy_b,
                    r#"{"grant_type":"authorization_code"}"#,
                    "/oauth/token",
                ),
                record(vec![
                    ("kind", Value::string("code_verifier")),
                    ("code_handle", code_b),
                    ("verifier_handle", verifier_b),
                ]),
                record(vec![
                    ("encoding", Value::string("json_object")),
                    ("secret_fields", Value::string("authorization_code")),
                    ("code_field", Value::string("authorization_code")),
                ]),
            ],
        )
        .is_err()
    );
    assert!(transport.take_sent().is_empty(), "closed pair cannot send");

    let started_again = invoke(
        &mut vm_b,
        "start_device_result",
        std::slice::from_ref(&policy_b),
    )
    .expect("owner can start a new flow after cleanup");
    let captured_again = invoke(
        &mut vm_b,
        "capture_result",
        &[
            request(
                &policy_b,
                r#"{"grant_type":"device_code"}"#,
                "/api/accounts/deviceauth/token",
            ),
            record(vec![
                ("kind", Value::string("device_session")),
                (
                    "device_handle",
                    field(field(&started_again, "value"), "device_handle").clone(),
                ),
            ]),
            payload(),
            capture_intent(),
        ],
    )
    .expect("new flow capture");
    let exchanged = invoke(
        &mut vm_b,
        "exchange_selected_result",
        &[
            request(
                &policy_b,
                r#"{"grant_type":"authorization_code"}"#,
                "/oauth/token",
            ),
            record(vec![
                ("kind", Value::string("code_verifier")),
                (
                    "code_handle",
                    field(field(&captured_again, "value"), "code_handle").clone(),
                ),
                (
                    "verifier_handle",
                    field(field(&captured_again, "value"), "verifier_handle").clone(),
                ),
            ]),
            record(vec![
                ("encoding", Value::string("json_object")),
                ("secret_fields", Value::string("authorization_code")),
                ("code_field", Value::string("authorization_code")),
            ]),
        ],
    )
    .expect("new flow selected exchange");
    assert_eq!(field(&exchanged, "ok"), &Value::Bool(true));
    assert_eq!(vm_b.host_context().resource_count(), 4);
    assert_eq!(
        invoke(&mut vm_b, "cleanup", std::slice::from_ref(&policy_b))
            .expect("cleanup unsaved native slots"),
        Value::Null
    );
    assert_eq!(vm_b.host_context().resource_count(), 2);
    let sends = transport.take_sent();
    assert_eq!(sends.len(), 3, "closed pair replay did not send");
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        host.fixture_live_oauth_flow_count()
            .expect("all native flows closed"),
        0
    );
}

#[cfg(feature = "config-fixture")]
#[test]
fn cleanup_closes_native_callback_verifier_access_and_refresh_resources() {
    let private_home = PrivateHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let host = AuthHost::new(
        private_home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    )))
    .with_oauth_callback_fixture();
    let catalog = auth_host_catalog();
    let mut vm = vm(&host, catalog.as_ref());
    let context = host.bind_vm(&mut vm).expect("bind native owner");
    let policy = invoke(&mut vm, "snapshot", &[field(&context, "host_home").clone()])
        .expect("native policy");
    let pair = invoke(&mut vm, "begin_manual", std::slice::from_ref(&policy))
        .expect("native PKCE callback and verifier resources");
    assert_eq!(field(&pair, "ok"), &Value::Bool(true));
    assert_eq!(vm.host_context().resource_count(), 4);
    let access = invoke(&mut vm, "issue_access", std::slice::from_ref(&policy))
        .expect("native access handle");
    let refresh = invoke(&mut vm, "issue_refresh", std::slice::from_ref(&policy))
        .expect("native refresh handle");
    assert!(matches!(access, Value::Int(_)) && matches!(refresh, Value::Int(_)));
    assert_eq!(vm.host_context().resource_count(), 6);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        host.fixture_live_oauth_flow_count()
            .expect("live callback flow"),
        1
    );
    assert_eq!(
        transport.take_sent().len(),
        0,
        "issuance has no transport side effect"
    );

    assert_eq!(
        invoke(&mut vm, "cleanup", std::slice::from_ref(&policy))
            .expect("cleanup closes all native auth transient classes"),
        Value::Null
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        host.fixture_live_oauth_flow_count()
            .expect("callback flow closed"),
        0
    );
}

#[test]
fn native_send_and_oversized_response_failures_are_guest_readable() {
    const TOKEN_MARKER: &str = "FALLIBLE_OVERSIZED_TOKEN_PRIVATE_93b4";

    let private_home = PrivateHome::new();
    let config_path = private_home.0.join("config.yaml");
    let config = fs::read_to_string(&config_path)
        .expect("fixture config")
        .replace("auth.openai.com", "auth.example.test");
    fs::write(config_path, config).expect("synthetic .test endpoint");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let host = AuthHost::new(
        private_home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    )));
    let catalog = auth_host_catalog();
    let mut send_vm = vm(&host, catalog.as_ref());
    let context = host.bind_vm(&mut send_vm).expect("bind native owner");
    let policy = invoke(
        &mut send_vm,
        "snapshot",
        &[field(&context, "host_home").clone()],
    )
    .expect("native policy");

    let send_failure = invoke(
        &mut send_vm,
        "start_device_result",
        std::slice::from_ref(&policy),
    )
    .expect("native send failure result");
    assert_eq!(field(&send_failure, "ok"), &Value::Bool(false));
    assert!(matches!(field(&send_failure, "value"), Value::Null));
    assert_eq!(
        field(field(&send_failure, "error"), "code"),
        &Value::string("transport_error")
    );
    assert!(!format!("{send_failure:?}").contains("scripted transport has no queued response"));
    assert_eq!(transport.take_sent().len(), 1);
    assert_eq!(send_vm.host_context().resource_count(), 2);

    let oversized_transport = Arc::new(ScriptedHttpsTransport::new());
    oversized_transport.push_raw(
        200,
        &format!(
            r#"{{"access_token":"{TOKEN_MARKER}","public":"{}"}}"#,
            "x".repeat(66_000)
        ),
    );
    let oversized_host = AuthHost::new(
        private_home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("oversized response host")
    .with_oauth_host(Arc::new(OAuthHost::new(
        oversized_transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    )));
    let mut oversized_vm = vm(&oversized_host, catalog.as_ref());
    let oversized_context = oversized_host
        .bind_vm(&mut oversized_vm)
        .expect("bind oversized owner");
    let oversized_policy = invoke(
        &mut oversized_vm,
        "snapshot",
        &[field(&oversized_context, "host_home").clone()],
    )
    .expect("oversized response policy");
    let oversized = invoke(
        &mut oversized_vm,
        "start_device_result",
        std::slice::from_ref(&oversized_policy),
    )
    .expect("oversized response typed result");
    assert_eq!(field(&oversized, "ok"), &Value::Bool(false));
    assert!(matches!(field(&oversized, "value"), Value::Null));
    assert_eq!(
        field(field(&oversized, "error"), "code"),
        &Value::string("response_too_large")
    );
    assert!(!format!("{oversized:?}").contains(TOKEN_MARKER));
    assert_eq!(oversized_transport.take_sent().len(), 1);
    assert_eq!(oversized_vm.host_context().resource_count(), 2);
}

#[test]
fn native_publication_failure_rolls_back_after_real_transport_send() {
    const DEVICE_MARKER: &str = "FALLIBLE_PUBLICATION_DEVICE_PRIVATE_19b2";

    let private_home = PrivateHome::new();
    let config_path = private_home.0.join("config.yaml");
    let config = fs::read_to_string(&config_path)
        .expect("fixture config")
        .replace("auth.openai.com", "auth.example.test");
    fs::write(config_path, config).expect("synthetic .test endpoint");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        &format!(
            r#"{{"device_code":"{DEVICE_MARKER}","user_code":"SYNTHETIC-USER","verification_uri":"https://auth.example.test/device","expires_in":900,"interval":5}}"#
        ),
    );
    let host = AuthHost::new(
        private_home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    )));
    let catalog = auth_host_catalog();
    let mut vm = vm(&host, catalog.as_ref());
    let context = host.bind_vm(&mut vm).expect("bind native owner");
    let policy = invoke(&mut vm, "snapshot", &[field(&context, "host_home").clone()])
        .expect("native policy");
    while vm.host_context().resource_count() < 64 {
        let _access = invoke(&mut vm, "issue_access", std::slice::from_ref(&policy))
            .expect("native access capability fills the remaining arena");
    }
    let count_before_publication = vm.host_context().resource_count();
    let failure = invoke(
        &mut vm,
        "start_device_result",
        std::slice::from_ref(&policy),
    )
    .expect("native response publication failure result");
    assert_eq!(field(&failure, "ok"), &Value::Bool(false));
    assert!(matches!(field(&failure, "value"), Value::Null));
    assert_eq!(
        field(field(&failure, "error"), "code"),
        &Value::string("resource_limit")
    );
    assert!(!format!("{failure:?}").contains(DEVICE_MARKER));
    assert_eq!(vm.host_context().resource_count(), count_before_publication);
    assert_eq!(
        transport.take_sent().len(),
        1,
        "response came from native send"
    );
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        host.fixture_live_oauth_flow_count()
            .expect("native rollback"),
        0
    );
    assert_eq!(
        invoke(&mut vm, "cleanup", std::slice::from_ref(&policy)).expect("close filled resources"),
        Value::Null
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn clock_wait_and_public_json_failures_are_guest_readable() {
    const JSON_MARKER: &str = "AUTH_JSON_PRIVATE_MARKER_b7e1";
    let private_home = PrivateHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let host = AuthHost::new(
        private_home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(oauth);
    let catalog = auth_host_catalog();
    let mut vm = vm(&host, catalog.as_ref());
    let context = host.bind_vm(&mut vm).expect("bind native owner");
    let home = field(&context, "host_home").clone();
    let policy = invoke(&mut vm, "snapshot", &[home]).expect("load native policy");

    let now = invoke(&mut vm, "now_result", std::slice::from_ref(&policy))
        .expect("actual native clock result");
    assert_eq!(field(&now, "ok"), &Value::Bool(true));
    assert_eq!(field(&now, "error"), &Value::Null);
    assert_eq!(field(&now, "value"), &Value::Int(1_900_000_000_000));

    let waited = invoke(&mut vm, "wait_result", &[policy.clone(), Value::Int(0)])
        .expect("zero-duration native wait result");
    assert_eq!(field(&waited, "ok"), &Value::Bool(true));
    assert_eq!(field(&waited, "error"), &Value::Null);
    let Value::Map(wait_fields) = &waited else {
        panic!("wait result is a named record");
    };
    assert!(
        wait_fields
            .iter()
            .all(|(key, _)| { !matches!(key, Value::String(key) if key.as_ref() == "value") })
    );

    let malformed = invoke(
        &mut vm,
        "public_json_field_result",
        &[
            policy.clone(),
            Value::string(format!("{JSON_MARKER}{{")),
            Value::string(""),
        ],
    )
    .expect("malformed JSON returns a typed result");
    assert_eq!(field(&malformed, "ok"), &Value::Bool(false));
    assert!(matches!(field(&malformed, "value"), Value::Null));
    assert_eq!(
        field(field(&malformed, "error"), "code"),
        &Value::string("public_json_invalid")
    );
    assert!(!format!("{malformed:?}").contains(JSON_MARKER));

    let oversized = invoke(
        &mut vm,
        "public_json_field_result",
        &[policy, Value::string("x".repeat(65_537)), Value::string("")],
    )
    .expect("over-bound JSON returns a typed failure");
    assert_eq!(field(&oversized, "ok"), &Value::Bool(false));
    assert!(matches!(field(&oversized, "value"), Value::Null));
    assert_eq!(
        field(field(&oversized, "error"), "code"),
        &Value::string("public_json_too_large")
    );
}

#[test]
fn native_result_cas_conflict_and_adoption_preserve_winner() {
    use rustscript_agent::auth::store::AuthStore;

    const DEVICE_A: &str = "CAS_DEVICE_A_PRIVATE_0319";
    const DEVICE_B: &str = "CAS_DEVICE_B_PRIVATE_0b31";
    const DEVICE_C: &str = "CAS_DEVICE_C_PRIVATE_64ab";
    const CODE_A: &str = "CAS_CODE_A_PRIVATE_9d20";
    const CODE_B: &str = "CAS_CODE_B_PRIVATE_c503";
    const CODE_C: &str = "CAS_CODE_C_PRIVATE_4c3f";
    const ACCESS_A: &str = "CAS_ACCESS_A_PRIVATE_285e";
    const ACCESS_B: &str = "CAS_ACCESS_B_PRIVATE_930f";
    const ACCESS_C: &str = "CAS_ACCESS_C_PRIVATE_320a";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

    let private_home = PrivateHome::new();
    let config_path = private_home.0.join("config.yaml");
    let config = fs::read_to_string(&config_path)
        .expect("fixture config")
        .replace("auth.openai.com", "auth.example.test");
    fs::write(config_path, config).expect("synthetic .test config");
    fs::write(
        private_home.0.join("auth.yaml"),
        b"version: 1\ncredentials: {}\n",
    )
    .expect("empty enrollment store");

    let transport = Arc::new(ScriptedHttpsTransport::new());
    for (device, code, access) in [
        (DEVICE_A, CODE_A, ACCESS_A),
        (DEVICE_B, CODE_B, ACCESS_B),
        (DEVICE_C, CODE_C, ACCESS_C),
    ] {
        transport.push_raw(
            200,
            &format!(
                r#"{{"device_code":"{device}","user_code":"SYNTHETIC-USER","verification_uri":"https://auth.example.test/device","expires_in":900,"interval":5}}"#
            ),
        );
        transport.push_raw(
            200,
            &format!(
                r#"{{"authorization_code":"{code}","code_verifier":"{VERIFIER}","public":"captured"}}"#
            ),
        );
        transport.push_raw(
            200,
            &format!(r#"{{"access_token":"{access}","token_type":"Bearer","expires_in":3600}}"#),
        );
    }
    let host = AuthHost::new_for_enrollment(
        private_home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
        "fixture-codex",
    )
    .expect("enrollment host")
    .with_oauth_host(Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    )));
    let catalog = auth_host_catalog();
    let mut vm_a = vm(&host, catalog.as_ref());
    let mut vm_b = vm(&host, catalog.as_ref());
    let mut vm_c = vm(&host, catalog.as_ref());
    let context_a = host.bind_vm(&mut vm_a).expect("bind owner A");
    let context_b = host.bind_vm(&mut vm_b).expect("bind owner B");
    let context_c = host.bind_vm(&mut vm_c).expect("bind owner C");
    let policy_a = invoke(
        &mut vm_a,
        "snapshot",
        &[field(&context_a, "host_home").clone()],
    )
    .expect("owner A policy");
    let policy_b = invoke(
        &mut vm_b,
        "snapshot",
        &[field(&context_b, "host_home").clone()],
    )
    .expect("owner B policy");
    let policy_c = invoke(
        &mut vm_c,
        "snapshot",
        &[field(&context_c, "host_home").clone()],
    )
    .expect("owner C policy");
    let slots_a = native_result_slots(&mut vm_a, &policy_a);
    let slots_b = native_result_slots(&mut vm_b, &policy_b);
    let slots_c = native_result_slots(&mut vm_c, &policy_c);

    let save_request = |policy: &Value, slots: &Value, expected: i64| {
        let metadata = record(vec![
            ("provider", Value::string("openai-codex")),
            ("kind", Value::string("oauth")),
            ("source", Value::string("native-rss-cas")),
            ("token_type", Value::string("Bearer")),
            ("expires_at_ms", Value::Int(1_900_003_600_000)),
            (
                "scopes",
                Value::array(vec![Value::string("scope.synthetic")]),
            ),
            ("account_id", Value::string("native-cas-account")),
            ("generation", Value::Int(expected)),
            ("status", Value::string("active")),
            ("last_refresh_at_ms", Value::Null),
            ("has_refresh_token", Value::Bool(false)),
        ]);
        record(vec![
            ("credential_id", Value::string("fixture-codex")),
            ("expected_generation", Value::Int(expected)),
            ("policy_handle", policy.clone()),
            ("metadata", metadata),
            ("access_slot", field(slots, "access_slot").clone()),
            ("refresh_action", Value::string("clear")),
            ("refresh_slot", Value::Null),
        ])
    };

    let rejected = invoke(
        &mut vm_c,
        "save_result",
        &[save_request(&policy_c, &slots_c, 1)],
    )
    .expect("future CAS generation is a guest-readable failure");
    assert_eq!(field(&rejected, "ok"), &Value::Bool(false));
    assert!(matches!(field(&rejected, "value"), Value::Null));
    assert_eq!(
        field(field(&rejected, "error"), "code"),
        &Value::string("save_rejected")
    );
    assert_eq!(
        vm_c.host_context().resource_count(),
        3,
        "guarded rejection keeps its slot retryable"
    );
    assert_eq!(
        invoke(&mut vm_c, "cleanup", std::slice::from_ref(&policy_c))
            .expect("close the retryable rejected candidate"),
        Value::Null
    );
    assert_eq!(vm_c.host_context().resource_count(), 2);
    assert!(
        AuthStore::from_home(&private_home.0)
            .expect("native store after rejected CAS")
            .load_metadata("fixture-codex")
            .is_err()
    );

    let committed = invoke(
        &mut vm_b,
        "save_result",
        &[save_request(&policy_b, &slots_b, 0)],
    )
    .expect("native expected-generation commit");
    assert_eq!(field(&committed, "ok"), &Value::Bool(true));
    let committed_value = field(&committed, "value");
    assert_eq!(
        field(committed_value, "outcome"),
        &Value::string("committed")
    );
    assert_eq!(
        field(field(committed_value, "metadata"), "generation"),
        &Value::Int(1)
    );

    let adopted = invoke(
        &mut vm_a,
        "save_result",
        &[save_request(&policy_a, &slots_a, 0)],
    )
    .expect("stale native response is adopted without overwrite");
    assert_eq!(field(&adopted, "ok"), &Value::Bool(true));
    let adopted_value = field(&adopted, "value");
    assert_eq!(field(adopted_value, "outcome"), &Value::string("adopted"));
    assert_eq!(
        field(field(adopted_value, "metadata"), "generation"),
        &Value::Int(1)
    );

    let persisted = fs::read(private_home.0.join("auth.yaml")).expect("committed bytes");
    assert!(
        persisted
            .windows(ACCESS_B.len())
            .any(|window| window == ACCESS_B.as_bytes())
    );
    for stale in [ACCESS_A, ACCESS_C] {
        assert!(
            !persisted
                .windows(stale.len())
                .any(|window| window == stale.as_bytes())
        );
    }
    assert_eq!(transport.take_sent().len(), 9);
    assert_eq!(vm_a.host_context().resource_count(), 2);
    assert_eq!(vm_b.host_context().resource_count(), 2);
    assert_eq!(vm_c.host_context().resource_count(), 2);
}

#[test]
fn native_capture_exchange_and_save_result_commits_generation_zero_once() {
    use rustscript_agent::auth::store::AuthStore;

    const DEVICE_CODE: &str = "FALLIBLE_DEVICE_PRIVATE_5e3a";
    const AUTH_CODE: &str = "FALLIBLE_CODE_PRIVATE_82b1";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    const ACCESS: &str = "FALLIBLE_ACCESS_PRIVATE_a11c";
    const REFRESH: &str = "FALLIBLE_REFRESH_PRIVATE_7fd0";

    for include_refresh in [false, true] {
        let private_home = PrivateHome::new();
        let config_path = private_home.0.join("config.yaml");
        let config = fs::read_to_string(&config_path)
            .expect("fixture config")
            .replace("auth.openai.com", "auth.example.test");
        fs::write(config_path, config).expect("synthetic .test config");
        fs::write(
            private_home.0.join("auth.yaml"),
            b"version: 1\ncredentials: {}\n",
        )
        .expect("empty enrollment store");

        let transport = Arc::new(ScriptedHttpsTransport::new());
        transport.push_raw(
            200,
            &format!(
                r#"{{"device_code":"{DEVICE_CODE}","user_code":"SYNTHETIC-USER","verification_uri":"https://auth.example.test/device","expires_in":900,"interval":5}}"#
            ),
        );
        transport.push_raw(
            200,
            &format!(
                r#"{{"authorization_code":"{AUTH_CODE}","code_verifier":"{VERIFIER}","public":"captured"}}"#
            ),
        );
        let refresh = if include_refresh {
            format!(r#", "refresh_token":"{REFRESH}""#)
        } else {
            String::new()
        };
        transport.push_raw(
            200,
            &format!(
                r#"{{"access_token":"{ACCESS}"{refresh},"token_type":"Bearer","expires_in":3600,"public":"authorized"}}"#
            ),
        );
        let oauth = Arc::new(OAuthHost::new(
            transport.clone(),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(1_900_000_000_000)),
            Arc::new(ScriptedCancel::new()),
        ));
        let host = AuthHost::new_for_enrollment(
            private_home.0.clone(),
            RunCancellation::with_timeout(Duration::from_secs(30)),
            "fixture-codex",
        )
        .expect("enrollment host")
        .with_oauth_host(oauth);
        let catalog = auth_host_catalog();
        let mut vm = vm(&host, catalog.as_ref());
        let context = host.bind_vm(&mut vm).expect("bind native owner");
        let home = field(&context, "host_home").clone();
        let policy = invoke(&mut vm, "snapshot", &[home]).expect("enrollment policy");

        let started = invoke(
            &mut vm,
            "start_device_result",
            std::slice::from_ref(&policy),
        )
        .expect("native RSS device start result");
        assert_eq!(field(&started, "ok"), &Value::Bool(true));
        let started_value = field(&started, "value");
        let device = field(started_value, "device_handle").clone();

        let request = |body: &str, path: &str| {
            record(vec![
                ("policy_handle", policy.clone()),
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
                ("public_body", Value::string(body)),
            ])
        };
        let captured = invoke(
            &mut vm,
            "capture_result",
            &[
                request(
                    r#"{"grant_type":"device_code"}"#,
                    "/api/accounts/deviceauth/token",
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
        )
        .expect("native RSS capture result");
        assert_eq!(field(&captured, "ok"), &Value::Bool(true));
        let captured_value = field(&captured, "value");
        let code = field(captured_value, "code_handle").clone();
        let verifier = field(captured_value, "verifier_handle").clone();

        let exchanged = invoke(
            &mut vm,
            "exchange_selected_result",
            &[
                request(r#"{"grant_type":"authorization_code"}"#, "/oauth/token"),
                record(vec![
                    ("kind", Value::string("code_verifier")),
                    ("code_handle", code.clone()),
                    ("verifier_handle", verifier.clone()),
                ]),
                record(vec![
                    ("encoding", Value::string("json_object")),
                    ("secret_fields", Value::string("authorization_code")),
                    ("code_field", Value::string("authorization_code")),
                ]),
            ],
        )
        .expect("native RSS selected exchange result");
        assert_eq!(field(&exchanged, "ok"), &Value::Bool(true));
        let response = field(&exchanged, "value");
        let access_slot = field(response, "access_slot").clone();
        let refresh_slot = field(response, "refresh_slot").clone();
        assert_eq!(
            matches!(refresh_slot, Value::Int(_)),
            include_refresh,
            "optional native refresh capability"
        );
        let public_output = format!("{started:?}{captured:?}{exchanged:?}");
        for secret in [DEVICE_CODE, AUTH_CODE, VERIFIER, ACCESS, REFRESH] {
            assert!(!public_output.contains(secret));
        }

        let metadata = record(vec![
            ("provider", Value::string("openai-codex")),
            ("kind", Value::string("oauth")),
            ("source", Value::string("native-rss-test")),
            ("token_type", Value::string("Bearer")),
            ("expires_at_ms", Value::Int(1_900_003_600_000)),
            (
                "scopes",
                Value::array(vec![Value::string("scope.synthetic")]),
            ),
            ("account_id", Value::string("rss-native-account")),
            ("generation", Value::Int(0)),
            ("status", Value::string("active")),
            ("last_refresh_at_ms", Value::Null),
            ("has_refresh_token", Value::Bool(include_refresh)),
        ]);
        let save_request = record(vec![
            ("credential_id", Value::string("fixture-codex")),
            ("expected_generation", Value::Int(0)),
            ("policy_handle", policy.clone()),
            ("metadata", metadata),
            ("access_slot", access_slot.clone()),
            (
                "refresh_action",
                Value::string(if include_refresh { "replace" } else { "clear" }),
            ),
            ("refresh_slot", refresh_slot.clone()),
        ]);
        let saved = invoke(&mut vm, "save_result", std::slice::from_ref(&save_request))
            .expect("native RSS CAS result");
        assert_eq!(field(&saved, "ok"), &Value::Bool(true));
        let saved_value = field(&saved, "value");
        assert_eq!(
            field(field(saved_value, "metadata"), "generation"),
            &Value::Int(1)
        );
        let sent = transport.take_sent();
        assert_eq!(sent.len(), 3, "one send for start, capture, exchange");
        assert_eq!(
            sent[0].url,
            "https://auth.example.test/api/accounts/deviceauth/usercode"
        );
        assert_eq!(
            sent[1].url,
            "https://auth.example.test/api/accounts/deviceauth/token"
        );
        assert_eq!(sent[2].url, "https://auth.example.test/oauth/token");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&sent[0].body)
                .expect("native start wire JSON")["client_id"],
            "public-client-id"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&sent[1].body)
                .expect("native capture wire JSON")["device_id"],
            DEVICE_CODE
        );
        let exchange_wire: serde_json::Value =
            serde_json::from_str(&sent[2].body).expect("native exchange wire JSON");
        assert_eq!(exchange_wire["authorization_code"], AUTH_CODE);
        assert_eq!(exchange_wire["code_verifier"], VERIFIER);
        assert_eq!(
            exchange_wire["redirect_uri"],
            "https://auth.example.test/callback"
        );
        let store = AuthStore::from_home(&private_home.0).expect("native auth store");
        assert_eq!(
            store
                .load_metadata("fixture-codex")
                .expect("saved metadata")
                .generation,
            1
        );
        let persisted = fs::read(private_home.0.join("auth.yaml")).expect("persisted bytes");
        assert!(
            persisted
                .windows(ACCESS.len())
                .any(|window| window == ACCESS.as_bytes())
        );
        assert_eq!(
            persisted
                .windows(REFRESH.len())
                .any(|window| window == REFRESH.as_bytes()),
            include_refresh
        );
        assert!(
            invoke(
                &mut vm,
                "exchange_selected_result",
                &[
                    request(r#"{"grant_type":"authorization_code"}"#, "/oauth/token"),
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
            )
            .is_err()
        );
        assert!(invoke(&mut vm, "save_result", &[save_request]).is_err());
        assert_eq!(transport.take_sent().len(), 0, "replay sends nothing");
        assert_eq!(
            AuthStore::from_home(&private_home.0)
                .expect("reopen native store")
                .load_metadata("fixture-codex")
                .expect("replay did not overwrite metadata")
                .generation,
            1
        );
        assert_eq!(vm.host_context().resource_count(), 2);
    }
}
