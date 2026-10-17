use rustscript_agent::{
    CancellationReason, RunCancellation,
    auth::{
        host::{AuthHost, auth_host_catalog},
        oauth::{
            BoundedHttpsTransport, OAuthError, OAuthHost, OAuthIoContext, PreparedHttpsRequest,
            RawHttpsResponse, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
            ScriptedHttpsTransport,
        },
        store::AuthStore,
    },
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, HostParamPassing, HostTypeSchema,
    ResourceTypeKey, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct CancelInsidePoll {
    transport: ScriptedHttpsTransport,
    cancellation: RunCancellation,
    sends: AtomicUsize,
}

impl CancelInsidePoll {
    fn new(cancellation: RunCancellation) -> Self {
        Self {
            transport: ScriptedHttpsTransport::new(),
            cancellation,
            sends: AtomicUsize::new(0),
        }
    }
}

impl BoundedHttpsTransport for CancelInsidePoll {
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        let response = self.transport.send(request, context)?;
        if self.sends.fetch_add(1, Ordering::AcqRel) == 1 {
            self.cancellation.request(CancellationReason::Requested);
            context.check()?;
        }
        Ok(response)
    }
}

fn fixture_home() -> PathBuf {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned temp"));
    let home = root.join(format!("oauth-device-red-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&home).expect("private fixture home");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
    fs::copy(fixture.join("config.yaml"), home.join("config.yaml")).expect("fixture config");
    let auth = fs::read_to_string(fixture.join("auth.yaml"))
        .expect("fixture auth")
        .replace("1788440000000", "1900000000000");
    fs::write(home.join("auth.yaml"), auth).expect("fixture auth copy");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        for name in ["config.yaml", "auth.yaml"] {
            fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                .expect("fixture mode");
        }
    }
    home
}

fn real_transport_vm(home: PathBuf, oauth: Arc<OAuthHost>) -> (Vm, AuthHost, Value) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/transport_contract.rss");
    let source = fs::read_to_string(&path).expect("existing real RSS transport entry");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile existing RSS transport entry");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let host = AuthHost::new(home, RunCancellation::with_timeout(Duration::from_secs(30)))
        .expect("synthetic auth host")
        .with_oauth_host(oauth);
    let mut registry = HostFunctionRegistry::restricted();
    host.register(&mut registry, catalog.as_ref())
        .expect("register exact catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind exact catalog");
    assert!(matches!(vm.run().expect("run RSS root"), VmStatus::Halted));
    let context = host.bind_vm(&mut vm).expect("bind synthetic owner");
    (vm, host, field(&context, "host_home").clone())
}

fn device_contract_vm(home: PathBuf, oauth: Arc<OAuthHost>) -> (Vm, AuthHost, Value) {
    device_contract_vm_with_cancellation(
        home,
        oauth,
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
}

fn device_contract_vm_with_cancellation(
    home: PathBuf,
    oauth: Arc<OAuthHost>,
    cancellation: RunCancellation,
) -> (Vm, AuthHost, Value) {
    const SAVE_PROBE: &str = r#"
pub fn save_slots(policy: resource<auth.policy>, access: resource<auth.secret_slot>, refresh: resource<auth.secret_slot>, expected: int) -> string {
    let saved = auth::save_if_generation({
        credential_id: "fixture-codex",
        expected_generation: expected,
        policy_handle: policy,
        metadata: {
            provider: "openai-codex", kind: "oauth", source: "synthetic-device-test",
            token_type: "Bearer", expires_at_ms: 1900000000000, scopes: [],
            account_id: "synthetic-device-account", generation: expected,
            status: "active", last_refresh_at_ms: 1790000000000, has_refresh_token: true
        },
        access_slot: access,
        refresh_action: "replace",
        refresh_slot: refresh
    });
    saved.outcome
}

pub fn save_access(policy: resource<auth.policy>, access: resource<auth.secret_slot>, expected: int) -> int {
    let saved = auth::save_if_generation({
        credential_id: "fixture-codex", expected_generation: expected, policy_handle: policy,
        metadata: {
            provider: "openai-codex", kind: "oauth", source: "synthetic-device-race",
            token_type: "Bearer", expires_at_ms: 1900000000000, scopes: [],
            account_id: "synthetic-device-account", generation: expected,
            status: "active", last_refresh_at_ms: 1790000000000, has_refresh_token: true
        },
        access_slot: access, refresh_action: "preserve"
    });
    saved.metadata.generation
}

pub fn direct_transport(request: TransportPublicRequest, usage: TransportCredentialUse) -> TransportResponseEnvelope {
    oauth::transport(&request, &usage)
}

pub fn issue_access(policy: resource<auth.policy>) -> resource<auth.access> {
    auth::access_handle("fixture-codex", 4, &policy).handle
}
"#;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/device_contract.rss");
    let mut source = fs::read_to_string(&path).expect("real typed device RSS");
    source.push_str(SAVE_PROBE);
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile typed device RSS against exact auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let host = AuthHost::new(home, cancellation)
        .expect("synthetic auth host")
        .with_oauth_host(oauth);
    let mut registry = HostFunctionRegistry::restricted();
    host.register(&mut registry, catalog.as_ref())
        .expect("register exact catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind exact catalog");
    assert!(matches!(vm.run().expect("run RSS root"), VmStatus::Halted));
    let context = host.bind_vm(&mut vm).expect("bind synthetic owner");
    (vm, host, field(&context, "host_home").clone())
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    let entry = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(entry, args).expect("RSS call")
}

fn text(value: &Value) -> Option<&str> {
    if let Value::String(value) = value {
        Some(value.as_ref())
    } else {
        None
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

#[test]
fn catalog_adds_exact_typed_device_fields_and_take_owned_close() {
    let catalog = auth_host_catalog();
    assert!(catalog.resources().iter().any(|resource| {
        resource.key == ResourceTypeKey::new("oauth.device_session").expect("key")
    }));
    let functions = catalog.functions();
    let transport = functions
        .iter()
        .find(|function| function.name == "oauth::transport")
        .expect("existing transport descriptor");
    assert_eq!(
        transport.params.len(),
        2,
        "legacy transport signature unchanged"
    );
    let HostTypeSchema::Named { name, fields } = &transport.params[1].ty else {
        panic!("credential-use is named");
    };
    assert_eq!(name, "TransportCredentialUse");
    for (field_name, resource_key) in [
        ("access_handle", "auth.access"),
        ("refresh_handle", "auth.refresh"),
        ("code_handle", "oauth.authorization_code"),
        ("verifier_handle", "oauth.verifier"),
        ("device_handle", "oauth.device_session"),
    ] {
        let field = fields
            .iter()
            .find(|field| field.name == field_name)
            .unwrap_or_else(|| panic!("missing {field_name}"));
        let HostTypeSchema::Optional(inner) = &field.ty else {
            panic!("{field_name} must remain optional");
        };
        assert_eq!(
            **inner,
            HostTypeSchema::Resource(ResourceTypeKey::new(resource_key).expect("key"))
        );
    }
    let HostTypeSchema::Named { fields, .. } = &transport.return_type else {
        panic!("transport response is named");
    };
    let device_field = fields
        .iter()
        .find(|field| field.name == "device_handle")
        .expect("additive response handle");
    let HostTypeSchema::Optional(inner) = &device_field.ty else {
        panic!("device response handle is optional");
    };
    assert_eq!(
        **inner,
        HostTypeSchema::Resource(ResourceTypeKey::new("oauth.device_session").expect("key"))
    );
    let close = functions
        .iter()
        .find(|function| function.name == "oauth::close_device")
        .expect("typed device close");
    assert_eq!(close.params.len(), 1);
    assert_eq!(close.params[0].passing, HostParamPassing::TakeOwned);
    assert_eq!(
        close.params[0].ty,
        HostTypeSchema::Resource(ResourceTypeKey::new("oauth.device_session").expect("key"))
    );
    assert_eq!(close.return_type, HostTypeSchema::Null);
}

fn transport_request(policy: Value, id: &str, path: &str, body: &str) -> Value {
    record(vec![
        ("policy_handle", policy),
        ("credential_id", Value::string(id)),
        ("method", Value::string("POST")),
        ("path", Value::string(path)),
        ("public_headers", Value::array(vec![])),
        ("public_body", Value::string(body)),
    ])
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected RSS record")
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name}"))
}

#[test]
fn real_rss_start_pending_poll_and_token_slots_save_with_frozen_generation() {
    const DEVICE_CODE: &str = "SYNTHETIC_DEVICE_CODE_9f21";
    const ACCESS: &str = "SYNTHETIC_DEVICE_ACCESS_3c72";
    const REFRESH: &str = "SYNTHETIC_DEVICE_REFRESH_4a18";
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        r#"{"device_code":"SYNTHETIC_DEVICE_CODE_9f21","user_code":"PUBLIC-USER-CODE","verification_uri":"https://verify.invalid"}"#,
    );
    transport.push_raw(
        200,
        r#"{"error":"authorization_pending","public":"pending"}"#,
    );
    transport.push_raw(
        200,
        r#"{"access_token":"SYNTHETIC_DEVICE_ACCESS_3c72","refresh_token":"SYNTHETIC_DEVICE_REFRESH_4a18","public":"authorized"}"#,
    );
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let home = fixture_home();
    let stored_home = home.clone();
    let (mut vm, _host, host_home) = device_contract_vm(home, oauth);
    let snapshot = invoke(&mut vm, "snapshot", &[host_home]);
    let policy = snapshot.clone();
    let id = Value::string("fixture-codex");

    let started = invoke(
        &mut vm,
        "start",
        &[
            policy.clone(),
            id.clone(),
            Value::string("/oauth/token"),
            Value::string("client_id=public-device-client"),
        ],
    );
    let device = field(&started, "device_handle").clone();
    assert!(
        matches!(device, Value::Int(_)),
        "typed opaque device resource"
    );
    let start_debug = format!("{started:?}");
    assert!(!start_debug.contains(DEVICE_CODE));
    assert!(
        text(field(&started, "body_without_secret_fields"))
            .is_some_and(|body| body.contains("PUBLIC-USER-CODE") && !body.contains(DEVICE_CODE))
    );
    assert_eq!(vm.host_context().resource_count(), 3);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host
            .fixture_live_oauth_flow_count()
            .expect("start flow count"),
        1
    );

    let poll_args = || {
        [
            policy.clone(),
            id.clone(),
            Value::string("/oauth/token"),
            Value::string("client_id=public-device-client"),
            device.clone(),
        ]
    };
    let pending = invoke(&mut vm, "poll", &poll_args());
    assert_eq!(field(&pending, "status"), &Value::Int(200));
    assert!(
        text(field(&pending, "body_without_secret_fields"))
            .is_some_and(|body| body.contains("pending"))
    );
    assert_eq!(
        vm.host_context().resource_count(),
        3,
        "pending resource retained"
    );
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host
            .fixture_live_oauth_flow_count()
            .expect("pending flow count"),
        1
    );

    let authorized = invoke(&mut vm, "poll", &poll_args());
    assert_eq!(field(&authorized, "status"), &Value::Int(200));
    let access = field(&authorized, "access_slot").clone();
    let refresh = field(&authorized, "refresh_slot").clone();
    assert!(matches!(access, Value::Int(_)) && matches!(refresh, Value::Int(_)));
    for secret in [DEVICE_CODE, ACCESS, REFRESH] {
        assert!(!format!("{started:?}{pending:?}{authorized:?}").contains(secret));
    }
    assert_eq!(
        vm.host_context().resource_count(),
        4,
        "device reclaimed, two slots issued"
    );
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host
            .fixture_live_oauth_flow_count()
            .expect("terminal flow count"),
        0
    );

    let replay = vm
        .resolve_exported_callable("poll")
        .expect("RSS poll export");
    let replay_failure = vm
        .invoke_callable(replay, &poll_args())
        .expect_err("terminal device alias cannot replay");
    assert!(!replay_failure.to_string().contains(DEVICE_CODE));

    let generation = invoke(
        &mut vm,
        "save_slots",
        &[policy, access, refresh, Value::Int(4)],
    );
    assert_eq!(generation, Value::string("committed"));
    let stored = AuthStore::from_home(&stored_home)
        .expect("fixture store")
        .load_metadata("fixture-codex")
        .expect("saved credential metadata");
    assert_eq!(stored.generation, 5);
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "only home and policy remain"
    );

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 3, "start plus two RSS-selected polls");
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].body, "client_id=public-device-client");
    for request in &sent[1..] {
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.body,
            format!("client_id=public-device-client&device_code={DEVICE_CODE}")
        );
    }
}

#[test]
fn frozen_device_generation_conflict_preserves_newer_store_and_closes_stale_slots() {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, r#"{"device_code":"SYNTHETIC_CAS_DEVICE_OLD"}"#);
    transport.push_raw(200, r#"{"device_code":"SYNTHETIC_CAS_DEVICE_UPDATE"}"#);
    transport.push_raw(200, r#"{"access_token":"SYNTHETIC_CAS_ACCESS_UPDATE"}"#);
    transport.push_raw(
        200,
        r#"{"access_token":"SYNTHETIC_CAS_ACCESS_STALE","refresh_token":"SYNTHETIC_CAS_REFRESH_STALE"}"#,
    );
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let home = fixture_home();
    let store_home = home.clone();
    let (mut vm, _host, host_home) = device_contract_vm(home, oauth);
    let policy = invoke(&mut vm, "snapshot", &[host_home]);
    let id = Value::string("fixture-codex");
    let first = invoke(
        &mut vm,
        "start",
        &[
            policy.clone(),
            id.clone(),
            Value::string("/oauth/token"),
            Value::string("client_id=cas-test"),
        ],
    );
    let second = invoke(
        &mut vm,
        "start",
        &[
            policy.clone(),
            id.clone(),
            Value::string("/oauth/token"),
            Value::string("client_id=cas-test"),
        ],
    );
    let updated = invoke(
        &mut vm,
        "poll",
        &[
            policy.clone(),
            id.clone(),
            Value::string("/oauth/token"),
            Value::string("client_id=cas-test"),
            field(&second, "device_handle").clone(),
        ],
    );
    let updated_generation = invoke(
        &mut vm,
        "save_access",
        &[
            policy.clone(),
            field(&updated, "access_slot").clone(),
            Value::Int(4),
        ],
    );
    assert_eq!(updated_generation, Value::Int(5));
    let stale = invoke(
        &mut vm,
        "poll",
        &[
            policy.clone(),
            id,
            Value::string("/oauth/token"),
            Value::string("client_id=cas-test"),
            field(&first, "device_handle").clone(),
        ],
    );
    assert!(matches!(field(&stale, "access_slot"), Value::Int(_)));
    assert!(matches!(field(&stale, "refresh_slot"), Value::Int(_)));
    assert_eq!(
        vm.host_context().resource_count(),
        4,
        "device closed, stale slots resident"
    );
    let outcome = vm
        .invoke_callable(
            vm.resolve_exported_callable("save_slots")
                .expect("RSS CAS save"),
            &[
                policy,
                field(&stale, "access_slot").clone(),
                field(&stale, "refresh_slot").clone(),
                Value::Int(4),
            ],
        )
        .expect("CAS returns current outcome");
    assert_eq!(
        outcome,
        Value::string("adopted"),
        "frozen generation cannot commit stale slots"
    );
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "both terminal slots closed"
    );
    assert_eq!(
        AuthStore::from_home(&store_home)
            .expect("fixture store")
            .load_metadata("fixture-codex")
            .expect("newer metadata")
            .generation,
        5,
        "stale generation must not overwrite newer state"
    );
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host
            .fixture_live_oauth_flow_count()
            .expect("native sessions"),
        0
    );
    assert_eq!(transport.take_sent().len(), 4);
}

#[test]
fn explicit_close_invalidates_alias_and_reclaims_both_resource_and_native_flow() {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, r#"{"device_code":"SYNTHETIC_CLOSE_DEVICE"}"#);
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let (mut vm, _host, host_home) = device_contract_vm(fixture_home(), oauth);
    let policy = invoke(&mut vm, "snapshot", &[host_home]);
    let started = invoke(
        &mut vm,
        "start",
        &[
            policy.clone(),
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string("client_id=close-test"),
        ],
    );
    let device = field(&started, "device_handle").clone();
    let alias = device.clone();
    assert_eq!(vm.host_context().resource_count(), 3);
    assert_eq!(invoke(&mut vm, "close", &[device]), Value::Null);
    assert_eq!(vm.host_context().resource_count(), 2);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host
            .fixture_live_oauth_flow_count()
            .expect("closed flow count"),
        0
    );
    let failure = vm
        .invoke_callable(
            vm.resolve_exported_callable("poll").expect("poll export"),
            &[
                policy,
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string("client_id=close-test"),
                alias.clone(),
            ],
        )
        .expect_err("closed alias is invalid");
    assert!(!failure.to_string().contains("SYNTHETIC_CLOSE_DEVICE"));
    assert_eq!(transport.take_sent().len(), 1, "alias replay sends nothing");
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn foreign_arena_policy_and_device_handles_fail_without_reclaiming_either_owner() {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, r#"{"device_code":"SYNTHETIC_FOREIGN_DEVICE_A"}"#);
    transport.push_raw(200, r#"{"device_code":"SYNTHETIC_FOREIGN_DEVICE_B"}"#);
    transport.push_raw(200, r#"{"error":"authorization_pending"}"#);
    transport.push_raw(200, r#"{"error":"authorization_pending"}"#);
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let (mut vm_a, _host_a, home_a) = device_contract_vm(fixture_home(), oauth.clone());
    let (mut vm_b, _host_b, home_b) = device_contract_vm(fixture_home(), oauth);
    let policy_a = invoke(&mut vm_a, "snapshot", &[home_a]);
    let policy_b = invoke(&mut vm_b, "snapshot", &[home_b]);
    let start = |vm: &mut Vm, policy: Value, client: &str| {
        invoke(
            vm,
            "start",
            &[
                policy,
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string(client),
            ],
        )
    };
    let first = start(&mut vm_a, policy_a.clone(), "client_id=foreign-a");
    let second = start(&mut vm_b, policy_b.clone(), "client_id=foreign-b");
    let device_a = field(&first, "device_handle").clone();
    let device_b = field(&second, "device_handle").clone();
    let poll_a = vm_a.resolve_exported_callable("poll").expect("poll export");
    let foreign_device = vm_a
        .invoke_callable(
            poll_a.clone(),
            &[
                policy_a.clone(),
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string("client_id=foreign-a"),
                device_b.clone(),
            ],
        )
        .expect_err("foreign arena device is rejected");
    assert!(
        foreign_device
            .to_string()
            .contains("resource_handle_wrong_table"),
        "{foreign_device}"
    );
    let foreign_policy = vm_a
        .invoke_callable(
            poll_a,
            &[
                policy_b.clone(),
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string("client_id=foreign-a"),
                device_a.clone(),
            ],
        )
        .expect_err("foreign arena policy is rejected");
    assert!(
        foreign_policy
            .to_string()
            .contains("resource_handle_wrong_table"),
        "{foreign_policy}"
    );
    assert_eq!(vm_a.host_context().resource_count(), 3);
    assert_eq!(vm_b.host_context().resource_count(), 3);
    assert_eq!(
        transport.take_sent().len(),
        2,
        "cross-arena denials never send"
    );
    #[cfg(feature = "config-fixture")]
    {
        assert_eq!(_host_a.fixture_live_oauth_flow_count().expect("flows"), 2);
        assert_eq!(
            _host_b
                .fixture_live_oauth_flow_count()
                .expect("shared native host"),
            2
        );
    }
    let valid_a = invoke(
        &mut vm_a,
        "poll",
        &[
            policy_a,
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string("client_id=foreign-a"),
            device_a,
        ],
    );
    let valid_b = invoke(
        &mut vm_b,
        "poll",
        &[
            policy_b,
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string("client_id=foreign-b"),
            device_b,
        ],
    );
    assert_eq!(field(&valid_a, "status"), &Value::Int(200));
    assert_eq!(field(&valid_b, "status"), &Value::Int(200));
    assert_eq!(transport.take_sent().len(), 2);
}

#[test]
fn cancellation_during_send_reclaims_device_flow_and_resource() {
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let transport = Arc::new(CancelInsidePoll::new(cancellation.clone()));
    transport
        .transport
        .push_raw(200, r#"{"device_code":"SYNTHETIC_CANCEL_DURING_SEND"}"#);
    transport
        .transport
        .push_raw(200, r#"{"error":"authorization_pending"}"#);
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let (mut vm, _host, host_home) =
        device_contract_vm_with_cancellation(fixture_home(), oauth, cancellation);
    let policy = invoke(&mut vm, "snapshot", &[host_home]);
    let started = invoke(
        &mut vm,
        "start",
        &[
            policy.clone(),
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string("client_id=cancel-test"),
        ],
    );
    let failure = vm
        .invoke_callable(
            vm.resolve_exported_callable("poll").expect("poll export"),
            &[
                policy,
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string("client_id=cancel-test"),
                field(&started, "device_handle").clone(),
            ],
        )
        .expect_err("owner cancellation during in-flight send");
    assert!(failure.to_string().contains("policy_inactive"), "{failure}");
    assert_eq!(
        transport.transport.take_sent().len(),
        2,
        "poll entered native transport"
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host
            .fixture_live_oauth_flow_count()
            .expect("cancelled flow"),
        0
    );
}

#[test]
fn cancelling_one_owner_preserves_shared_host_session_for_another_owner() {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, r#"{"device_code":"SYNTHETIC_OWNER_A"}"#);
    transport.push_raw(200, r#"{"device_code":"SYNTHETIC_OWNER_B"}"#);
    transport.push_raw(200, r#"{"error":"authorization_pending"}"#);
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let cancel_a = RunCancellation::with_timeout(Duration::from_secs(30));
    let cancel_b = RunCancellation::with_timeout(Duration::from_secs(30));
    let (mut vm_a, _host_a, home_a) =
        device_contract_vm_with_cancellation(fixture_home(), oauth.clone(), cancel_a.clone());
    let (mut vm_b, _host_b, home_b) =
        device_contract_vm_with_cancellation(fixture_home(), oauth, cancel_b);
    let policy_a = invoke(&mut vm_a, "snapshot", &[home_a]);
    let policy_b = invoke(&mut vm_b, "snapshot", &[home_b]);
    let started_a = invoke(
        &mut vm_a,
        "start",
        &[
            policy_a.clone(),
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string("client_id=owner-a"),
        ],
    );
    let started_b = invoke(
        &mut vm_b,
        "start",
        &[
            policy_b.clone(),
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string("client_id=owner-b"),
        ],
    );
    cancel_a.request(CancellationReason::Requested);
    let cancelled = vm_a
        .invoke_callable(
            vm_a.resolve_exported_callable("poll").expect("poll export"),
            &[
                policy_a,
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string("client_id=owner-a"),
                field(&started_a, "device_handle").clone(),
            ],
        )
        .expect_err("inactive owner poll is rejected");
    assert!(cancelled.to_string().contains("policy_inactive"));
    assert_eq!(vm_a.host_context().resource_count(), 2);
    assert_eq!(vm_b.host_context().resource_count(), 3);
    #[cfg(feature = "config-fixture")]
    {
        assert_eq!(
            _host_a
                .fixture_live_oauth_flow_count()
                .expect("shared flows"),
            1
        );
        assert_eq!(
            _host_b
                .fixture_live_oauth_flow_count()
                .expect("shared flows"),
            1
        );
    }
    let pending_b = invoke(
        &mut vm_b,
        "poll",
        &[
            policy_b,
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string("client_id=owner-b"),
            field(&started_b, "device_handle").clone(),
        ],
    );
    assert_eq!(field(&pending_b, "status"), &Value::Int(200));
    assert_eq!(vm_b.host_context().resource_count(), 3);
    assert_eq!(transport.take_sent().len(), 3);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host_b
            .fixture_live_oauth_flow_count()
            .expect("unrelated flow remains"),
        1
    );
}

#[test]
fn inactive_owner_cleanup_accepts_only_exact_device_usage() {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, r#"{"device_code":"SYNTHETIC_INACTIVE_DEVICE_A"}"#);
    transport.push_raw(200, r#"{"device_code":"SYNTHETIC_INACTIVE_DEVICE_B"}"#);
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let (mut vm, _host, home) =
        device_contract_vm_with_cancellation(fixture_home(), oauth, cancellation.clone());
    let policy = invoke(&mut vm, "snapshot", &[home]);
    let mut start = |client: &str| {
        invoke(
            &mut vm,
            "start",
            &[
                policy.clone(),
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string(client),
            ],
        )
    };
    let first = start("client_id=inactive-a");
    let second = start("client_id=inactive-b");
    let device_a = field(&first, "device_handle").clone();
    let device_b = field(&second, "device_handle").clone();
    cancellation.request(CancellationReason::Requested);
    let direct = vm
        .resolve_exported_callable("direct_transport")
        .expect("direct probe");
    let request_a = transport_request(
        policy.clone(),
        "fixture-codex",
        "/oauth/token",
        "client_id=inactive-a",
    );
    let mixed = record(vec![
        ("kind", Value::string("none")),
        ("device_handle", device_a.clone()),
    ]);
    let failure = vm
        .invoke_callable(direct.clone(), &[request_a.clone(), mixed])
        .expect_err("inactive mixed usage is rejected");
    assert!(failure.to_string().contains("policy_inactive"), "{failure}");
    assert_eq!(
        vm.host_context().resource_count(),
        4,
        "mixed family is not reclaimed"
    );
    let valid = record(vec![
        ("kind", Value::string("device_session")),
        ("device_handle", device_a),
    ]);
    let failure = vm
        .invoke_callable(direct, &[request_a, valid])
        .expect_err("inactive exact device use preserves original owner error");
    assert!(failure.to_string().contains("policy_inactive"), "{failure}");
    assert_eq!(
        vm.host_context().resource_count(),
        3,
        "only submitted device reclaimed"
    );
    let closed = vm
        .invoke_callable(
            vm.resolve_exported_callable("close")
                .expect("RSS close export"),
            &[device_b],
        )
        .expect_err("close reclaims resource before inactive-owner error");
    assert!(closed.to_string().contains("policy_inactive"), "{closed}");
    assert_eq!(vm.host_context().resource_count(), 2);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host
            .fixture_live_oauth_flow_count()
            .expect("all flows closed"),
        0
    );
    assert_eq!(transport.take_sent().len(), 2);
}

#[test]
fn local_request_corrections_preserve_the_active_device_session() {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, r#"{"device_code":"SYNTHETIC_RETRY_DEVICE"}"#);
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let (mut vm, _host, host_home) = device_contract_vm(fixture_home(), oauth);
    let policy = invoke(&mut vm, "snapshot", &[host_home]);
    let started = invoke(
        &mut vm,
        "start",
        &[
            policy.clone(),
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string("client_id=retry-test"),
        ],
    );
    let device = field(&started, "device_handle").clone();
    let poll = vm.resolve_exported_callable("poll").expect("poll export");
    let args = |id: &str, path: &str, body: &str| {
        [
            policy.clone(),
            Value::string(id),
            Value::string(path),
            Value::string(body),
            device.clone(),
        ]
    };
    let denied_path = vm
        .invoke_callable(
            poll.clone(),
            &args("fixture-codex", "/not-admitted", "client_id=x"),
        )
        .expect_err("path denied before send");
    assert!(denied_path.to_string().contains("path_denied"));
    let denied_body = vm
        .invoke_callable(
            poll.clone(),
            &args("fixture-codex", "/oauth/token", "device_code=caller"),
        )
        .expect_err("host-owned form key denied");
    assert!(denied_body.to_string().contains("invalid_intent"));
    let denied_id = vm
        .invoke_callable(
            poll.clone(),
            &args("unadmitted", "/oauth/token", "client_id=x"),
        )
        .expect_err("unadmitted credential denied");
    assert!(denied_id.to_string().contains("credential_not_admitted"));
    assert_eq!(vm.host_context().resource_count(), 3);
    assert_eq!(transport.take_sent().len(), 1, "local denials do not send");
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host
            .fixture_live_oauth_flow_count()
            .expect("still-live flow"),
        1
    );

    transport.push_raw(200, r#"{"error":"authorization_pending"}"#);
    let retried = invoke(
        &mut vm,
        "poll",
        &args("fixture-codex", "/oauth/token", "client_id=x"),
    );
    assert_eq!(field(&retried, "status"), &Value::Int(200));
    assert_eq!(vm.host_context().resource_count(), 3);
    assert_eq!(
        transport.take_sent().len(),
        1,
        "corrected request reaches transport"
    );
}

#[test]
fn unknown_and_mixed_device_usage_do_not_consume_a_valid_sibling() {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, r#"{"device_code":"SYNTHETIC_SHAPE_DEVICE"}"#);
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let (mut vm, _host, host_home) = device_contract_vm(fixture_home(), oauth);
    let policy = invoke(&mut vm, "snapshot", &[host_home]);
    let started = invoke(
        &mut vm,
        "start",
        &[
            policy.clone(),
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string("client_id=shape-test"),
        ],
    );
    let device = field(&started, "device_handle").clone();
    assert_eq!(transport.take_sent().len(), 1, "device start sent once");
    let request = transport_request(
        policy.clone(),
        "fixture-codex",
        "/oauth/token",
        "client_id=shape-test",
    );
    let direct = vm
        .resolve_exported_callable("direct_transport")
        .expect("typed direct probe");
    let malformed = [
        (
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device.clone()),
                ("unexpected", Value::Bool(true)),
            ]),
            "credential_use_unsupported",
        ),
        (
            record(vec![
                ("kind", Value::string("none")),
                ("device_handle", device.clone()),
            ]),
            "credential_use_unsupported",
        ),
        (
            record(vec![
                ("kind", Value::string("device_session")),
                ("device_handle", device.clone()),
                ("access_handle", device.clone()),
            ]),
            "resource_type_key_mismatch",
        ),
    ];
    for (case_index, (usage, expected_error)) in malformed.into_iter().enumerate() {
        let failure = vm
            .invoke_callable(direct.clone(), &[request.clone(), usage])
            .expect_err("invalid or mixed usage rejected");
        assert!(
            failure.to_string().contains(expected_error),
            "case {case_index}: {failure}"
        );
        assert!(!failure.to_string().contains("SYNTHETIC_SHAPE_DEVICE"));
        assert_eq!(vm.host_context().resource_count(), 3);
        assert_eq!(
            transport.take_sent().len(),
            0,
            "malformed usage case {case_index} must not send"
        );
    }
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host
            .fixture_live_oauth_flow_count()
            .expect("preserved flow"),
        1
    );
    transport.push_raw(200, r#"{"error":"authorization_pending"}"#);
    let pending = invoke(
        &mut vm,
        "poll",
        &[
            policy,
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string("client_id=shape-test"),
            device,
        ],
    );
    assert_eq!(field(&pending, "status"), &Value::Int(200));
    assert_eq!(transport.take_sent().len(), 1);
}

#[test]
fn post_send_error_malformed_and_oversized_response_reclaim_device_resources() {
    const DEVICE_CODE: &str = "SYNTHETIC_POST_SEND_DEVICE";
    const RESPONSE_SECRET: &str = "SYNTHETIC_POST_SEND_SECRET";
    for scenario in [
        "transport_error",
        "malformed_response",
        "response_too_large",
    ] {
        let transport = Arc::new(ScriptedHttpsTransport::new());
        transport.push_raw(200, r#"{"device_code":"SYNTHETIC_POST_SEND_DEVICE"}"#);
        match scenario {
            "transport_error" => {}
            "malformed_response" => transport.push_raw(200, "not-json-SYNTHETIC_POST_SEND_SECRET"),
            "response_too_large" => transport.push_raw(200, &"X".repeat(64 * 1024 + 1)),
            _ => unreachable!(),
        }
        let oauth = Arc::new(OAuthHost::new(
            transport.clone(),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(1_900_000_000_000)),
            Arc::new(ScriptedCancel::new()),
        ));
        let (mut vm, _host, host_home) = device_contract_vm(fixture_home(), oauth);
        let policy = invoke(&mut vm, "snapshot", &[host_home]);
        let started = invoke(
            &mut vm,
            "start",
            &[
                policy.clone(),
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string("client_id=error-test"),
            ],
        );
        let device = field(&started, "device_handle").clone();
        let poll = vm.resolve_exported_callable("poll").expect("poll export");
        let failure = vm
            .invoke_callable(
                poll.clone(),
                &[
                    policy.clone(),
                    Value::string("fixture-codex"),
                    Value::string("/oauth/token"),
                    Value::string("client_id=error-test"),
                    device.clone(),
                ],
            )
            .expect_err("post-send failure");
        assert!(
            failure.to_string().contains(scenario),
            "{scenario}: {failure}"
        );
        assert!(!failure.to_string().contains(DEVICE_CODE));
        assert!(!failure.to_string().contains(RESPONSE_SECRET));
        assert_eq!(
            vm.host_context().resource_count(),
            2,
            "device Core entry closed"
        );
        #[cfg(feature = "config-fixture")]
        assert_eq!(
            _host
                .fixture_live_oauth_flow_count()
                .expect("native cleanup"),
            0
        );
        let replay = vm.invoke_callable(
            poll,
            &[
                policy,
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string("client_id=error-test"),
                device,
            ],
        );
        assert!(replay.is_err(), "{scenario}: terminal alias rejected");
        assert_eq!(
            transport.take_sent().len(),
            2,
            "no replay send for {scenario}"
        );
        assert_eq!(vm.host_context().resource_count(), 2);
    }
}

#[test]
fn expired_device_flow_reclaims_native_and_core_resource_before_poll() {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, r#"{"device_code":"SYNTHETIC_EXPIRED_DEVICE"}"#);
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        clock.clone(),
        Arc::new(ScriptedCancel::new()),
    ));
    let (mut vm, _host, host_home) = device_contract_vm(fixture_home(), oauth);
    let policy = invoke(&mut vm, "snapshot", &[host_home]);
    let started = invoke(
        &mut vm,
        "start",
        &[
            policy.clone(),
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string("client_id=expiry-test"),
        ],
    );
    let device = field(&started, "device_handle").clone();
    clock.expire();
    let failure = vm
        .invoke_callable(
            vm.resolve_exported_callable("poll").expect("poll export"),
            &[
                policy,
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string("client_id=expiry-test"),
                device,
            ],
        )
        .expect_err("expired session is rejected");
    assert!(
        failure.to_string().contains("resource_invalid"),
        "{failure}"
    );
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "expired Core alias reclaimed"
    );
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host
            .fixture_live_oauth_flow_count()
            .expect("expired native flow"),
        0
    );
    assert_eq!(
        transport.take_sent().len(),
        1,
        "expired session sends nothing"
    );
}

#[test]
fn expired_inactive_device_session_reclaims_core_resource_during_owner_cleanup() {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        r#"{"device_code":"SYNTHETIC_EXPIRED_INACTIVE_DEVICE"}"#,
    );
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        clock.clone(),
        Arc::new(ScriptedCancel::new()),
    ));
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let (mut vm, _host, home) =
        device_contract_vm_with_cancellation(fixture_home(), oauth, cancellation.clone());
    let policy = invoke(&mut vm, "snapshot", &[home]);
    let started = invoke(
        &mut vm,
        "start",
        &[
            policy.clone(),
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string("client_id=expiry-cleanup"),
        ],
    );
    let device = field(&started, "device_handle").clone();
    clock.expire();
    cancellation.request(CancellationReason::Requested);
    let failure = vm
        .invoke_callable(
            vm.resolve_exported_callable("poll").expect("poll export"),
            &[
                policy,
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string("client_id=expiry-cleanup"),
                device,
            ],
        )
        .expect_err("inactive owner rejects expired session");
    assert!(failure.to_string().contains("policy_inactive"), "{failure}");
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "expired alias reclaimed"
    );
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host
            .fixture_live_oauth_flow_count()
            .expect("expired flow swept"),
        0
    );
    assert_eq!(
        transport.take_sent().len(),
        1,
        "inactive owner sends nothing"
    );
}

#[test]
fn replacement_device_response_rejects_and_revokes_both_native_sessions() {
    const FIRST: &str = "SYNTHETIC_REPLACEMENT_DEVICE_FIRST";
    const NEXT: &str = "SYNTHETIC_REPLACEMENT_DEVICE_NEXT";
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        r#"{"device_code":"SYNTHETIC_REPLACEMENT_DEVICE_FIRST"}"#,
    );
    transport.push_raw(
        200,
        r#"{"device_code":"SYNTHETIC_REPLACEMENT_DEVICE_NEXT"}"#,
    );
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let (mut vm, _host, home) = device_contract_vm(fixture_home(), oauth);
    let policy = invoke(&mut vm, "snapshot", &[home]);
    let started = invoke(
        &mut vm,
        "start",
        &[
            policy.clone(),
            Value::string("fixture-codex"),
            Value::string("/oauth/token"),
            Value::string("client_id=replacement"),
        ],
    );
    let device = field(&started, "device_handle").clone();
    let failure = vm
        .invoke_callable(
            vm.resolve_exported_callable("poll").expect("RSS poll"),
            &[
                policy,
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string("client_id=replacement"),
                device,
            ],
        )
        .expect_err("replacement device handle is not supported");
    assert!(
        failure.to_string().contains("response_handle_unsupported"),
        "{failure}"
    );
    assert!(!failure.to_string().contains(FIRST));
    assert!(!failure.to_string().contains(NEXT));
    assert_eq!(vm.host_context().resource_count(), 2);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host
            .fixture_live_oauth_flow_count()
            .expect("replacement cleanup"),
        0
    );
    assert_eq!(transport.take_sent().len(), 2);
}

#[test]
fn issued_alias_quota_failure_rolls_back_slots_device_and_native_flow() {
    const DEVICE_CODE: &str = "SYNTHETIC_QUOTA_DEVICE";
    const ACCESS: &str = "SYNTHETIC_QUOTA_ACCESS";
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        r#"{"device_code":"SYNTHETIC_QUOTA_DEVICE","access_token":"SYNTHETIC_QUOTA_ACCESS"}"#,
    );
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let (mut vm, _host, host_home) = device_contract_vm(fixture_home(), oauth);
    let policy = invoke(&mut vm, "snapshot", &[host_home]);
    for _ in 0..61 {
        let _ = invoke(&mut vm, "issue_access", std::slice::from_ref(&policy));
    }
    assert_eq!(vm.host_context().resource_count(), 63);
    let failure = vm
        .invoke_callable(
            vm.resolve_exported_callable("start").expect("RSS start"),
            &[
                policy,
                Value::string("fixture-codex"),
                Value::string("/oauth/token"),
                Value::string("client_id=quota-test"),
            ],
        )
        .expect_err("device resource exceeds remaining arena quota");
    assert!(failure.to_string().contains("resource_limit"), "{failure}");
    assert!(!failure.to_string().contains(DEVICE_CODE));
    assert!(!failure.to_string().contains(ACCESS));
    assert_eq!(
        vm.host_context().resource_count(),
        63,
        "partially issued slot closed"
    );
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        _host
            .fixture_live_oauth_flow_count()
            .expect("native rollback"),
        0
    );
    assert_eq!(transport.take_sent().len(), 1);
}

#[test]
fn existing_real_rss_transport_accepts_a_typed_device_session_response() {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(
        200,
        r#"{"device_code":"SYNTHETIC_DEVICE_CODE_9f21","user_code":"PUBLIC-USER-CODE","verification_uri":"https://verify.invalid"}"#,
    );
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let (mut vm, _host, home) = real_transport_vm(fixture_home(), oauth);
    let run = vm.resolve_exported_callable("run").expect("RSS run export");
    let outcome = vm.invoke_callable(run, &[home]);
    assert!(
        outcome.is_ok(),
        "device-session response was rejected: {}",
        outcome
            .err()
            .map_or_else(|| "unknown".to_string(), |e| e.to_string())
    );
}
