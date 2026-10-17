use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "config-fixture")]
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Instant,
};

#[cfg(feature = "config-fixture")]
use rustscript_agent::CancellationReason;
#[cfg(feature = "config-fixture")]
use rustscript_agent::auth::oauth::{
    BoundedHttpsTransport, OAuthCancel, OAuthError, OAuthIoContext, PreparedHttpsRequest,
    RawHttpsResponse,
};

#[cfg(feature = "config-fixture")]
use rustscript_agent::auth::oauth::{
    OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
    ScriptedHttpsTransport,
};
use rustscript_agent::{
    RunCancellation,
    auth::host::{AuthHost, auth_host_catalog},
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, HostParamPassing, HostTypeSchema,
    ResourceTypeKey, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};

#[cfg(feature = "config-fixture")]
const CALLBACK_CODE: &str = "FIXTURE_CALLBACK_AUTH_CODE_9cfd";
#[cfg(feature = "config-fixture")]
const NEXT_ACCESS: &str = "SYNTHETIC_CODE_EXCHANGE_ACCESS";
#[cfg(feature = "config-fixture")]
const NEXT_REFRESH: &str = "SYNTHETIC_CODE_EXCHANGE_REFRESH";

struct TempHome(PathBuf);

impl TempHome {
    fn new(label: &str) -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned temp"));
        let path = root.join(format!(
            "oauth-code-exchange-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create private home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml")).expect("copy config");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read synthetic auth fixture")
            .replace("1788440000000", "1900000000000");
        fs::write(path.join("auth.yaml"), auth).expect("copy auth");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                    .expect("file mode");
            }
        }
        Self(path)
    }

    #[cfg(feature = "config-fixture")]
    fn admit_second_credential(&self) {
        let config_path = self.0.join("config.yaml");
        let config = fs::read_to_string(&config_path).expect("read test config");
        let block_start = config.find("  openai-codex:\n").expect("fixture provider");
        let block_end = config[block_start..]
            .find("workspaces:\n")
            .expect("workspace boundary")
            + block_start;
        let second_provider = config[block_start..block_end]
            .replace("openai-codex", "synthetic-codex-two")
            .replace("fixture-codex", "fixture-codex-two");
        let mut config = config;
        config.insert_str(block_end, &second_provider);
        fs::write(config_path, config).expect("write isolated second provider");

        let mut auth = fs::read_to_string(self.0.join("auth.yaml")).expect("read test auth");
        let credential_start = auth.find("  fixture-codex:\n").expect("fixture credential");
        let second_credential =
            auth[credential_start..].replace("fixture-codex", "fixture-codex-two");
        auth.push_str(&second_credential);
        fs::write(self.0.join("auth.yaml"), auth).expect("write isolated second credential");
    }
}

impl AsRef<Path> for TempHome {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn compile_vm(auth: &AuthHost) -> Vm {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/code_exchange_contract.rss");
    let source = fs::read_to_string(&path).expect("real code exchange RSS");
    compile_vm_source(auth, &path, &source)
}

fn compile_vm_source(auth: &AuthHost, path: &Path, source: &str) -> Vm {
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        path,
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile RSS against exact auth host catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog.as_ref())
        .expect("register exact catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted registry");
    assert!(matches!(vm.run().expect("run RSS root"), VmStatus::Halted));
    vm
}

#[cfg(feature = "config-fixture")]
const TEST_TRANSPORT_PROBES: &str = r#"
pub fn test_direct_transport(request: TransportPublicRequest, usage: TransportCredentialUse) -> TransportResponseEnvelope {
    oauth::transport(&request, &usage)
}

pub fn test_access_handle(policy: resource<auth.policy>) -> resource<auth.access> {
    auth::access_handle("fixture-codex", 4, &policy).handle
}

pub fn test_close_access(handle: resource<auth.access>) -> null {
    auth::close_access(handle)
}
"#;

#[cfg(feature = "config-fixture")]
fn compile_vm_with_probes(auth: &AuthHost) -> Vm {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/code_exchange_contract.rss");
    let mut source = fs::read_to_string(&path).expect("real code exchange RSS");
    source.push_str(TEST_TRANSPORT_PROBES);
    compile_vm_source(auth, &path, &source)
}

#[test]
fn catalog_keeps_transport_pair_optional_nominal_and_borrowed() {
    let catalog = auth_host_catalog();
    let transport = catalog
        .functions()
        .iter()
        .find(|function| function.name == "oauth::transport")
        .expect("canonical transport function");
    assert_eq!(transport.params.len(), 2);
    assert_eq!(transport.params[0].passing, HostParamPassing::Borrow);
    assert_eq!(transport.params[1].name, "credential_use");
    assert_eq!(transport.params[1].passing, HostParamPassing::Borrow);
    let HostTypeSchema::Named { name, fields } = &transport.params[1].ty else {
        panic!("credential use remains a named host struct");
    };
    assert_eq!(name, "TransportCredentialUse");
    for (field_name, resource_key) in [
        ("access_handle", "auth.access"),
        ("refresh_handle", "auth.refresh"),
        ("code_handle", "oauth.authorization_code"),
        ("verifier_handle", "oauth.verifier"),
    ] {
        let field = fields
            .iter()
            .find(|field| field.name == field_name)
            .unwrap_or_else(|| panic!("missing credential-use field {field_name}"));
        let HostTypeSchema::Optional(inner) = &field.ty else {
            panic!("credential-use field {field_name} must remain optional");
        };
        assert_eq!(
            **inner,
            HostTypeSchema::Resource(ResourceTypeKey::new(resource_key).expect("resource key"))
        );
    }
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected named value");
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

fn call(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    let entry = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(entry, args).expect("RSS call")
}

fn public_intent() -> Value {
    public_intent_for("fixture-codex")
}

fn public_intent_for(credential_id: &str) -> Value {
    record(vec![
        ("credential_id", Value::string(credential_id)),
        ("path", Value::string("/codex/device")),
        ("flow", Value::string("authorization_code_pkce")),
        ("callback_mode", Value::string("manual")),
        (
            "scopes",
            Value::array(vec![Value::string("scope.synthetic")]),
        ),
        (
            "public_query",
            Value::array(vec![
                record(vec![
                    ("name", Value::string("client_id")),
                    ("value", Value::string("public-client-id")),
                ]),
                record(vec![
                    ("name", Value::string("response_type")),
                    ("value", Value::string("code")),
                ]),
            ]),
        ),
    ])
}

#[cfg(feature = "config-fixture")]
fn public_request(policy: Value, path: &str, public_body: &str) -> Value {
    public_request_for("fixture-codex", policy, path, public_body)
}

#[cfg(feature = "config-fixture")]
fn public_request_for(credential_id: &str, policy: Value, path: &str, public_body: &str) -> Value {
    record(vec![
        ("policy_handle", policy),
        ("credential_id", Value::string(credential_id)),
        ("method", Value::string("POST")),
        ("path", Value::string(path)),
        ("public_headers", Value::array(vec![])),
        ("public_body", Value::string(public_body)),
    ])
}

#[cfg(feature = "config-fixture")]
fn ready_exchange(auth: &AuthHost, vm: &mut Vm) -> (Value, Value, Value, Value) {
    let (policy, _, request, code, verifier) = ready_exchange_with_callback(auth, vm);
    (policy, request, code, verifier)
}

#[cfg(feature = "config-fixture")]
fn ready_exchange_with_callback(
    auth: &AuthHost,
    vm: &mut Vm,
) -> (Value, Value, Value, Value, Value) {
    let bound = auth.bind_vm(vm).expect("bind owner");
    let snapshot = call(vm, "snapshot", &[field(&bound, "host_home")]);
    let policy = field(&snapshot, "policy_handle");
    let (callback, request, code, verifier) = ready_pair(auth, vm, policy.clone());
    (policy, callback, request, code, verifier)
}

#[cfg(feature = "config-fixture")]
fn ready_pair(auth: &AuthHost, vm: &mut Vm, policy: Value) -> (Value, Value, Value, Value) {
    ready_pair_for(auth, vm, policy, "fixture-codex")
}

#[cfg(feature = "config-fixture")]
fn ready_pair_for(
    auth: &AuthHost,
    vm: &mut Vm,
    policy: Value,
    credential_id: &str,
) -> (Value, Value, Value, Value) {
    let begun = call(
        vm,
        "begin",
        &[policy.clone(), public_intent_for(credential_id)],
    );
    let callback = field(&begun, "callback_handle");
    let verifier = field(&begun, "verifier_handle");
    auth.fixture_inject_matching_callback(vm, &callback, CALLBACK_CODE)
        .expect("host-injected matching callback");
    let waited = call(vm, "wait", std::slice::from_ref(&callback));
    let code = field(&waited, "code_handle");
    let request = public_request_for(
        credential_id,
        policy,
        "/oauth/token",
        "client_id=caller-selected",
    );
    (callback, request, code, verifier)
}

#[cfg(feature = "config-fixture")]
fn scripted_auth(home: &TempHome, transport: Arc<ScriptedHttpsTransport>) -> AuthHost {
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(oauth)
    .with_oauth_callback_fixture()
}

#[cfg(feature = "config-fixture")]
fn fixture_auth_with_oauth(
    home: &TempHome,
    cancellation: RunCancellation,
    oauth: Arc<OAuthHost>,
) -> Arc<AuthHost> {
    Arc::new(
        AuthHost::new(home.0.clone(), cancellation)
            .expect("auth host")
            .with_oauth_host(oauth)
            .with_oauth_callback_fixture(),
    )
}

#[cfg(feature = "config-fixture")]
struct OwnerScopedTransport {
    entered: mpsc::Sender<usize>,
    calls: AtomicUsize,
    rescue_after: Duration,
}

#[cfg(feature = "config-fixture")]
impl OwnerScopedTransport {
    fn response() -> RawHttpsResponse {
        RawHttpsResponse {
            status: 200,
            headers: std::collections::BTreeMap::from([(
                "content-type".to_string(),
                "application/json".to_string(),
            )]),
            body: br#"{"public":"accepted"}"#.to_vec(),
        }
    }
}

#[cfg(feature = "config-fixture")]
impl BoundedHttpsTransport for OwnerScopedTransport {
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel);
        if request.body.contains("allow_success") {
            context.check()?;
            return Ok(Self::response());
        }
        let _ = self.entered.send(call);
        let rescue_deadline = Instant::now() + self.rescue_after;
        loop {
            context.check()?;
            if Instant::now() >= rescue_deadline {
                return Err(OAuthError::Transport {
                    message: "fixture independent wall-time rescue".to_string(),
                });
            }
            thread::yield_now();
        }
    }
}

#[cfg(feature = "config-fixture")]
struct CancelOnResponseTransport {
    cancellation: RunCancellation,
    calls: AtomicUsize,
}

#[cfg(feature = "config-fixture")]
impl BoundedHttpsTransport for CancelOnResponseTransport {
    fn send(
        &self,
        _request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        context.check()?;
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.cancellation.request(CancellationReason::Requested);
        Ok(RawHttpsResponse {
            status: 200,
            headers: std::collections::BTreeMap::from([(
                "content-type".to_string(),
                "application/json".to_string(),
            )]),
            body: format!(
                "{{\"access_token\":\"{NEXT_ACCESS}\",\"refresh_token\":\"{NEXT_REFRESH}\"}}"
            )
            .into_bytes(),
        })
    }
}

#[cfg(feature = "config-fixture")]
struct ExchangeOutcome {
    cancelled: bool,
    deadline: bool,
    succeeded: bool,
    resource_count: usize,
    native_flow_count: usize,
}

#[cfg(feature = "config-fixture")]
struct ExchangeWorker {
    cancellation: RunCancellation,
    join: Option<thread::JoinHandle<ExchangeOutcome>>,
}

#[cfg(feature = "config-fixture")]
impl ExchangeWorker {
    fn spawn(auth: Arc<AuthHost>, cancellation: RunCancellation) -> Self {
        let join = thread::spawn(move || {
            let mut vm = compile_vm(&auth);
            let (policy, _, code, verifier) = ready_exchange(&auth, &mut vm);
            let request = public_request(policy, "/oauth/token", "client_id=worker");
            let exchange = vm
                .resolve_exported_callable("exchange")
                .expect("RSS export");
            let result = vm.invoke_callable(exchange, &[request, code, verifier]);
            let failure = result.as_ref().err().map(ToString::to_string);
            ExchangeOutcome {
                cancelled: failure.as_deref().is_some_and(|text| {
                    text.contains("cancelled") || text.contains("policy_inactive")
                }),
                deadline: failure
                    .as_deref()
                    .is_some_and(|text| text.contains("deadline_exceeded")),
                succeeded: result.is_ok(),
                resource_count: vm.host_context().resource_count(),
                native_flow_count: auth.fixture_live_oauth_flow_count().unwrap_or(usize::MAX),
            }
        });
        Self {
            cancellation,
            join: Some(join),
        }
    }

    fn finish(&mut self) -> ExchangeOutcome {
        self.join
            .take()
            .expect("exchange worker")
            .join()
            .expect("worker joined")
    }
}

#[cfg(feature = "config-fixture")]
impl Drop for ExchangeWorker {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            self.cancellation.request(CancellationReason::Requested);
            let _ = join.join();
        }
    }
}

#[cfg(feature = "config-fixture")]
fn credential_metadata(generation: i64) -> Value {
    record(vec![
        ("provider", Value::string("openai-codex")),
        ("kind", Value::string("oauth")),
        ("source", Value::string("synthetic-rss-test")),
        ("token_type", Value::string("Bearer")),
        ("expires_at_ms", Value::Int(1_900_000_000_000)),
        (
            "scopes",
            Value::array(vec![Value::string("scope.synthetic")]),
        ),
        ("account_id", Value::string("rss-test-account")),
        ("generation", Value::Int(generation)),
        ("status", Value::string("active")),
        ("last_refresh_at_ms", Value::Int(1_790_000_000_000)),
        ("has_refresh_token", Value::Bool(true)),
    ])
}

#[cfg(feature = "config-fixture")]
fn save_request(
    policy: Value,
    expected_generation: i64,
    access_slot: Value,
    refresh_slot: Value,
) -> Value {
    record(vec![
        ("credential_id", Value::string("fixture-codex")),
        ("expected_generation", Value::Int(expected_generation)),
        ("policy_handle", policy),
        ("metadata", credential_metadata(expected_generation)),
        ("access_slot", access_slot),
        ("refresh_action", Value::string("replace")),
        ("refresh_slot", refresh_slot),
    ])
}

#[cfg(feature = "config-fixture")]
#[test]
fn real_rss_exchange_mints_captured_generation_slots_and_saves_by_cas() {
    use rustscript_agent::auth::store::AuthStore;
    use serde_json::json;

    let home = TempHome::new("exchange-save");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(
        200,
        json!({
            "access_token": NEXT_ACCESS,
            "refresh_token": NEXT_REFRESH,
            "public": "accepted"
        }),
    );
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(oauth.clone())
    .with_oauth_callback_fixture();
    let mut vm = compile_vm(&auth);
    let bound = auth.bind_vm(&mut vm).expect("bind owner");
    let snapshot = call(&mut vm, "snapshot", &[field(&bound, "host_home")]);
    let policy = field(&snapshot, "policy_handle");
    let begun = call(&mut vm, "begin", &[policy.clone(), public_intent()]);
    let callback = field(&begun, "callback_handle");
    let verifier = field(&begun, "verifier_handle");
    auth.fixture_inject_matching_callback(&mut vm, &callback, CALLBACK_CODE)
        .expect("host-injected matching callback");
    let waited = call(&mut vm, "wait", &[callback]);
    let code = field(&waited, "code_handle");
    let request = record(vec![
        ("policy_handle", policy.clone()),
        ("credential_id", Value::string("fixture-codex")),
        ("method", Value::string("POST")),
        ("path", Value::string("/oauth/token")),
        ("public_headers", Value::array(vec![])),
        ("public_body", Value::string("client_id=caller-selected")),
    ]);
    let response = call(&mut vm, "exchange", &[request, code, verifier]);
    assert_eq!(field(&response, "status"), Value::Int(200));
    assert_eq!(
        field(&response, "body_without_secret_fields"),
        Value::string(r#"{"public":"accepted"}"#)
    );
    let response_text = format!("{response:?}");
    for secret in [CALLBACK_CODE, NEXT_ACCESS, NEXT_REFRESH] {
        assert!(!response_text.contains(secret), "RSS response redaction");
    }
    let access_slot = field(&response, "access_slot");
    let refresh_slot = field(&response, "refresh_slot");
    assert!(matches!(access_slot, Value::Int(_)) && matches!(refresh_slot, Value::Int(_)));

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    let body = &sent[0].body;
    assert!(
        body.contains(&format!("code={CALLBACK_CODE}")),
        "host inserted callback code"
    );
    assert!(
        body.split('&').any(|item| item
            .strip_prefix("code_verifier=")
            .is_some_and(|value| !value.is_empty())),
        "host inserted native verifier"
    );
    assert!(
        body.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A"),
        "host inserted native redirect URI"
    );
    assert!(sent[0].url == "https://auth.openai.com/oauth/token");

    let wrong_generation =
        save_request(policy.clone(), 5, access_slot.clone(), refresh_slot.clone());
    let failure = vm
        .resolve_exported_callable("save")
        .expect("RSS save export");
    let rejected = vm
        .invoke_callable(failure, &[wrong_generation])
        .expect_err("wrong slot generation is rejected");
    assert!(
        rejected.to_string().contains("save_rejected"),
        "typed CAS rejection"
    );
    assert!(
        !rejected.to_string().contains(NEXT_ACCESS) && !rejected.to_string().contains(NEXT_REFRESH)
    );

    let saved = call(
        &mut vm,
        "save",
        &[save_request(policy, 4, access_slot, refresh_slot)],
    );
    assert_eq!(
        field(&field(&saved, "metadata"), "generation"),
        Value::Int(5)
    );
    let stored = AuthStore::from_home(&home.0)
        .expect("open fixture store")
        .load_metadata("fixture-codex")
        .expect("saved metadata");
    assert_eq!(stored.generation, 5);
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
    assert_eq!(
        vm.host_context().resource_count(),
        2,
        "retain only home and policy"
    );
}

#[cfg(feature = "config-fixture")]
fn save_request_preserving(policy: Value, expected_generation: i64, access_slot: Value) -> Value {
    record(vec![
        ("credential_id", Value::string("fixture-codex")),
        ("expected_generation", Value::Int(expected_generation)),
        ("policy_handle", policy),
        ("metadata", credential_metadata(expected_generation)),
        ("access_slot", access_slot),
        ("refresh_action", Value::string("preserve")),
        ("refresh_slot", Value::Null),
    ])
}

#[cfg(feature = "config-fixture")]
#[test]
fn concurrent_store_change_after_begin_keeps_captured_generation_and_does_not_overwrite() {
    use rustscript_agent::auth::store::AuthStore;
    use serde_json::json;

    let home = TempHome::new("generation-race");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(
        200,
        json!({
            "access_token": NEXT_ACCESS,
            "refresh_token": NEXT_REFRESH,
            "public": "accepted"
        }),
    );
    let auth = scripted_auth(&home, transport.clone());
    let mut vm_a = compile_vm(&auth);
    let (policy_a, request_a, code_a, verifier_a) = ready_exchange(&auth, &mut vm_a);

    let mut vm_b = compile_vm(&auth);
    let bound_b = auth.bind_vm(&mut vm_b).expect("bind concurrent owner");
    let snapshot_b = call(&mut vm_b, "snapshot", &[field(&bound_b, "host_home")]);
    let policy_b = field(&snapshot_b, "policy_handle");
    let concurrent_slot = auth
        .fixture_slot(
            &mut vm_b,
            "fixture-codex",
            4,
            false,
            "SYNTHETIC_CONCURRENT_ACCESS",
        )
        .expect("issue synthetic concurrent slot");
    let advanced = call(
        &mut vm_b,
        "save",
        &[save_request_preserving(policy_b, 4, concurrent_slot)],
    );
    assert_eq!(
        field(&field(&advanced, "metadata"), "generation"),
        Value::Int(5)
    );

    let exchange = call(&mut vm_a, "exchange", &[request_a, code_a, verifier_a]);
    assert_eq!(field(&exchange, "status"), Value::Int(200));
    let stale_save = call(
        &mut vm_a,
        "save",
        &[save_request(
            policy_a,
            4,
            field(&exchange, "access_slot"),
            field(&exchange, "refresh_slot"),
        )],
    );
    assert_eq!(field(&stale_save, "outcome"), Value::string("adopted"));
    assert_eq!(
        field(&field(&stale_save, "metadata"), "generation"),
        Value::Int(5)
    );

    let store = AuthStore::from_home(&home.0).expect("open fixture store");
    assert_eq!(
        store
            .load_metadata("fixture-codex")
            .expect("current metadata")
            .generation,
        5
    );
    let persisted =
        fs::read_to_string(home.0.join("auth.yaml")).expect("current synthetic auth file");
    assert!(
        persisted.contains("SYNTHETIC_CONCURRENT_ACCESS"),
        "newer access remains persisted"
    );
    assert!(
        !persisted.contains(NEXT_ACCESS),
        "stale response did not overwrite newer access"
    );
    assert_eq!(transport.take_sent().len(), 1);
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
    assert_eq!(vm_a.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn foreign_owner_flow_pair_cannot_cross_vm_arena() {
    use serde_json::json;

    let home = TempHome::new("cross-owner");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, json!({"public": "accepted"}));
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let cancellation_a = RunCancellation::with_timeout(Duration::from_secs(30));
    let cancellation_b = RunCancellation::with_timeout(Duration::from_secs(30));
    let auth_a = fixture_auth_with_oauth(&home, cancellation_a, oauth.clone());
    let auth_b = fixture_auth_with_oauth(&home, cancellation_b, oauth);
    let mut vm_a = compile_vm_with_probes(&auth_a);
    let mut vm_b = compile_vm(&auth_b);
    let bound_a = auth_a.bind_vm(&mut vm_a).expect("owner A binding");
    let snapshot_a = call(&mut vm_a, "snapshot", &[field(&bound_a, "host_home")]);
    let policy_a = field(&snapshot_a, "policy_handle");
    let (_policy_b, request_b, code_b, verifier_b) = ready_exchange(&auth_b, &mut vm_b);
    let request_a = public_request(policy_a, "/oauth/token", "client_id=owner-a");
    let foreign_usage = record(vec![
        ("kind", Value::string("code_verifier")),
        ("code_handle", code_b.clone()),
        ("verifier_handle", verifier_b.clone()),
    ]);
    let direct = vm_a
        .resolve_exported_callable("test_direct_transport")
        .expect("typed probe");
    let _failure = vm_a
        .invoke_callable(direct, &[request_a, foreign_usage])
        .expect_err("foreign VM resources rejected");
    assert!(transport.take_sent().is_empty());
    assert_eq!(
        auth_a
            .fixture_live_oauth_flow_count()
            .expect("native flow count"),
        1
    );
    assert_eq!(vm_a.host_context().resource_count(), 2);
    assert_eq!(vm_b.host_context().resource_count(), 5);
    let response_b = call(&mut vm_b, "exchange", &[request_b, code_b, verifier_b]);
    assert_eq!(field(&response_b, "status"), Value::Int(200));
    assert_eq!(transport.take_sent().len(), 1);
    assert_eq!(
        auth_b
            .fixture_live_oauth_flow_count()
            .expect("owner B flow"),
        0
    );
    assert_eq!(vm_b.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn closed_verifier_closes_family_and_alias_cannot_send() {
    let home = TempHome::new("closed-pair");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = scripted_auth(&home, transport.clone());
    let mut vm = compile_vm(&auth);
    let (policy, callback, _request, code, verifier) = ready_exchange_with_callback(&auth, &mut vm);
    call(&mut vm, "close_callback", std::slice::from_ref(&callback));
    call(&mut vm, "close_verifier", std::slice::from_ref(&verifier));
    call(&mut vm, "close_code", std::slice::from_ref(&code));
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 2);

    let request = public_request(policy, "/oauth/token", "client_id=caller-selected");
    let failure = vm
        .invoke_callable(
            vm.resolve_exported_callable("exchange")
                .expect("RSS export"),
            &[request, code, verifier],
        )
        .expect_err("closed pair alias");
    assert!(!failure.to_string().contains(NEXT_ACCESS));
    assert!(transport.take_sent().is_empty());
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn wrong_class_and_forged_ids_reject_without_closing_the_valid_pair() {
    use serde_json::json;

    let home = TempHome::new("wrong-resource-class");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, json!({"public": "accepted"}));
    let auth = scripted_auth(&home, transport.clone());
    let mut vm = compile_vm_with_probes(&auth);
    let (_policy, callback, request, code, verifier) = ready_exchange_with_callback(&auth, &mut vm);
    let direct = vm
        .resolve_exported_callable("test_direct_transport")
        .expect("typed probe");

    let wrong_class = record(vec![
        ("kind", Value::string("code_verifier")),
        ("code_handle", callback),
        ("verifier_handle", verifier.clone()),
    ]);
    let failure = vm
        .invoke_callable(direct.clone(), &[request.clone(), wrong_class])
        .expect_err("callback resource is not a code resource");
    assert!(failure.to_string().contains("resource_type_key_mismatch"));

    let forged = record(vec![
        ("kind", Value::string("code_verifier")),
        ("code_handle", Value::Int(999_999_999)),
        ("verifier_handle", verifier.clone()),
    ]);
    let _failure = vm
        .invoke_callable(direct, &[request.clone(), forged])
        .expect_err("forged resource id");
    assert!(transport.take_sent().is_empty());
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        1
    );
    assert_eq!(vm.host_context().resource_count(), 5);

    let response = call(&mut vm, "exchange", &[request, code, verifier]);
    assert_eq!(field(&response, "status"), Value::Int(200));
    assert_eq!(transport.take_sent().len(), 1);
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn mixed_two_flow_pair_is_rejected_and_both_flows_remain_usable() {
    use serde_json::json;

    let home = TempHome::new("two-flow-mix");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, json!({"public": "first"}));
    transport.push_json(200, json!({"public": "second"}));
    let auth = scripted_auth(&home, transport.clone());
    let mut vm = compile_vm_with_probes(&auth);
    let (policy, _, request_a, code_a, verifier_a) = ready_exchange_with_callback(&auth, &mut vm);
    let (_, request_b, code_b, verifier_b) = ready_pair(&auth, &mut vm, policy.clone());
    let direct = vm
        .resolve_exported_callable("test_direct_transport")
        .expect("typed probe");
    let mixed = record(vec![
        ("kind", Value::string("code_verifier")),
        ("code_handle", code_a.clone()),
        ("verifier_handle", verifier_b.clone()),
    ]);
    let failure = vm
        .invoke_callable(direct, &[request_a.clone(), mixed])
        .expect_err("mixed flow pair");
    assert!(failure.to_string().contains("handle_provenance"));
    assert!(transport.take_sent().is_empty());
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        2
    );
    assert_eq!(vm.host_context().resource_count(), 8);

    let result_a = call(&mut vm, "exchange", &[request_a, code_a, verifier_a]);
    let result_b = call(&mut vm, "exchange", &[request_b, code_b, verifier_b]);
    assert_eq!(field(&result_a, "status"), Value::Int(200));
    assert_eq!(field(&result_b, "status"), Value::Int(200));
    assert_eq!(transport.take_sent().len(), 2);
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn cross_credential_pair_is_rejected_without_consuming_either_flow() {
    use serde_json::json;

    let home = TempHome::new("cross-credential");
    home.admit_second_credential();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, json!({"public": "first"}));
    transport.push_json(200, json!({"public": "second"}));
    let auth = scripted_auth(&home, transport.clone());
    let mut vm = compile_vm_with_probes(&auth);
    let (policy, _, request_a, code_a, verifier_a) = ready_exchange_with_callback(&auth, &mut vm);
    let (_, request_b, code_b, verifier_b) =
        ready_pair_for(&auth, &mut vm, policy, "fixture-codex-two");
    let direct = vm
        .resolve_exported_callable("test_direct_transport")
        .expect("typed probe");
    let wrong_credential = record(vec![
        ("kind", Value::string("code_verifier")),
        ("code_handle", code_a.clone()),
        ("verifier_handle", verifier_a.clone()),
    ]);
    let failure = vm
        .invoke_callable(direct, &[request_b.clone(), wrong_credential])
        .expect_err("first credential pair cannot authorize second credential");
    assert!(failure.to_string().contains("handle_provenance"));
    assert!(transport.take_sent().is_empty());
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        2
    );
    assert_eq!(vm.host_context().resource_count(), 8);

    let response_a = call(&mut vm, "exchange", &[request_a, code_a, verifier_a]);
    let response_b = call(&mut vm, "exchange", &[request_b, code_b, verifier_b]);
    assert_eq!(field(&response_a, "status"), Value::Int(200));
    assert_eq!(field(&response_b, "status"), Value::Int(200));
    assert_eq!(transport.take_sent().len(), 2);
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn malformed_code_use_shapes_reject_without_effect_and_valid_pair_remains_usable() {
    use serde_json::json;

    let home = TempHome::new("malformed-use");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, json!({"public": "accepted"}));
    let auth = scripted_auth(&home, transport.clone());
    let mut vm = compile_vm_with_probes(&auth);
    let (policy, _, code, verifier) = ready_exchange(&auth, &mut vm);
    let access = call(&mut vm, "test_access_handle", std::slice::from_ref(&policy));
    let request = public_request(policy, "/oauth/token", "client_id=caller-selected");
    let direct = vm
        .resolve_exported_callable("test_direct_transport")
        .expect("typed probe");

    let incomplete = record(vec![
        ("kind", Value::string("code_verifier")),
        ("code_handle", code.clone()),
    ]);
    let failure = vm
        .invoke_callable(direct.clone(), &[request.clone(), incomplete])
        .expect_err("incomplete pair");
    assert!(failure.to_string().contains("credential_use_unsupported"));

    let mixed = record(vec![
        ("kind", Value::string("code_verifier")),
        ("access_handle", access.clone()),
        ("code_handle", code.clone()),
        ("verifier_handle", verifier.clone()),
    ]);
    let failure = vm
        .invoke_callable(direct.clone(), &[request.clone(), mixed])
        .expect_err("mixed kinds");
    assert!(failure.to_string().contains("credential_use_unsupported"));

    let unknown = record(vec![
        ("kind", Value::string("code_verifier")),
        ("code_handle", code.clone()),
        ("verifier_handle", verifier.clone()),
        ("unexpected", Value::Bool(true)),
    ]);
    let failure = vm
        .invoke_callable(direct, &[request.clone(), unknown])
        .expect_err("unknown use key");
    assert!(failure.to_string().contains("credential_use_unsupported"));

    assert!(transport.take_sent().is_empty());
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        1
    );
    assert_eq!(vm.host_context().resource_count(), 6);

    let valid = call(&mut vm, "exchange", &[request, code, verifier]);
    assert_eq!(field(&valid, "status"), Value::Int(200));
    assert_eq!(transport.take_sent().len(), 1);
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 3);
    call(&mut vm, "test_close_access", &[access]);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn cancellation_after_send_withholds_token_slots_and_closes_consumed_family() {
    let home = TempHome::new("late-cancel");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let transport = Arc::new(CancelOnResponseTransport {
        cancellation: cancellation.clone(),
        calls: AtomicUsize::new(0),
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
        .with_oauth_host(oauth)
        .with_oauth_callback_fixture();
    let mut vm = compile_vm(&auth);
    let (_policy, _request, code, verifier) = ready_exchange(&auth, &mut vm);
    let failure = vm
        .invoke_callable(
            vm.resolve_exported_callable("exchange")
                .expect("RSS export"),
            &[_request, code, verifier],
        )
        .expect_err("late cancellation");
    let public_error = failure.to_string();
    assert!(public_error.contains("policy_inactive"));
    assert!(!public_error.contains(NEXT_ACCESS) && !public_error.contains(NEXT_REFRESH));
    assert_eq!(transport.calls.load(Ordering::Acquire), 1);
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn inactive_owner_rejection_cleans_only_its_valid_pair() {
    use serde_json::json;

    let home = TempHome::new("inactive-owner-cleanup");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, json!({"public": "owner b"}));
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let cancellation_a = RunCancellation::with_timeout(Duration::from_secs(30));
    let auth_a = fixture_auth_with_oauth(&home, cancellation_a.clone(), oauth.clone());
    let auth_b = fixture_auth_with_oauth(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        oauth,
    );
    let mut vm_a = compile_vm_with_probes(&auth_a);
    let mut vm_b = compile_vm(&auth_b);
    let (_policy_a, request_a, code_a, verifier_a) = ready_exchange(&auth_a, &mut vm_a);
    let (_policy_b, request_b, code_b, verifier_b) = ready_exchange(&auth_b, &mut vm_b);

    cancellation_a.request(CancellationReason::Requested);
    let failure = vm_a
        .invoke_callable(
            vm_a.resolve_exported_callable("exchange")
                .expect("RSS export"),
            &[request_a.clone(), code_a, verifier_a],
        )
        .expect_err("inactive owner A");
    assert!(failure.to_string().contains("policy_inactive"));
    assert_eq!(
        auth_a
            .fixture_live_oauth_flow_count()
            .expect("native flow count"),
        1
    );
    assert_eq!(vm_a.host_context().resource_count(), 2);

    let foreign_usage = record(vec![
        ("kind", Value::string("code_verifier")),
        ("code_handle", code_b.clone()),
        ("verifier_handle", verifier_b.clone()),
    ]);
    let direct = vm_a
        .resolve_exported_callable("test_direct_transport")
        .expect("typed probe");
    let _foreign_failure = vm_a
        .invoke_callable(direct, &[request_a, foreign_usage])
        .expect_err("inactive owner A does not close B's foreign pair");
    assert!(transport.take_sent().is_empty());
    assert_eq!(
        auth_a
            .fixture_live_oauth_flow_count()
            .expect("native flow count"),
        1
    );
    assert_eq!(vm_b.host_context().resource_count(), 5);

    let response_b = call(&mut vm_b, "exchange", &[request_b, code_b, verifier_b]);
    assert_eq!(field(&response_b, "status"), Value::Int(200));
    assert_eq!(transport.take_sent().len(), 1);
    assert_eq!(
        auth_b
            .fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
    assert_eq!(vm_b.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn provider_error_response_consumes_pair_without_minting_slots() {
    use serde_json::json;

    let home = TempHome::new("provider-error");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(
        400,
        json!({"error": "invalid_grant", "error_description": "synthetic"}),
    );
    let auth = scripted_auth(&home, transport.clone());
    let mut vm = compile_vm(&auth);
    let (policy, _, code, verifier) = ready_exchange(&auth, &mut vm);
    let request = public_request(policy, "/oauth/token", "client_id=caller-selected");
    let result = vm
        .invoke_callable(
            vm.resolve_exported_callable("exchange")
                .expect("RSS export"),
            &[request, code, verifier],
        )
        .expect("sanitized provider error response");
    assert_eq!(field(&result, "status"), Value::Int(400));
    assert_eq!(field(&result, "access_slot"), Value::Null);
    assert_eq!(field(&result, "refresh_slot"), Value::Null);
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_eq!(transport.take_sent().len(), 1);
}

#[cfg(feature = "config-fixture")]
#[test]
fn malformed_provider_response_consumes_pair_and_mints_no_slots() {
    let home = TempHome::new("malformed-provider");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, "not-json");
    let auth = scripted_auth(&home, transport.clone());
    let mut vm = compile_vm(&auth);
    let (policy, _, code, verifier) = ready_exchange(&auth, &mut vm);
    let request = public_request(policy, "/oauth/token", "client_id=caller-selected");
    let failure = vm
        .invoke_callable(
            vm.resolve_exported_callable("exchange")
                .expect("RSS export"),
            &[request, code, verifier],
        )
        .expect_err("malformed response");
    assert!(failure.to_string().contains("malformed_response"));
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_eq!(transport.take_sent().len(), 1);
}

#[cfg(feature = "config-fixture")]
#[test]
fn transport_failure_consumes_pair_and_mints_no_slots() {
    let home = TempHome::new("transport-failure");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let auth = scripted_auth(&home, transport.clone());
    let mut vm = compile_vm(&auth);
    let (policy, _, code, verifier) = ready_exchange(&auth, &mut vm);
    let request = public_request(policy, "/oauth/token", "client_id=caller-selected");
    let failure = vm
        .invoke_callable(
            vm.resolve_exported_callable("exchange")
                .expect("RSS export"),
            &[request, code, verifier],
        )
        .expect_err("missing scripted transport response");
    assert!(failure.to_string().contains("transport_error"));
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_eq!(transport.take_sent().len(), 1);
}

#[cfg(feature = "config-fixture")]
#[test]
fn scoped_transport_observes_owner_cancel_and_revoke_without_stopping_owner_b() {
    let home = TempHome::new("owner-cancel");
    let (entered_tx, entered_rx) = mpsc::channel();
    let transport = Arc::new(OwnerScopedTransport {
        entered: entered_tx,
        calls: AtomicUsize::new(0),
        rescue_after: Duration::from_secs(4),
    });
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let host_cancel = Arc::new(ScriptedCancel::new());
    let oauth = Arc::new(OAuthHost::new(
        transport.clone(),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        clock.clone(),
        host_cancel.clone(),
    ));

    let cancellation_a = RunCancellation::with_timeout(Duration::from_secs(30));
    let auth_a = fixture_auth_with_oauth(&home, cancellation_a.clone(), oauth.clone());
    let mut worker_a = ExchangeWorker::spawn(auth_a.clone(), cancellation_a.clone());
    assert_eq!(
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("A reached send"),
        0
    );
    cancellation_a.request(CancellationReason::Requested);
    let outcome_a = worker_a.finish();
    assert!(outcome_a.cancelled && !outcome_a.succeeded);
    assert_eq!(outcome_a.resource_count, 2);
    assert_eq!(outcome_a.native_flow_count, 0);

    let cancellation_c = RunCancellation::with_timeout(Duration::from_secs(30));
    let auth_c = fixture_auth_with_oauth(&home, cancellation_c.clone(), oauth.clone());
    let mut worker_c = ExchangeWorker::spawn(auth_c.clone(), cancellation_c.clone());
    assert_eq!(
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("C reached send"),
        1
    );
    auth_c.revoke();
    let outcome_c = worker_c.finish();
    assert!(outcome_c.cancelled && !outcome_c.succeeded);
    assert_eq!(outcome_c.resource_count, 2);
    assert_eq!(outcome_c.native_flow_count, 0);

    let cancellation_b = RunCancellation::with_timeout(Duration::from_secs(30));
    let auth_b = fixture_auth_with_oauth(&home, cancellation_b, oauth);
    let mut vm_b = compile_vm(&auth_b);
    let (policy_b, _, code_b, verifier_b) = ready_exchange(&auth_b, &mut vm_b);
    let request_b = public_request(policy_b, "/oauth/token", "client_id=allow_success");
    let response_b = call(&mut vm_b, "exchange", &[request_b, code_b, verifier_b]);
    assert_eq!(field(&response_b, "status"), Value::Int(200));
    assert_eq!(vm_b.host_context().resource_count(), 2);
    assert_eq!(
        auth_b
            .fixture_live_oauth_flow_count()
            .expect("owner B flow"),
        0
    );
    assert_eq!(transport.calls.load(Ordering::Acquire), 3);
    assert!(
        !host_cancel.is_cancelled(),
        "owner cancellation must not mutate host cancellation"
    );
}

#[cfg(feature = "config-fixture")]
#[test]
fn scoped_transport_deadline_reaches_cooperative_send_and_reclaims_pair() {
    let home = TempHome::new("transport-deadline");
    let (entered_tx, entered_rx) = mpsc::channel();
    let transport = Arc::new(OwnerScopedTransport {
        entered: entered_tx,
        calls: AtomicUsize::new(0),
        rescue_after: Duration::from_secs(4),
    });
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let host_cancel = Arc::new(ScriptedCancel::new());
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        clock.clone(),
        host_cancel.clone(),
    ));
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let auth = fixture_auth_with_oauth(&home, cancellation.clone(), oauth);
    let mut worker = ExchangeWorker::spawn(auth.clone(), cancellation);
    assert_eq!(
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("reached send"),
        0
    );
    clock.expire();
    let outcome = worker.finish();
    assert!(outcome.deadline && !outcome.succeeded);
    assert_eq!(outcome.resource_count, 2);
    assert_eq!(outcome.native_flow_count, 0);
    assert!(!host_cancel.is_cancelled());
}

#[cfg(feature = "config-fixture")]
#[test]
fn local_request_denials_preserve_pair_for_retry_and_alias_replay_cannot_send() {
    use serde_json::json;

    let home = TempHome::new("local-denial-retry");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, json!({"public": "accepted"}));
    let auth = scripted_auth(&home, transport.clone());
    let mut vm = compile_vm(&auth);
    let (policy, _, code, verifier) = ready_exchange(&auth, &mut vm);

    let denied = [
        (
            public_request(policy.clone(), "/not-admitted", "client_id=caller-selected"),
            "path_denied",
        ),
        (
            record(vec![
                ("policy_handle", policy.clone()),
                ("credential_id", Value::string("fixture-codex")),
                ("method", Value::string("POST")),
                ("path", Value::string("/oauth/token")),
                (
                    "public_headers",
                    Value::array(vec![record(vec![
                        ("name", Value::string("Host")),
                        ("value", Value::string("attacker.invalid")),
                    ])]),
                ),
                ("public_body", Value::string("client_id=caller-selected")),
            ]),
            "header_denied",
        ),
        (
            public_request(policy.clone(), "/oauth/token", "code=caller-supplied"),
            "invalid_intent",
        ),
        (
            record(vec![
                ("policy_handle", policy.clone()),
                ("credential_id", Value::string("fixture-codex")),
                ("method", Value::string("DELETE")),
                ("path", Value::string("/oauth/token")),
                ("public_headers", Value::array(vec![])),
                ("public_body", Value::string("client_id=caller-selected")),
            ]),
            "method_denied",
        ),
    ];
    for (request, expected_code) in denied {
        let exchange = vm
            .resolve_exported_callable("exchange")
            .expect("RSS exchange");
        let failure = vm
            .invoke_callable(exchange, &[request, code.clone(), verifier.clone()])
            .expect_err("local request denial");
        assert!(
            failure.to_string().contains(expected_code),
            "typed local denial"
        );
        assert!(
            transport.take_sent().is_empty(),
            "no send before local admission"
        );
        assert_eq!(auth.fixture_live_oauth_flow_count().expect("live flow"), 1);
        assert_eq!(vm.host_context().resource_count(), 5);
    }

    let corrected = public_request(policy, "/oauth/token", "client_id=caller-selected");
    let response = call(
        &mut vm,
        "exchange",
        &[corrected.clone(), code.clone(), verifier.clone()],
    );
    assert_eq!(field(&response, "status"), Value::Int(200));
    assert_eq!(transport.take_sent().len(), 1);
    assert_eq!(
        auth.fixture_live_oauth_flow_count().expect("terminal flow"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 2);

    let exchange = vm
        .resolve_exported_callable("exchange")
        .expect("RSS exchange");
    let _failure = vm
        .invoke_callable(exchange, &[corrected, code, verifier])
        .expect_err("closed aliases cannot replay");
    assert!(
        transport.take_sent().is_empty(),
        "alias replay must not send"
    );
}

#[test]
fn callback_begin_remains_unavailable_without_fixture_opt_in() {
    let home = TempHome::new("callback-default-off");
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host");
    let mut vm = compile_vm(&auth);
    let bound = auth.bind_vm(&mut vm).expect("bind owner");
    let snapshot = call(&mut vm, "snapshot", &[field(&bound, "host_home")]);
    let policy = field(&snapshot, "policy_handle");
    let begin = vm.resolve_exported_callable("begin").expect("RSS begin");
    let failure = vm
        .invoke_callable(begin, &[policy, public_intent()])
        .expect_err("callback bridge is opt-in");
    assert!(failure.to_string().contains("callback_unavailable"));
}
