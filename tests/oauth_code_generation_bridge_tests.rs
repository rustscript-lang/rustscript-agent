use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use rustscript_agent::auth::{
    host::{AuthHost, auth_host_catalog},
    oauth::{
        BoundedHttpsTransport, BrowserOpener, OAuthCancel, OAuthClock, OAuthError, OAuthHost,
        OAuthIoContext, PreparedHttpsRequest, RawHttpsResponse, ScriptedClock,
    },
    store::AuthStore,
};
use rustscript_agent::{CancellationReason, RunCancellation};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
use url::Url;

const CREDENTIAL_ID: &str = "fixture-codex";
const CALLBACK_CODE: &str = "SYNTHETIC_NATIVE_CODEGEN_CALLBACK";
const WRITER_ACCESS: &str = "SYNTHETIC_WRITER_B_ACCESS";
const OLD_FLOW_ACCESS: &str = "SYNTHETIC_OLD_FLOW_ACCESS";
const TEST_RSS: &str = r#"
pub fn current_metadata(policy: resource<auth.policy>) -> AuthMetadataResultEnvelope {
    auth::load_metadata_result("fixture-codex", &policy)
}

pub fn selected_generation(
    policy: resource<auth.policy>,
    code_handle: resource<oauth.authorization_code>,
    verifier_handle: resource<oauth.verifier>
) -> CodeGenerationResultEnvelope {
    oauth::code_generation_result(&code_handle, &verifier_handle)
}

pub fn exchange_for_save(
    request: TransportPublicRequest,
    code: resource<oauth.authorization_code>,
    verifier: resource<oauth.verifier>
) -> TransportResultEnvelope {
    let usage: TransportCredentialUse = {
        kind: "code_verifier",
        access_handle: null,
        refresh_handle: null,
        code_handle: code,
        verifier_handle: verifier,
        device_handle: null
    };
    let payload: TransportPayloadIntent = {
        encoding: "form",
        secret_fields: "authorization_code",
        device_field: null,
        code_field: "code"
    };
    oauth::transport_payload_result(&request, &usage, payload)
}

pub fn save_selected(
    policy: resource<auth.policy>,
    expected_generation: int,
    access_slot: resource<auth.secret_slot>,
    refresh_action: string
) -> AuthSaveResultEnvelope {
    let has_refresh_token: bool = refresh_action == "preserve";
    let metadata: CredentialMetadata = {
        provider: "openai-codex",
        kind: "oauth",
        source: "synthetic-generation-bridge",
        token_type: "Bearer",
        expires_at_ms: 1900003600000,
        scopes: ["scope.synthetic"],
        account_id: "synthetic-generation-bridge",
        generation: expected_generation,
        status: "active",
        last_refresh_at_ms: 1900000000000,
        has_refresh_token: has_refresh_token
    };
    let request: SaveCredentialRequest = {
        credential_id: "fixture-codex",
        expected_generation: expected_generation,
        policy_handle: policy,
        metadata: metadata,
        access_slot: access_slot,
        refresh_action: refresh_action,
        refresh_slot: null
    };
    auth::save_if_generation_result(&request)
}

pub fn cleanup(policy: resource<auth.policy>) -> null {
    auth::cleanup_transients(&policy)
}
"#;

struct TempHome(PathBuf);

impl TempHome {
    fn from_fixture(label: &str) -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned temp"));
        let path = root.join(format!(
            "oauth-code-generation-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create private home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml"))
            .expect("copy synthetic config");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read synthetic auth fixture")
            .replace("1788440000000", "1900000000000");
        fs::write(path.join("auth.yaml"), auth).expect("write synthetic auth fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("private home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                    .expect("private file mode");
            }
        }
        Self(path)
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct LoopbackBrowser {
    stream: Mutex<Option<TcpStream>>,
}

impl LoopbackBrowser {
    fn new() -> Self {
        Self {
            stream: Mutex::new(None),
        }
    }

    fn release_callback_stream(&self) {
        self.stream.lock().unwrap_or_else(|p| p.into_inner()).take();
    }
}

impl BrowserOpener for LoopbackBrowser {
    fn open(&self, authorization_url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
        let authorization = Url::parse(authorization_url).map_err(|_| OAuthError::Transport {
            message: "synthetic authorization URL is invalid".into(),
        })?;
        let redirect = authorization
            .query_pairs()
            .find_map(|(key, value)| (key == "redirect_uri").then(|| value.into_owned()))
            .ok_or_else(|| OAuthError::Transport {
                message: "native redirect is missing".into(),
            })?;
        let state = authorization
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            .ok_or_else(|| OAuthError::Transport {
                message: "native state is missing".into(),
            })?;
        let callback = Url::parse(&redirect).map_err(|_| OAuthError::Transport {
            message: "synthetic callback URL is invalid".into(),
        })?;
        let port = callback.port().ok_or_else(|| OAuthError::Transport {
            message: "native callback port is missing".into(),
        })?;
        let target = format!("{}?state={}&code={}", callback.path(), state, CALLBACK_CODE);
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let mut stream =
            TcpStream::connect_timeout(&address, Duration::from_secs(2)).map_err(|_| {
                OAuthError::Transport {
                    message: "loopback callback connect failed".into(),
                }
            })?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| OAuthError::Transport {
                message: "loopback callback timeout setup failed".into(),
            })?;
        write!(
            stream,
            "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        )
        .map_err(|_| OAuthError::Transport {
            message: "loopback callback request failed".into(),
        })?;
        *self.stream.lock().unwrap_or_else(|p| p.into_inner()) = Some(stream);
        Ok(())
    }
}

struct SyntheticTransport {
    calls: AtomicUsize,
}

impl SyntheticTransport {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl BoundedHttpsTransport for SyntheticTransport {
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        context.check()?;
        self.calls.fetch_add(1, Ordering::AcqRel);
        let access = if request.body.contains("client_id=writer-b") {
            WRITER_ACCESS
        } else {
            OLD_FLOW_ACCESS
        };
        Ok(RawHttpsResponse {
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
            body: format!("{{\"access_token\":\"{access}\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"public\":\"accepted\"}}").into_bytes(),
        })
    }
}

struct TestClock {
    started: Instant,
}

impl OAuthClock for TestClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn unix_ms(&self) -> u64 {
        1_900_000_000_000 + self.started.elapsed().as_millis() as u64
    }
}

struct NeverCancel;

impl OAuthCancel for NeverCancel {
    fn is_cancelled(&self) -> bool {
        false
    }
}

fn native_auth_with_cancellation(
    home: &TempHome,
    browser: Arc<LoopbackBrowser>,
    transport: Arc<SyntheticTransport>,
    clock: Arc<dyn OAuthClock>,
    cancellation: RunCancellation,
) -> AuthHost {
    let oauth = Arc::new(OAuthHost::new_with_native_callbacks(
        transport,
        browser,
        clock,
        Arc::new(NeverCancel),
    ));
    AuthHost::new(home.0.clone(), cancellation)
        .expect("native auth host")
        .with_oauth_host(oauth)
}

fn native_auth(
    home: &TempHome,
    browser: Arc<LoopbackBrowser>,
    transport: Arc<SyntheticTransport>,
) -> AuthHost {
    native_auth_with_cancellation(
        home,
        browser,
        transport,
        Arc::new(TestClock {
            started: Instant::now(),
        }),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
}

fn native_enrollment_auth(
    home: &TempHome,
    browser: Arc<LoopbackBrowser>,
    transport: Arc<SyntheticTransport>,
    clock: Arc<dyn OAuthClock>,
    cancellation: RunCancellation,
) -> AuthHost {
    let oauth = Arc::new(OAuthHost::new_with_native_callbacks(
        transport,
        browser,
        clock,
        Arc::new(NeverCancel),
    ));
    AuthHost::new_for_enrollment(home.0.clone(), cancellation, CREDENTIAL_ID)
        .expect("native enrollment auth host")
        .with_oauth_host(oauth)
}

fn compile_vm(auth: &AuthHost) -> Vm {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/code_exchange_contract.rss");
    let source = fs::read_to_string(&path).expect("real code exchange RSS");
    let source = format!("{source}\n{TEST_RSS}");
    let catalog = auth_host_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog)),
    )
    .expect("compile actual RSS against exact catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog.as_ref())
        .expect("register exact restricted catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted catalog");
    assert!(matches!(vm.run().expect("run RSS root"), VmStatus::Halted));
    vm
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected RSS map: {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing RSS field {name}: {value:?}"))
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
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args).expect("RSS call")
}

fn call_result(vm: &mut Vm, name: &str, args: &[Value]) -> Result<Value, rustscript_vm::VmError> {
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args)
}

fn public_intent() -> Value {
    record(vec![
        ("credential_id", Value::string(CREDENTIAL_ID)),
        ("path", Value::string("/codex/device")),
        ("flow", Value::string("authorization_code_pkce")),
        ("callback_mode", Value::string("browser")),
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

fn public_request(policy: Value, client: &str) -> Value {
    record(vec![
        ("policy_handle", policy),
        ("credential_id", Value::string(CREDENTIAL_ID)),
        ("method", Value::string("POST")),
        ("path", Value::string("/oauth/token")),
        (
            "public_headers",
            Value::array(vec![record(vec![
                ("name", Value::string("content-type")),
                ("value", Value::string("application/x-www-form-urlencoded")),
            ])]),
        ),
        (
            "public_body",
            Value::string(format!("grant_type=authorization_code&client_id={client}")),
        ),
    ])
}

fn captured_generation(vm: &mut Vm, policy: &Value, code: &Value, verifier: &Value) -> i64 {
    let result = call(
        vm,
        "selected_generation",
        &[policy.clone(), code.clone(), verifier.clone()],
    );
    assert_eq!(
        field(&result, "ok"),
        Value::Bool(true),
        "captured generation: {result:?}"
    );
    let Value::Int(generation) = field(&result, "value") else {
        panic!("captured generation must be an integer");
    };
    generation
}

fn exchange_slot(vm: &mut Vm, policy: &Value, client: &str, code: Value, verifier: Value) -> Value {
    let result = call(
        vm,
        "exchange_for_save",
        &[public_request(policy.clone(), client), code, verifier],
    );
    assert_eq!(
        field(&result, "ok"),
        Value::Bool(true),
        "native exchange: {result:?}"
    );
    let response = field(&result, "value");
    assert_eq!(field(&response, "status"), Value::Int(200));
    field(&response, "access_slot")
}

fn bind_policy(auth: &AuthHost, vm: &mut Vm) -> Value {
    let bound = auth.bind_vm(vm).expect("bind native owner");
    let snapshot = call(vm, "snapshot", &[field(&bound, "host_home")]);
    field(&snapshot, "policy_handle")
}

fn ready_pair(
    _auth: &AuthHost,
    vm: &mut Vm,
    policy: &Value,
    browser: &LoopbackBrowser,
) -> (Value, Value) {
    let begun = call(vm, "begin", &[policy.clone(), public_intent()]);
    let callback = field(&begun, "callback_handle");
    let verifier = field(&begun, "verifier_handle");
    let waited = call(vm, "wait", std::slice::from_ref(&callback));
    browser.release_callback_stream();
    let code = field(&waited, "code_handle");
    #[cfg(feature = "config-fixture")]
    assert!(
        _auth
            .fixture_live_oauth_flow_count()
            .expect("native flow count")
            >= 1
    );
    (code, verifier)
}

#[test]
fn captured_generation_adopts_concurrent_writer_without_overwrite() {
    let home = TempHome::from_fixture("concurrent-writer-green");
    let browser = Arc::new(LoopbackBrowser::new());
    let transport = Arc::new(SyntheticTransport::new());
    let auth = native_auth(&home, browser.clone(), transport.clone());
    let mut vm_a = compile_vm(&auth);
    let policy_a = bind_policy(&auth, &mut vm_a);
    let (code_a, verifier_a) = ready_pair(&auth, &mut vm_a, &policy_a, &browser);

    let mut vm_b = compile_vm(&auth);
    let policy_b = bind_policy(&auth, &mut vm_b);
    let (code_b, verifier_b) = ready_pair(&auth, &mut vm_b, &policy_b, &browser);
    let writer_generation = captured_generation(&mut vm_b, &policy_b, &code_b, &verifier_b);
    assert_eq!(writer_generation, 4);
    assert_eq!(
        captured_generation(&mut vm_b, &policy_b, &code_b, &verifier_b),
        4
    );
    let writer_slot = exchange_slot(&mut vm_b, &policy_b, "writer-b", code_b, verifier_b);
    let writer = call(
        &mut vm_b,
        "save_selected",
        &[
            policy_b.clone(),
            Value::Int(writer_generation),
            writer_slot,
            Value::string("preserve"),
        ],
    );
    assert_eq!(
        field(&writer, "ok"),
        Value::Bool(true),
        "writer result: {writer:?}"
    );
    let writer_value = field(&writer, "value");
    assert_eq!(field(&writer_value, "outcome"), Value::string("committed"));
    assert_eq!(
        field(&field(&writer_value, "metadata"), "generation"),
        Value::Int(5)
    );

    let captured_a = captured_generation(&mut vm_a, &policy_a, &code_a, &verifier_a);
    let old_flow_slot = exchange_slot(&mut vm_a, &policy_a, "old-a", code_a, verifier_a);
    let adopted = call(
        &mut vm_a,
        "save_selected",
        &[
            policy_a.clone(),
            Value::Int(captured_a),
            old_flow_slot,
            Value::string("preserve"),
        ],
    );
    assert_eq!(
        field(&adopted, "ok"),
        Value::Bool(true),
        "captured save: {adopted:?}"
    );
    let adopted_value = field(&adopted, "value");
    assert_eq!(field(&adopted_value, "outcome"), Value::string("adopted"));
    assert_eq!(
        field(&field(&adopted_value, "metadata"), "generation"),
        Value::Int(5)
    );
    let _ = call(&mut vm_a, "cleanup", std::slice::from_ref(&policy_a));

    let metadata = AuthStore::from_home(&home.0)
        .expect("open private store")
        .load_metadata(CREDENTIAL_ID)
        .expect("read actual stored metadata");
    assert_eq!(metadata.generation, 5);
    let persisted = fs::read_to_string(home.0.join("auth.yaml")).expect("read private auth bytes");
    assert!(
        persisted.contains(WRITER_ACCESS),
        "independent writer's credential must remain persisted"
    );
    assert!(
        !persisted.contains(OLD_FLOW_ACCESS),
        "old flow must not overwrite newer credentials"
    );
    assert_eq!(transport.calls(), 2);
    assert_eq!(vm_a.host_context().resource_count(), 2);
    assert_eq!(vm_b.host_context().resource_count(), 2);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
}

#[test]
fn native_first_enrollment_captures_zero_and_commits_generation_one() {
    let home = TempHome::from_fixture("native-first-enrollment");
    fs::write(home.0.join("auth.yaml"), "version: 1\ncredentials: {}\n")
        .expect("create empty private auth store");
    let browser = Arc::new(LoopbackBrowser::new());
    let transport = Arc::new(SyntheticTransport::new());
    let auth = native_enrollment_auth(
        &home,
        browser.clone(),
        transport.clone(),
        Arc::new(TestClock {
            started: Instant::now(),
        }),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    );
    let mut vm = compile_vm(&auth);
    let policy = bind_policy(&auth, &mut vm);
    let (code, verifier) = ready_pair(&auth, &mut vm, &policy, &browser);
    assert_eq!(captured_generation(&mut vm, &policy, &code, &verifier), 0);
    assert_eq!(captured_generation(&mut vm, &policy, &code, &verifier), 0);

    let access_slot = exchange_slot(&mut vm, &policy, "first-enrollment", code, verifier);
    let saved = call(
        &mut vm,
        "save_selected",
        &[
            policy.clone(),
            Value::Int(0),
            access_slot,
            Value::string("clear"),
        ],
    );
    assert_eq!(
        field(&saved, "ok"),
        Value::Bool(true),
        "first enrollment save: {saved:?}"
    );
    let saved_value = field(&saved, "value");
    assert_eq!(field(&saved_value, "outcome"), Value::string("committed"));
    assert_eq!(
        field(&field(&saved_value, "metadata"), "generation"),
        Value::Int(1)
    );
    let metadata = AuthStore::from_home(&home.0)
        .expect("open newly enrolled store")
        .load_metadata(CREDENTIAL_ID)
        .expect("read enrolled metadata");
    assert_eq!(metadata.generation, 1);
    assert!(
        fs::read_to_string(home.0.join("auth.yaml"))
            .expect("read private enrollment file")
            .contains(OLD_FLOW_ACCESS)
    );
    assert_eq!(transport.calls(), 1);
    let _ = call(&mut vm, "cleanup", std::slice::from_ref(&policy));
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn same_owner_mismatched_pair_rejects_without_revoking_either_family() {
    let home = TempHome::from_fixture("same-owner-family-security");
    let browser = Arc::new(LoopbackBrowser::new());
    let transport = Arc::new(SyntheticTransport::new());
    let auth = native_auth(&home, browser.clone(), transport.clone());
    let mut vm = compile_vm(&auth);
    let policy = bind_policy(&auth, &mut vm);
    let (code_a, verifier_a) = ready_pair(&auth, &mut vm, &policy, &browser);
    let (code_b, verifier_b) = ready_pair(&auth, &mut vm, &policy, &browser);

    let mismatched = call(
        &mut vm,
        "selected_generation",
        &[policy.clone(), code_a.clone(), verifier_b.clone()],
    );
    assert_eq!(field(&mismatched, "ok"), Value::Bool(false));
    assert_eq!(
        field(&field(&mismatched, "error"), "code"),
        Value::string("handle_provenance")
    );
    assert_eq!(
        captured_generation(&mut vm, &policy, &code_a, &verifier_a),
        4
    );
    assert_eq!(
        captured_generation(&mut vm, &policy, &code_b, &verifier_b),
        4
    );

    let access_slot = exchange_slot(
        &mut vm,
        &policy,
        "single-send",
        code_a.clone(),
        verifier_a.clone(),
    );
    assert!(matches!(access_slot, Value::Int(_)));
    assert_eq!(transport.calls(), 1);
    assert_eq!(
        captured_generation(&mut vm, &policy, &code_b, &verifier_b),
        4
    );
    let replay = call_result(
        &mut vm,
        "exchange_for_save",
        &[public_request(policy.clone(), "replay"), code_a, verifier_a],
    );
    match replay {
        Err(_) => {}
        Ok(result) => assert_eq!(
            field(&result, "ok"),
            Value::Bool(false),
            "exchange replay: {result:?}"
        ),
    }
    assert_eq!(
        transport.calls(),
        1,
        "closed family must not reach transport"
    );
    let _ = call(&mut vm, "cleanup", std::slice::from_ref(&policy));
    assert_eq!(vm.host_context().resource_count(), 2);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
}

#[test]
fn foreign_vm_cannot_read_or_consume_another_owners_pair() {
    let home = TempHome::from_fixture("foreign-owner-family-security");
    let browser = Arc::new(LoopbackBrowser::new());
    let transport = Arc::new(SyntheticTransport::new());
    let auth = native_auth(&home, browser.clone(), transport.clone());
    let mut vm_a = compile_vm(&auth);
    let policy_a = bind_policy(&auth, &mut vm_a);
    let (code_a, verifier_a) = ready_pair(&auth, &mut vm_a, &policy_a, &browser);

    let mut vm_b = compile_vm(&auth);
    let _policy_b = bind_policy(&auth, &mut vm_b);
    let foreign = call_result(
        &mut vm_b,
        "selected_generation",
        &[_policy_b.clone(), code_a.clone(), verifier_a.clone()],
    );
    assert!(
        foreign.is_err(),
        "foreign arena resource must fail at VM/native boundary"
    );
    assert_eq!(transport.calls(), 0);
    assert_eq!(
        captured_generation(&mut vm_a, &policy_a, &code_a, &verifier_a),
        4
    );
    let access_slot = exchange_slot(&mut vm_a, &policy_a, "owner-a", code_a, verifier_a);
    assert!(matches!(access_slot, Value::Int(_)));
    assert_eq!(transport.calls(), 1);
    let _ = call(&mut vm_a, "cleanup", std::slice::from_ref(&policy_a));
    assert_eq!(vm_a.host_context().resource_count(), 2);
}

#[test]
fn owner_cancellation_rolls_back_captured_family() {
    let home = TempHome::from_fixture("owner-cancellation-family-security");
    let browser = Arc::new(LoopbackBrowser::new());
    let transport = Arc::new(SyntheticTransport::new());
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let auth = native_auth_with_cancellation(
        &home,
        browser.clone(),
        transport.clone(),
        Arc::new(TestClock {
            started: Instant::now(),
        }),
        cancellation.clone(),
    );
    let mut vm = compile_vm(&auth);
    let policy = bind_policy(&auth, &mut vm);
    let (code, verifier) = ready_pair(&auth, &mut vm, &policy, &browser);
    cancellation.request(CancellationReason::Requested);

    let result = call(
        &mut vm,
        "selected_generation",
        &[policy.clone(), code, verifier],
    );
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    let failure = field(&result, "error");
    assert_eq!(field(&failure, "code"), Value::string("policy_inactive"));
    assert_eq!(field(&failure, "cancelled"), Value::Bool(true));
    assert_eq!(transport.calls(), 0);
    assert_eq!(vm.host_context().resource_count(), 2);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
}

#[test]
fn oauth_clock_expiry_rolls_back_captured_family() {
    let home = TempHome::from_fixture("oauth-clock-expiry-family-security");
    let browser = Arc::new(LoopbackBrowser::new());
    let transport = Arc::new(SyntheticTransport::new());
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let auth = native_auth_with_cancellation(
        &home,
        browser.clone(),
        transport.clone(),
        clock.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    );
    let mut vm = compile_vm(&auth);
    let policy = bind_policy(&auth, &mut vm);
    let (code, verifier) = ready_pair(&auth, &mut vm, &policy, &browser);
    clock.expire();

    let result = call(
        &mut vm,
        "selected_generation",
        &[policy.clone(), code, verifier],
    );
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_eq!(
        field(&field(&result, "error"), "code"),
        Value::string("handle_expired")
    );
    assert_eq!(transport.calls(), 0);
    assert_eq!(vm.host_context().resource_count(), 2);
    #[cfg(feature = "config-fixture")]
    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("native flow count"),
        0
    );
}
