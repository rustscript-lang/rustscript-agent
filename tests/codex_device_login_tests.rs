use rustscript_agent::{
    CancellationReason, RunCancellation,
    auth::{
        host::{AuthHost, auth_host_catalog},
        oauth::{
            OAuthClock, OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel,
            ScriptedClock, ScriptedHttpsTransport,
        },
        store::{AuthMetadata, AuthStore},
    },
};
use rustscript_vm::{
    CallOutcome, CallReturn, CompileSourceFileOptions, HostApiBuilder, HostFunctionRegistry,
    HostFunctionSchema, HostParamSchema, HostTypeSchema, SourceFlavor, Value, Vm, VmStatus,
    catalog_import_schemas, compile_source_at_path_with_flavor_and_options,
};
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const CREDENTIAL_ID: &str = "fixture-codex";
const DEVICE_SECRET: &str = "NATIVE_DEVICE_PRIVATE_028c";
const CODE_SECRET: &str = "NATIVE_CODE_PRIVATE_1d9a";
const VERIFIER_SECRET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
const ACCESS_SECRET: &str = "NATIVE_ACCESS_PRIVATE_773e";
const REFRESH_SECRET: &str = "NATIVE_REFRESH_PRIVATE_8ab2";
const START_MS: u64 = 1_900_000_000_000;

#[derive(Default)]
struct InstructionLog {
    events: Mutex<Vec<Value>>,
    cancel_after_instruction: Mutex<Option<RunCancellation>>,
}

fn record(fields: Vec<(&str, Value)>) -> Value {
    Value::map(
        fields
            .into_iter()
            .map(|(name, value)| (Value::string(name), value))
            .collect(),
    )
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(fields) = value else {
        panic!("expected RSS record: {value:?}")
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn replace_field(value: &Value, name: &str, replacement: Value) -> Value {
    let Value::Map(fields) = value else {
        panic!("expected RSS record")
    };
    let mut found = false;
    let entries = fields
        .iter()
        .map(|(key, value)| {
            if matches!(key, Value::String(key) if key.as_ref() == name) {
                found = true;
                (key.clone(), replacement.clone())
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect::<Vec<_>>();
    assert!(found, "typed field exists");
    Value::map(entries)
}

fn emit_instruction(vm: &mut Vm, args: &[Value]) -> rustscript_vm::VmResult<CallOutcome> {
    let verification_url = args
        .first()
        .cloned()
        .ok_or_else(|| rustscript_vm::VmError::HostError("invalid_request".into()))?;
    let user_code = args
        .get(1)
        .cloned()
        .ok_or_else(|| rustscript_vm::VmError::HostError("invalid_request".into()))?;
    let expires_in_seconds = args
        .get(2)
        .cloned()
        .ok_or_else(|| rustscript_vm::VmError::HostError("invalid_request".into()))?;
    let context = vm.host_context();
    let log = context
        .module_state::<InstructionLog>()
        .expect("instruction state");
    log.events
        .lock()
        .expect("instruction log")
        .push(record(vec![
            ("verification_url", verification_url),
            ("user_code", user_code),
            ("expires_in_seconds", expires_in_seconds),
        ]));
    let cancellation = log
        .cancel_after_instruction
        .lock()
        .expect("cancel hook")
        .take();
    if let Some(cancellation) = cancellation {
        cancellation.request(CancellationReason::Requested);
    }
    Ok(CallOutcome::Return(CallReturn::One(Value::Null)))
}

fn fixture_catalog() -> Arc<rustscript_vm::HostApiCatalog> {
    let base = auth_host_catalog();
    let mut builder = HostApiBuilder::new();
    for resource in base.resources() {
        builder.resource(resource.clone());
    }
    for named in base.structs() {
        builder.named_struct(named.clone());
    }
    for function in base.functions() {
        builder.function(function.clone());
    }
    builder.function(HostFunctionSchema::with_return(
        "test::emit_instruction",
        vec![
            HostParamSchema::value("verification_url", HostTypeSchema::String),
            HostParamSchema::value("user_code", HostTypeSchema::String),
            HostParamSchema::value("expires_in_seconds", HostTypeSchema::Int),
        ],
        HostTypeSchema::Null,
    ));
    Arc::new(builder.build().expect("test catalog"))
}

struct FixtureHome(PathBuf);
impl FixtureHome {
    fn new() -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test TEMP"));
        fs::create_dir_all(&root).expect("assigned TEMP exists");
        let path = root.join(format!("codex-device-native-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).expect("private auth home");
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/codex_device/config.yaml");
        fs::copy(fixture, path.join("config.yaml")).expect("copy synthetic config");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("home mode");
            fs::set_permissions(path.join("config.yaml"), fs::Permissions::from_mode(0o600))
                .expect("config mode");
        }
        Self(path)
    }
}
impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn compiled_vm(auth: &AuthHost) -> Vm {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/codex_device/native_entry.rss");
    let source = fs::read_to_string(&path).expect("native entry fixture");
    let catalog = fixture_catalog();
    let compiled = compile_source_at_path_with_flavor_and_options(
        &path,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
    )
    .expect("compile native RSS wrapper against exact auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    auth.register(&mut registry, catalog.as_ref())
        .expect("register native auth catalog");
    for schema in catalog_import_schemas(catalog.as_ref(), "test::emit_instruction") {
        registry
            .register_exact_static("test::emit_instruction", 3, schema, emit_instruction)
            .expect("typed callback adapter");
    }
    registry.authorize_registered_builtin_import("test::emit_instruction");
    registry
        .allow_builtin("json::encode")
        .expect("authorize RSS JSON encoding");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted registry");
    vm.host_context()
        .set_module_state(InstructionLog::default());
    assert!(matches!(vm.run().expect("RSS entry"), VmStatus::Halted));
    vm
}

struct NativeFixture {
    home: FixtureHome,
    config_before: Vec<u8>,
    transport: Arc<ScriptedHttpsTransport>,
    auth: AuthHost,
    cancellation: RunCancellation,
    vm: Vm,
    policy: Value,
    provider: Value,
}

impl NativeFixture {
    fn new() -> Self {
        Self::with_clock(Arc::new(ScriptedClock::new(START_MS)))
    }

    fn with_clock(clock: Arc<dyn OAuthClock>) -> Self {
        let home = FixtureHome::new();
        let config_before = fs::read(home.0.join("config.yaml")).expect("config bytes");
        let transport = Arc::new(ScriptedHttpsTransport::new());
        let oauth = Arc::new(OAuthHost::new(
            transport.clone(),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            clock,
            Arc::new(ScriptedCancel::new()),
        ));
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let auth =
            AuthHost::new_for_enrollment(home.0.clone(), cancellation.clone(), CREDENTIAL_ID)
                .expect("admit selected enrollment")
                .with_oauth_host(oauth);
        let mut vm = compiled_vm(&auth);
        let owner = auth.bind_vm(&mut vm).expect("bind owner");
        let snapshot_fn = vm
            .resolve_exported_callable("snapshot")
            .expect("snapshot function");
        let snapshot = vm
            .invoke_callable(snapshot_fn, &[field(&owner, "host_home")])
            .expect("load config");
        let policy = field(&snapshot, "policy_handle");
        let providers = field(&field(&snapshot, "public_config"), "providers");
        let Value::Array(providers) = providers else {
            panic!("provider array")
        };
        let provider = providers.first().expect("Codex provider").clone();
        Self {
            home,
            config_before,
            transport,
            auth,
            cancellation,
            vm,
            policy,
            provider,
        }
    }

    fn rebind(&mut self) {
        let oauth = Arc::new(OAuthHost::new(
            self.transport.clone(),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(START_MS)),
            Arc::new(ScriptedCancel::new()),
        ));
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let auth =
            AuthHost::new_for_enrollment(self.home.0.clone(), cancellation.clone(), CREDENTIAL_ID)
                .expect("admit refreshed credential snapshot")
                .with_oauth_host(oauth);
        let mut vm = compiled_vm(&auth);
        let owner = auth.bind_vm(&mut vm).expect("bind refreshed owner");
        let snapshot_fn = vm
            .resolve_exported_callable("snapshot")
            .expect("snapshot function");
        let snapshot = vm
            .invoke_callable(snapshot_fn, &[field(&owner, "host_home")])
            .expect("reload config");
        let policy = field(&snapshot, "policy_handle");
        let providers = field(&field(&snapshot, "public_config"), "providers");
        let Value::Array(providers) = providers else {
            panic!("provider array")
        };
        let provider = providers.first().expect("Codex provider").clone();
        self.cancellation = cancellation;
        self.auth = auth;
        self.vm = vm;
        self.policy = policy;
        self.provider = provider;
    }

    fn login(&mut self, expected_generation: i64) -> Value {
        let provider = self.provider.clone();
        self.login_with_provider(expected_generation, provider)
    }

    fn login_with_provider(&mut self, expected_generation: i64, provider: Value) -> Value {
        let run = self
            .vm
            .resolve_exported_callable("run")
            .expect("native RSS wrapper");
        self.vm
            .invoke_callable(
                run,
                &[
                    self.policy.clone(),
                    provider,
                    Value::string(CREDENTIAL_ID),
                    Value::Int(expected_generation),
                ],
            )
            .unwrap_or_else(|error| panic!("{}", rustscript_vm::render_vm_error(&self.vm, &error)))
    }

    fn events(&mut self) -> Vec<Value> {
        let context = self.vm.host_context();
        let log = context
            .module_state::<InstructionLog>()
            .expect("callback log");
        log.events.lock().expect("callback events").clone()
    }

    fn cancel_after_instruction(&mut self) {
        let cancellation = self.cancellation.clone();
        let context = self.vm.host_context();
        let log = context
            .module_state::<InstructionLog>()
            .expect("callback log");
        *log.cancel_after_instruction.lock().expect("cancel hook") = Some(cancellation);
    }

    fn assert_clean(&mut self) {
        let _ = &self.auth;
        assert_eq!(
            self.vm.host_context().resource_count(),
            2,
            "terminal cleanup retains only bound roots"
        );
        #[cfg(feature = "config-fixture")]
        assert_eq!(
            self.auth
                .fixture_live_oauth_flow_count()
                .expect("native flow count"),
            0,
            "terminal cleanup removes OAuth flows"
        );
    }

    fn stored_metadata(&self) -> Option<AuthMetadata> {
        AuthStore::from_home(&self.home.0)
            .ok()?
            .load_metadata(CREDENTIAL_ID)
            .ok()
    }

    fn auth_bytes(&self) -> Option<Vec<u8>> {
        fs::read(self.home.0.join("auth.yaml")).ok()
    }

    fn assert_config_unchanged(&self) {
        assert!(
            fs::read(self.home.0.join("config.yaml"))
                .is_ok_and(|bytes| bytes == self.config_before),
            "public config bytes remain unchanged"
        );
    }
}

struct OffsetAfterFirstClock {
    base_ms: u64,
    reads: AtomicUsize,
}
impl OffsetAfterFirstClock {
    fn new(base_ms: u64) -> Self {
        Self {
            base_ms,
            reads: AtomicUsize::new(0),
        }
    }
}
impl OAuthClock for OffsetAfterFirstClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn unix_ms(&self) -> u64 {
        if self.reads.fetch_add(1, Ordering::Relaxed) == 0 {
            self.base_ms
        } else {
            self.base_ms + 120_000
        }
    }
}

struct SequenceClock {
    values: Vec<u64>,
    reads: AtomicUsize,
}
impl SequenceClock {
    fn new(values: Vec<u64>) -> Self {
        Self {
            values,
            reads: AtomicUsize::new(0),
        }
    }
}
impl OAuthClock for SequenceClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn unix_ms(&self) -> u64 {
        let index = self.reads.fetch_add(1, Ordering::Relaxed);
        self.values
            .get(index)
            .copied()
            .unwrap_or_else(|| *self.values.last().expect("clock values"))
    }
}

fn queue_login(transport: &ScriptedHttpsTransport, refresh_token: Option<&str>) {
    transport.push_raw(200, &format!(r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"SYNTHETIC-CODE-74","expires_in":900,"interval":"0"}}"#));
    transport.push_raw(200, &format!(r#"{{"authorization_code":"{CODE_SECRET}","code_verifier":"{VERIFIER_SECRET}","public":"poll-ok"}}"#));
    let refresh = refresh_token
        .map(|value| format!(",\"refresh_token\":\"{}\"", value))
        .unwrap_or_default();
    transport.push_raw(200, &format!(r#"{{"access_token":"{ACCESS_SECRET}"{refresh},"token_type":"Bearer","expires_in":3600,"public":"exchange-ok"}}"#));
}

fn assert_no_private_material(value: &Value) {
    let rendered = format!("{value:?}");
    for secret in [
        DEVICE_SECRET,
        CODE_SECRET,
        VERIFIER_SECRET,
        ACCESS_SECRET,
        REFRESH_SECRET,
    ] {
        assert!(
            !rendered.contains(secret),
            "private material stays out of RSS results and callback events"
        );
    }
}

#[test]
fn actual_rss_login_enrolls_saves_and_reloads_native_credentials() {
    let mut fixture = NativeFixture::new();
    queue_login(&fixture.transport, Some(REFRESH_SECRET));
    let result = fixture.login(0);
    let sent = fixture.transport.take_sent();
    assert_eq!(
        field(&result, "ok"),
        Value::Bool(true),
        "RSS terminal code: {:?}; transport requests: {}",
        field(&result, "code"),
        sent.len()
    );
    assert_eq!(field(&result, "code"), Value::string("ok"));
    let metadata = field(&result, "metadata");
    assert_eq!(field(&metadata, "ok"), Value::Bool(true));
    assert_eq!(
        field(&field(&metadata, "metadata"), "generation"),
        Value::Int(1)
    );
    assert_eq!(
        field(&field(&metadata, "metadata"), "has_refresh_token"),
        Value::Bool(true)
    );
    let events = fixture.events();
    assert_eq!(events.len(), 1);
    assert_eq!(
        field(&events[0], "user_code"),
        Value::string("SYNTHETIC-CODE-74")
    );
    assert_eq!(
        field(&events[0], "verification_url"),
        Value::string("https://auth.example.test/codex/device")
    );

    assert_eq!(sent.len(), 3);
    assert_eq!(
        sent[0].url,
        "https://auth.example.test/api/accounts/deviceauth/usercode"
    );
    assert_eq!(sent[0].method, "POST");
    assert_eq!(
        sent[0].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&sent[0].body).expect("start body"),
        serde_json::json!({"client_id":"synthetic-public-client"})
    );
    assert_eq!(
        sent[1].url,
        "https://auth.example.test/api/accounts/deviceauth/token"
    );
    assert_eq!(sent[1].method, "POST");
    assert_eq!(
        sent[1].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    let poll: serde_json::Value = serde_json::from_str(&sent[1].body).expect("poll body");
    assert!(
        poll["user_code"] == "SYNTHETIC-CODE-74" && poll["device_auth_id"] == DEVICE_SECRET,
        "poll wire contains public code and host-injected device id"
    );
    assert_eq!(sent[2].url, "https://auth.example.test/oauth/token");
    assert_eq!(sent[2].method, "POST");
    assert_eq!(
        sent[2].headers.get("content-type").map(String::as_str),
        Some("application/x-www-form-urlencoded")
    );
    let form: std::collections::BTreeMap<String, String> =
        url::form_urlencoded::parse(sent[2].body.as_bytes())
            .into_owned()
            .collect();
    assert!(
        form.get("grant_type")
            .is_some_and(|value| value == "authorization_code")
    );
    assert!(
        form.get("client_id")
            .is_some_and(|value| value == "synthetic-public-client")
    );
    assert!(form.get("code").is_some_and(|value| value == CODE_SECRET));
    assert!(
        form.get("code_verifier")
            .is_some_and(|value| value == VERIFIER_SECRET)
    );
    assert!(
        form.get("redirect_uri")
            .is_some_and(|value| value == "https://auth.example.test/deviceauth/callback")
    );
    assert_no_private_material(&result);
    for event in &events {
        assert_no_private_material(event);
    }
    fixture.assert_clean();
    let stored = fixture.stored_metadata().expect("reload saved metadata");
    assert_eq!(stored.generation, 1);
    assert_eq!(stored.provider, "openai-codex");
    assert!(stored.has_refresh_token);
    fixture.assert_config_unchanged();
}

#[test]
fn native_update_clears_absent_refresh_and_cas_adopts_the_winner() {
    let mut fixture = NativeFixture::new();
    queue_login(&fixture.transport, Some(REFRESH_SECRET));
    let first = fixture.login(0);
    assert_eq!(field(&first, "ok"), Value::Bool(true));
    let first_metadata = fixture.stored_metadata().expect("first persistence");
    assert_eq!(first_metadata.generation, 1);
    assert!(first_metadata.has_refresh_token);
    fixture.assert_clean();
    fixture.transport.take_sent();

    let winner_bytes = fixture.auth_bytes().expect("winner auth bytes");
    queue_login(&fixture.transport, None);
    let rejected = fixture.login(1);
    assert_eq!(field(&rejected, "ok"), Value::Bool(false));
    assert_eq!(field(&rejected, "code"), Value::string("save_failed"));
    assert_eq!(
        fixture.transport.take_sent().len(),
        3,
        "rejected save occurs after one exchange"
    );
    assert!(
        fixture
            .auth_bytes()
            .is_some_and(|after| after == winner_bytes),
        "rejected save preserves winner bytes"
    );
    assert_eq!(
        fixture.stored_metadata().expect("winner after rejection"),
        first_metadata
    );
    fixture.assert_clean();

    queue_login(&fixture.transport, None);
    let adopted = fixture.login(0);
    assert_eq!(
        field(&adopted, "ok"),
        Value::Bool(true),
        "stale candidate adopts the committed winner"
    );
    let adopted_metadata = field(&field(&adopted, "metadata"), "metadata");
    assert_eq!(field(&adopted_metadata, "generation"), Value::Int(1));
    assert_eq!(
        field(&adopted_metadata, "has_refresh_token"),
        Value::Bool(true)
    );
    assert!(
        fixture
            .auth_bytes()
            .is_some_and(|after| after == winner_bytes),
        "CAS adoption preserves winner bytes"
    );
    assert_eq!(
        fixture.stored_metadata().expect("winner reload").generation,
        1
    );
    fixture.assert_clean();

    fixture.rebind();
    queue_login(&fixture.transport, None);
    let second = fixture.login(1);
    assert_eq!(
        field(&second, "ok"),
        Value::Bool(true),
        "generation update result code: {:?}",
        field(&second, "code")
    );
    let updated_metadata = field(&field(&second, "metadata"), "metadata");
    assert_eq!(field(&updated_metadata, "generation"), Value::Int(2));
    assert_eq!(
        field(&updated_metadata, "has_refresh_token"),
        Value::Bool(false)
    );
    let updated = fixture.stored_metadata().expect("updated metadata");
    assert_eq!(updated.generation, 2);
    assert!(!updated.has_refresh_token);
    fixture.assert_clean();
    assert_no_private_material(&first);
    assert_no_private_material(&adopted);
    assert_no_private_material(&second);
    fixture.assert_config_unchanged();
}

#[test]
fn malformed_native_start_cleans_device_resource_without_poll_or_save() {
    let mut fixture = NativeFixture::new();
    fixture.transport.push_raw(
        200,
        &format!(r#"{{"device_auth_id":"{DEVICE_SECRET}","interval":"5"}}"#),
    );
    let result = fixture.login(0);
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_eq!(
        field(&result, "code"),
        Value::string("invalid_start_response")
    );
    assert!(fixture.events().is_empty());
    assert_eq!(fixture.transport.take_sent().len(), 1);
    assert!(
        fixture.stored_metadata().is_none(),
        "malformed start does not persist credentials"
    );
    fixture.assert_clean();
    assert_no_private_material(&result);
}

#[test]
fn malformed_interval_stops_before_instruction_or_poll() {
    let mut fixture = NativeFixture::new();
    fixture.transport.push_raw(
        200,
        &format!(r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"SYNTHETIC-CODE-74","interval":" 05 "}}"#),
    );
    let result = fixture.login(0);
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_eq!(
        field(&result, "code"),
        Value::string("invalid_start_response")
    );
    assert!(fixture.events().is_empty());
    assert_eq!(fixture.transport.take_sent().len(), 1);
    assert!(fixture.stored_metadata().is_none());
    fixture.assert_clean();
    assert_no_private_material(&result);
}

#[test]
fn malformed_native_capture_cleans_pair_without_exchange_or_save() {
    let mut fixture = NativeFixture::new();
    fixture.transport.push_raw(200, &format!(r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"SYNTHETIC-CODE-74","interval":"0"}}"#));
    fixture.transport.push_raw(
        200,
        &format!(r#"{{"authorization_code":"{CODE_SECRET}","public":"missing-verifier"}}"#),
    );
    let result = fixture.login(0);
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_eq!(
        field(&result, "code"),
        Value::string("poll_transport_failed")
    );
    assert_eq!(fixture.events().len(), 1);
    assert_eq!(fixture.transport.take_sent().len(), 2);
    assert!(
        fixture.stored_metadata().is_none(),
        "malformed capture does not persist credentials"
    );
    fixture.assert_clean();
    assert_no_private_material(&result);
}

#[test]
fn native_exchange_rejection_and_missing_access_never_persist() {
    let mut fixture = NativeFixture::new();
    fixture.transport.push_raw(200, &format!(r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"SYNTHETIC-CODE-74","interval":"0"}}"#));
    fixture.transport.push_raw(
        200,
        &format!(r#"{{"authorization_code":"{CODE_SECRET}","code_verifier":"{VERIFIER_SECRET}"}}"#),
    );
    fixture
        .transport
        .push_raw(400, r#"{"error":"PRIVATE_PROVIDER_ERROR_TEXT"}"#);
    let rejected = fixture.login(0);
    assert_eq!(field(&rejected, "ok"), Value::Bool(false));
    assert_eq!(field(&rejected, "code"), Value::string("exchange_rejected"));
    assert_eq!(fixture.transport.take_sent().len(), 3);
    assert!(
        fixture.stored_metadata().is_none(),
        "rejected exchange does not persist credentials"
    );
    fixture.assert_clean();
    assert_no_private_material(&rejected);

    fixture.transport.push_raw(
        200,
        &format!(r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"SYNTHETIC-CODE-74","interval":"0"}}"#),
    );
    fixture.transport.push_raw(
        200,
        &format!(r#"{{"authorization_code":"{CODE_SECRET}","code_verifier":"{VERIFIER_SECRET}"}}"#),
    );
    fixture.transport.push_raw(200, "not-json");
    let malformed_exchange = fixture.login(0);
    assert_eq!(field(&malformed_exchange, "ok"), Value::Bool(false));
    assert_eq!(
        field(&malformed_exchange, "code"),
        Value::string("exchange_transport_failed")
    );
    assert_eq!(fixture.transport.take_sent().len(), 3);
    assert!(
        fixture.stored_metadata().is_none(),
        "malformed exchange does not persist credentials"
    );
    fixture.assert_clean();
    assert_no_private_material(&malformed_exchange);

    fixture.transport.push_raw(200, &format!(r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"SYNTHETIC-CODE-74","interval":"0"}}"#));
    fixture.transport.push_raw(
        200,
        &format!(r#"{{"authorization_code":"{CODE_SECRET}","code_verifier":"{VERIFIER_SECRET}"}}"#),
    );
    fixture.transport.push_raw(
        200,
        &format!(
            r#"{{"refresh_token":"{REFRESH_SECRET}","expires_in":3600,"public":"no-access-slot"}}"#
        ),
    );
    let missing_access = fixture.login(0);
    assert_eq!(field(&missing_access, "ok"), Value::Bool(false));
    assert_eq!(
        field(&missing_access, "code"),
        Value::string("invalid_token_response")
    );
    assert_eq!(fixture.transport.take_sent().len(), 3);
    assert!(
        fixture.stored_metadata().is_none(),
        "missing access slot does not persist credentials"
    );
    fixture.assert_clean();
    assert_no_private_material(&missing_access);

    fixture.transport.push_raw(200, &format!(r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"SYNTHETIC-CODE-74","interval":"0"}}"#));
    fixture.transport.push_raw(
        200,
        &format!(r#"{{"authorization_code":"{CODE_SECRET}","code_verifier":"{VERIFIER_SECRET}"}}"#),
    );
    fixture.transport.push_raw(
        200,
        &format!(r#"{{"access_token":"{ACCESS_SECRET}","expires_in":0}}"#),
    );
    let invalid_expiry = fixture.login(0);
    assert_eq!(field(&invalid_expiry, "ok"), Value::Bool(false));
    assert_eq!(
        field(&invalid_expiry, "code"),
        Value::string("invalid_token_response")
    );
    assert_eq!(fixture.transport.take_sent().len(), 3);
    assert!(
        fixture.stored_metadata().is_none(),
        "invalid token expiry does not persist credentials"
    );
    fixture.assert_clean();
    assert_no_private_material(&invalid_expiry);
    fixture.assert_config_unchanged();
}

#[test]
fn native_owner_cancellation_after_instruction_cleans_device_flow() {
    let mut fixture = NativeFixture::new();
    fixture.cancel_after_instruction();
    fixture.transport.push_raw(200, &format!(r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"SYNTHETIC-CODE-74","interval":"0"}}"#));
    let result = fixture.login(0);
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_eq!(
        field(&result, "code"),
        Value::string("cancelled_or_inactive")
    );
    assert_eq!(fixture.events().len(), 1);
    assert_eq!(
        fixture.transport.take_sent().len(),
        1,
        "cancelled owner sends no poll request"
    );
    assert!(
        fixture.stored_metadata().is_none(),
        "cancelled owner does not persist credentials"
    );
    fixture.assert_clean();
    assert_no_private_material(&result);
}

#[test]
fn native_429_retries_before_single_exchange() {
    let mut fixture = NativeFixture::new();
    fixture.transport.push_json(
        200,
        serde_json::json!({
            "device_auth_id": DEVICE_SECRET,
            "user_code": "SYNTHETIC-CODE-74",
            "interval": "0"
        }),
    );
    fixture
        .transport
        .push_raw(429, r#"{"error":"rate-limited"}"#);
    fixture.transport.push_json(
        200,
        serde_json::json!({
            "authorization_code": CODE_SECRET,
            "code_verifier": VERIFIER_SECRET
        }),
    );
    fixture.transport.push_json(
        200,
        serde_json::json!({
            "access_token": ACCESS_SECRET,
            "expires_in": 3600
        }),
    );
    let result = fixture.login(0);
    assert_eq!(field(&result, "ok"), Value::Bool(true));
    let sent = fixture.transport.take_sent();
    assert_eq!(sent.len(), 4, "one 429 retry precedes one exchange");
    assert!(sent[1..3].iter().all(|request| request.url == "https://auth.example.test/api/accounts/deviceauth/token"));
    assert_eq!(sent[3].url, "https://auth.example.test/oauth/token");
    assert_eq!(fixture.events().len(), 1);
    assert!(fixture.stored_metadata().is_some());
    fixture.assert_clean();
    assert_no_private_material(&result);
}

#[test]
fn native_403_and_404_are_pending_before_successful_exchange() {
    let mut fixture = NativeFixture::new();
    fixture.transport.push_json(
        200,
        serde_json::json!({
            "device_auth_id": DEVICE_SECRET,
            "user_code": "SYNTHETIC-CODE-74",
            "interval": "0"
        }),
    );
    fixture
        .transport
        .push_raw(403, r#"{"error":"pending-forbidden"}"#);
    fixture
        .transport
        .push_raw(404, r#"{"error":"pending-not-found"}"#);
    fixture.transport.push_json(
        200,
        serde_json::json!({
            "authorization_code": CODE_SECRET,
            "code_verifier": VERIFIER_SECRET
        }),
    );
    fixture.transport.push_json(
        200,
        serde_json::json!({
            "access_token": ACCESS_SECRET,
            "expires_in": 3600
        }),
    );
    let result = fixture.login(0);
    assert_eq!(field(&result, "ok"), Value::Bool(true));
    assert_eq!(
        field(
            &field(&field(&result, "metadata"), "metadata"),
            "generation"
        ),
        Value::Int(1)
    );
    assert_eq!(
        field(
            &field(&field(&result, "metadata"), "metadata"),
            "has_refresh_token"
        ),
        Value::Bool(false)
    );
    let sent = fixture.transport.take_sent();
    assert_eq!(
        sent.len(),
        5,
        "two pending replies are followed by a third poll and one exchange"
    );
    assert_eq!(
        sent[0].url,
        "https://auth.example.test/api/accounts/deviceauth/usercode"
    );
    assert!(sent[1..4].iter().all(|request| request.url == "https://auth.example.test/api/accounts/deviceauth/token"));
    assert_eq!(sent[4].url, "https://auth.example.test/oauth/token");
    assert_eq!(fixture.events().len(), 1);
    fixture.assert_clean();
    assert_no_private_material(&result);
}

#[test]
fn token_endpoint_origin_mismatch_fails_before_native_transport() {
    let mut fixture = NativeFixture::new();
    let oauth = field(&fixture.provider, "oauth");
    let invalid_oauth = replace_field(
        &oauth,
        "token_endpoint",
        Value::string("https://other.example.test/oauth/token"),
    );
    let invalid_provider = replace_field(&fixture.provider, "oauth", invalid_oauth);
    let result = fixture.login_with_provider(0, invalid_provider);
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_eq!(
        field(&result, "code"),
        Value::string("invalid_provider_config")
    );
    assert!(
        fixture.transport.take_sent().is_empty(),
        "origin mismatch stops before network transport"
    );
    assert!(fixture.events().is_empty());
    assert!(fixture.stored_metadata().is_none());
    fixture.assert_clean();
    fixture.assert_config_unchanged();
}

#[test]
fn native_deadline_expires_after_start_before_instruction_or_poll() {
    let clock = Arc::new(SequenceClock::new(vec![START_MS, START_MS + 900_000]));
    let mut fixture = NativeFixture::with_clock(clock);
    fixture.transport.push_raw(
        200,
        &format!(r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"SYNTHETIC-CODE-74","interval":"0"}}"#),
    );
    let result = fixture.login(0);
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_eq!(field(&result, "code"), Value::string("timeout"));
    assert!(fixture.events().is_empty());
    assert_eq!(fixture.transport.take_sent().len(), 1);
    assert!(fixture.stored_metadata().is_none());
    fixture.assert_clean();
    assert_no_private_material(&result);
}

#[test]
fn native_backward_clock_after_poll_stops_before_exchange() {
    let clock = Arc::new(SequenceClock::new(vec![
        START_MS,
        START_MS + 1,
        START_MS + 2,
        START_MS + 100,
        START_MS + 50,
    ]));
    let mut fixture = NativeFixture::with_clock(clock);
    fixture.transport.push_raw(
        200,
        &format!(r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"SYNTHETIC-CODE-74","interval":"0"}}"#),
    );
    fixture.transport.push_raw(
        200,
        &format!(r#"{{"authorization_code":"{CODE_SECRET}","code_verifier":"{VERIFIER_SECRET}"}}"#),
    );
    let result = fixture.login(0);
    assert_eq!(field(&result, "ok"), Value::Bool(false));
    assert_eq!(field(&result, "code"), Value::string("clock_unavailable"));
    assert_eq!(fixture.events().len(), 1);
    assert_eq!(
        fixture.transport.take_sent().len(),
        2,
        "backward clock rejects before exchange"
    );
    assert!(fixture.stored_metadata().is_none());
    fixture.assert_clean();
    assert_no_private_material(&result);
}

#[test]
fn missing_start_expiry_is_bounded_by_remaining_fixed_deadline() {
    let clock = Arc::new(OffsetAfterFirstClock::new(START_MS));
    let mut fixture = NativeFixture::with_clock(clock);
    fixture.transport.push_raw(200, &format!(r#"{{"device_auth_id":"{DEVICE_SECRET}","user_code":"SYNTHETIC-CODE-74","interval":"0"}}"#));
    fixture.transport.push_raw(
        200,
        &format!(r#"{{"authorization_code":"{CODE_SECRET}","code_verifier":"{VERIFIER_SECRET}"}}"#),
    );
    fixture.transport.push_raw(
        200,
        &format!(r#"{{"access_token":"{ACCESS_SECRET}","expires_in":3600}}"#),
    );
    let result = fixture.login(0);
    assert_eq!(field(&result, "ok"), Value::Bool(true));
    let events = fixture.events();
    assert_eq!(events.len(), 1);
    assert_eq!(field(&events[0], "expires_in_seconds"), Value::Int(780));
    fixture.assert_clean();
    assert_no_private_material(&result);
}
