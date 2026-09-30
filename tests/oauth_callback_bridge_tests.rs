use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "config-fixture")]
use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

#[cfg(feature = "config-fixture")]
use rustscript_agent::auth::oauth::OAuthHost;
#[cfg(feature = "config-fixture")]
use rustscript_agent::{
    CancellationReason,
    auth::oauth::{CallbackWaiter, OAuthError, OAuthIoContext, RawCallbackInput},
};
use rustscript_agent::{
    RunCancellation,
    auth::host::{AuthHost, auth_host_catalog},
};
#[cfg(feature = "config-fixture")]
use rustscript_vm::resource::{HostResource, ResourceCloseReason, ResourceHandle};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, HostParamPassing, HostTypeSchema,
    ResourceTypeKey, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};

const SYNTHETIC_CODE: &str = "FIXTURE_CALLBACK_AUTH_CODE_9cfd";

#[cfg(feature = "config-fixture")]
struct CountingCallback {
    queued: Mutex<VecDeque<RawCallbackInput>>,
    waits: AtomicUsize,
    cancel_after_wait: Option<RunCancellation>,
}

#[cfg(feature = "config-fixture")]
impl CountingCallback {
    fn new(cancel_after_wait: Option<RunCancellation>) -> Self {
        Self {
            queued: Mutex::new(VecDeque::new()),
            waits: AtomicUsize::new(0),
            cancel_after_wait,
        }
    }

    fn wait_count(&self) -> usize {
        self.waits.load(Ordering::Acquire)
    }
}

#[cfg(feature = "config-fixture")]
impl CallbackWaiter for CountingCallback {
    fn wait_one(&self, context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
        context.check()?;
        self.waits.fetch_add(1, Ordering::AcqRel);
        let input = self
            .queued
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .unwrap_or(RawCallbackInput::Timeout);
        if let Some(cancellation) = &self.cancel_after_wait {
            cancellation.request(CancellationReason::Requested);
        }
        Ok(input)
    }

    fn inject(&self, input: RawCallbackInput) -> Result<(), OAuthError> {
        self.queued
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push_back(input);
        Ok(())
    }
}

#[cfg(feature = "config-fixture")]
struct QuotaResource;

#[cfg(feature = "config-fixture")]
impl HostResource for QuotaResource {}

#[cfg(feature = "config-fixture")]
fn fill_resource_arena(vm: &mut Vm, target: usize) -> Vec<ResourceHandle> {
    let mut handles = Vec::new();
    while vm.host_context().resource_count() < target {
        let resource = vm
            .host_context()
            .push_resource(QuotaResource)
            .expect("fill resource quota");
        handles.push(resource.handle());
    }
    handles
}

#[cfg(feature = "config-fixture")]
fn close_quota_resources(vm: &mut Vm, handles: Vec<ResourceHandle>) {
    for handle in handles {
        vm.host_context()
            .close_resource::<QuotaResource>(handle, ResourceCloseReason::Requested)
            .expect("close quota filler");
    }
}

struct TempHome(PathBuf);

impl TempHome {
    fn new(name: &str) -> Self {
        let base =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned temp"));
        let path = base.join(format!("oauth-callback-{name}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).expect("create home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), path.join("config.yaml")).expect("copy config");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read fixture auth")
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

fn contract_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
    fs::read_to_string(path).expect("real rss/auth/callback_contract.rss")
}

fn compile_contract(source: &str) -> Vm {
    let fixture_config = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let compiled = compile_source_at_path_with_flavor_and_options(
        &fixture_config,
        source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(auth_host_catalog()),
    )
    .expect("compile callback contract RSS against exact auth catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    let registration_home = TempHome::new("registration");
    let host = AuthHost::new(
        registration_home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host");
    host.register(&mut registry, auth_host_catalog().as_ref())
        .expect("register exact catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind restricted registry");
    assert!(matches!(vm.run().expect("run root"), VmStatus::Halted));
    vm
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected named result, got {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name} in {value:?}"))
}

#[cfg(feature = "config-fixture")]
fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
    let callable = vm.resolve_exported_callable(name).expect("RSS export");
    vm.invoke_callable(callable, args).expect("RSS call")
}

fn public_query(name: &str, value: &str) -> Value {
    Value::map(vec![
        (Value::string("name"), Value::string(name)),
        (Value::string("value"), Value::string(value)),
    ])
}

fn public_intent(path: &str, flow: &str, mode: &str, query: Vec<Value>) -> Value {
    public_intent_with_scopes(
        path,
        flow,
        mode,
        query,
        vec![Value::string("scope.synthetic")],
    )
}

fn public_intent_with_scopes(
    path: &str,
    flow: &str,
    mode: &str,
    query: Vec<Value>,
    scopes: Vec<Value>,
) -> Value {
    Value::map(vec![
        (
            Value::string("credential_id"),
            Value::string("fixture-codex"),
        ),
        (Value::string("path"), Value::string(path)),
        (Value::string("flow"), Value::string(flow)),
        (Value::string("callback_mode"), Value::string(mode)),
        (Value::string("scopes"), Value::array(scopes)),
        (Value::string("public_query"), Value::array(query)),
    ])
}

fn fixture_intent() -> Value {
    public_intent(
        "/codex/device",
        "authorization_code_pkce",
        "manual",
        vec![
            public_query("client_id", "public-client-id"),
            public_query("response_type", "code"),
        ],
    )
}

#[test]
fn catalog_exposes_exact_resource_backed_pkce_callback_contract() {
    let catalog = auth_host_catalog();
    let functions = catalog.functions();
    let function = |name: &str| {
        functions
            .iter()
            .find(|schema| schema.name == name)
            .unwrap_or_else(|| panic!("missing canonical host function {name}"))
    };

    let begin = function("oauth::pkce_begin");
    assert_eq!(begin.params.len(), 2);
    assert_eq!(begin.params[0].name, "policy_handle");
    assert_eq!(begin.params[1].name, "public_intent");
    assert_eq!(begin.params[0].passing, HostParamPassing::Borrow);
    assert_eq!(begin.params[1].passing, HostParamPassing::Value);
    assert_eq!(
        begin.params[0].ty,
        HostTypeSchema::Resource(ResourceTypeKey::new("auth.policy").expect("key"))
    );
    assert!(matches!(
        &begin.params[1].ty,
        HostTypeSchema::Named { name, .. } if name == "BoundedPublicOAuthIntent"
    ));
    assert!(matches!(
        &begin.return_type,
        HostTypeSchema::Named { name, .. } if name == "PkceBeginEnvelope"
    ));
    let HostTypeSchema::Named { fields, .. } = &begin.return_type else {
        panic!("begin result must be a named envelope");
    };
    for (field_name, key) in [
        ("callback_handle", "oauth.callback"),
        ("verifier_handle", "oauth.verifier"),
    ] {
        assert_eq!(
            fields
                .iter()
                .find(|field| field.name == field_name)
                .unwrap()
                .ty,
            HostTypeSchema::Resource(ResourceTypeKey::new(key).expect("key"))
        );
    }
    let begin_debug = format!("{begin:?}");
    assert!(begin_debug.contains("oauth.callback"), "{begin_debug}");
    assert!(begin_debug.contains("oauth.verifier"), "{begin_debug}");
    assert!(!begin_debug.contains("oauth.state"), "{begin_debug}");

    let wait = function("oauth::callback_wait");
    assert_eq!(wait.params.len(), 1);
    assert_eq!(wait.params[0].name, "callback_handle");
    assert_eq!(wait.params[0].passing, HostParamPassing::Borrow);
    assert_eq!(
        wait.params[0].ty,
        HostTypeSchema::Resource(ResourceTypeKey::new("oauth.callback").expect("key"))
    );
    assert!(matches!(
        &wait.return_type,
        HostTypeSchema::Named { name, .. } if name == "CallbackEnvelope"
    ));
    let HostTypeSchema::Named { fields, .. } = &wait.return_type else {
        panic!("wait result must be a named envelope");
    };
    let HostTypeSchema::Optional(code_type) = &fields
        .iter()
        .find(|field| field.name == "code_handle")
        .expect("code field")
        .ty
    else {
        panic!("callback code handle must be optional");
    };
    assert_eq!(
        **code_type,
        HostTypeSchema::Resource(ResourceTypeKey::new("oauth.authorization_code").expect("key"))
    );
    let wait_debug = format!("{wait:?}");
    assert!(wait_debug.contains("oauth.callback"), "{wait_debug}");
    assert!(
        wait_debug.contains("oauth.authorization_code"),
        "{wait_debug}"
    );

    for (name, key) in [
        ("oauth::close_callback", "oauth.callback"),
        ("oauth::close_verifier", "oauth.verifier"),
        ("oauth::close_code", "oauth.authorization_code"),
    ] {
        let close = function(name);
        assert_eq!(close.params.len(), 1);
        assert_eq!(close.params[0].passing, HostParamPassing::TakeOwned);
        assert_eq!(
            close.params[0].ty,
            HostTypeSchema::Resource(ResourceTypeKey::new(key).expect("key"))
        );
    }
}

#[test]
fn injected_oauth_host_keeps_callback_unavailable_by_default() {
    use rustscript_agent::auth::oauth::{
        OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
        ScriptedHttpsTransport,
    };

    let mut vm = compile_contract(&contract_source());
    let home = TempHome::new("default-unavailable");
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth);
    let home_resource = auth.bind_vm(&mut vm).expect("bind owner");
    let callable = vm.resolve_exported_callable("begin").expect("RSS export");
    let failure = vm
        .invoke_callable(
            callable,
            &[field(&home_resource, "host_home"), fixture_intent()],
        )
        .expect_err("injected OAuth alone must not enable callbacks");

    assert!(
        failure.to_string().contains("callback_unavailable"),
        "{failure}"
    );
    assert!(!failure.to_string().contains(SYNTHETIC_CODE));
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[test]
fn compiler_rejects_json_serialization_of_callback_resource() {
    let mut source = contract_source();
    source.push_str(
        "\nuse json;\npub fn serialize_callback(handle: resource<oauth.callback>) -> string {\n    let encoded: string = json::encode(handle);\n    encoded\n}\n",
    );
    let fixture_config = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let failure = match compile_source_at_path_with_flavor_and_options(
        &fixture_config,
        &source,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(auth_host_catalog()),
    ) {
        Ok(_) => panic!("resource-bearing values must not be JSON serializable"),
        Err(failure) => failure,
    };
    assert!(
        failure
            .to_string()
            .to_ascii_lowercase()
            .contains("resource"),
        "{failure}"
    );
}

#[cfg(feature = "config-fixture")]
#[test]
fn restricted_real_rss_pkce_call_is_unavailable_without_callback_opt_in() {
    use rustscript_agent::auth::oauth::{
        OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
        ScriptedHttpsTransport,
    };

    let source = contract_source();
    let mut vm = compile_contract(&source);
    let home = TempHome::new("rss-flow-disabled");
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth);
    let home_resource = auth.bind_vm(&mut vm).expect("bind owner");
    let callable = vm.resolve_exported_callable("begin").expect("RSS export");
    let failure = vm
        .invoke_callable(
            callable,
            &[field(&home_resource, "host_home"), fixture_intent()],
        )
        .expect_err("callback bridge must require explicit opt-in");
    assert!(
        failure.to_string().contains("callback_unavailable"),
        "{failure}"
    );
    assert!(!failure.to_string().contains(SYNTHETIC_CODE));
}

#[cfg(feature = "config-fixture")]
#[test]
fn restricted_real_rss_waits_once_and_callback_close_preserves_siblings() {
    use rustscript_agent::auth::oauth::{
        ScriptedBrowser, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
    };

    let mut vm = compile_contract(&contract_source());
    let home = TempHome::new("rss-flow-success");
    let callback_waiter = Arc::new(CountingCallback::new(None));
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        callback_waiter.clone(),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth)
    .with_oauth_callback_fixture();
    let home_resource = auth.bind_vm(&mut vm).expect("bind owner");
    let begun = invoke(
        &mut vm,
        "begin",
        &[field(&home_resource, "host_home"), fixture_intent()],
    );
    let callback = field(&begun, "callback_handle");
    let verifier = field(&begun, "verifier_handle");
    assert!(format!("{begun:?}").contains("authorization_url"));
    assert!(!format!("{begun:?}").contains(SYNTHETIC_CODE));
    assert_eq!(vm.host_context().resource_count(), 4);
    auth.fixture_inject_matching_callback(&mut vm, &callback, SYNTHETIC_CODE)
        .expect("fixture-only callback injection");

    let waited = invoke(&mut vm, "wait", std::slice::from_ref(&callback));
    assert_eq!(field(&waited, "outcome"), Value::string("success"));
    let code = field(&waited, "code_handle");
    assert!(matches!(code, Value::Int(_)));
    assert!(matches!(verifier, Value::Int(_)));
    assert!(!format!("{waited:?}").contains(SYNTHETIC_CODE));
    assert!(!format!("{waited:?}").contains("code_verifier"));

    let callable = vm.resolve_exported_callable("wait").expect("wait export");
    let replay = vm
        .invoke_callable(callable, std::slice::from_ref(&callback))
        .expect_err("callback aliases share one consumed wait");
    assert!(replay.to_string().contains("handle_replayed"));
    assert!(!replay.to_string().contains(SYNTHETIC_CODE));
    assert_eq!(callback_waiter.wait_count(), 1);
    assert_eq!(auth.fixture_live_oauth_flow_count().expect("flow count"), 1);
    assert_eq!(vm.host_context().resource_count(), 5);

    invoke(&mut vm, "close_callback", std::slice::from_ref(&callback));
    let stale_wait = vm.resolve_exported_callable("wait").expect("wait export");
    let stale = vm
        .invoke_callable(stale_wait, std::slice::from_ref(&callback))
        .expect_err("closed callback alias must be stale");
    assert!(
        stale.to_string().contains("resource_already_closed"),
        "{stale}"
    );
    assert_eq!(
        auth.fixture_live_oauth_flow_count().expect("flow remains"),
        1
    );
    assert_eq!(vm.host_context().resource_count(), 4);
    invoke(&mut vm, "close_verifier", std::slice::from_ref(&verifier));
    assert_eq!(
        auth.fixture_live_oauth_flow_count().expect("flow revoked"),
        0
    );
    invoke(&mut vm, "close_code", std::slice::from_ref(&code));
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn callback_resources_reject_wrong_class_forgery_cross_vm_and_revocation() {
    use rustscript_agent::auth::oauth::{
        ScriptedBrowser, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
    };

    let mut vm_one = compile_contract(&contract_source());
    let mut vm_two = compile_contract(&contract_source());
    let home_one = TempHome::new("resource-owner-one");
    let home_two = TempHome::new("resource-owner-two");
    let oauth_one = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(CountingCallback::new(None)),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let oauth_two = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(CountingCallback::new(None)),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth_one = AuthHost::new(
        home_one.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("first host")
    .with_oauth_host(oauth_one)
    .with_oauth_callback_fixture();
    let auth_two = AuthHost::new(
        home_two.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("second host")
    .with_oauth_host(oauth_two)
    .with_oauth_callback_fixture();
    let owner_one = auth_one.bind_vm(&mut vm_one).expect("bind first VM");
    let _owner_two = auth_two.bind_vm(&mut vm_two).expect("bind second VM");
    let begun = invoke(
        &mut vm_one,
        "begin",
        &[field(&owner_one, "host_home"), fixture_intent()],
    );
    let callback = field(&begun, "callback_handle");
    let verifier = field(&begun, "verifier_handle");
    let wait_one = vm_one.resolve_exported_callable("wait").expect("wait");

    let wrong_class = vm_one
        .invoke_callable(wait_one.clone(), std::slice::from_ref(&verifier))
        .expect_err("verifier is not a callback resource");
    assert!(
        wrong_class
            .to_string()
            .contains("resource_type_key_mismatch"),
        "{wrong_class}"
    );
    let forged = vm_one
        .invoke_callable(wait_one.clone(), &[Value::Int(i64::MAX)])
        .expect_err("forged carrier is not host-issued");
    assert!(
        forged.to_string().contains("resource_handle_wrong_table"),
        "{forged}"
    );

    let wait_two = vm_two
        .resolve_exported_callable("wait")
        .expect("other wait");
    let cross_vm = vm_two
        .invoke_callable(wait_two, std::slice::from_ref(&callback))
        .expect_err("resource handles cannot cross VM arenas");
    assert!(
        cross_vm.to_string().contains("resource_handle_wrong_table"),
        "{cross_vm}"
    );
    assert_eq!(
        auth_one
            .fixture_live_oauth_flow_count()
            .expect("first flow"),
        1
    );
    assert_eq!(
        auth_two
            .fixture_live_oauth_flow_count()
            .expect("second flow"),
        0
    );
    assert_eq!(vm_one.host_context().resource_count(), 4);

    auth_one.revoke();
    let revoked = vm_one
        .invoke_callable(wait_one, std::slice::from_ref(&callback))
        .expect_err("revoked owner cannot wait");
    assert!(revoked.to_string().contains("policy_inactive"), "{revoked}");
    assert_eq!(
        auth_one
            .fixture_live_oauth_flow_count()
            .expect("revoked flow"),
        0
    );
    assert_eq!(vm_one.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn callback_close_before_wait_revokes_flow_and_stale_aliases() {
    use rustscript_agent::auth::oauth::{
        ScriptedBrowser, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
    };

    let mut vm = compile_contract(&contract_source());
    let home = TempHome::new("callback-close-before-wait");
    let callback_waiter = Arc::new(CountingCallback::new(None));
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        callback_waiter.clone(),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth)
    .with_oauth_callback_fixture();
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let begun = invoke(
        &mut vm,
        "begin",
        &[field(&owner, "host_home"), fixture_intent()],
    );
    let callback = field(&begun, "callback_handle");
    let callback_alias = callback.clone();
    let verifier = field(&begun, "verifier_handle");
    let verifier_alias = verifier.clone();

    invoke(&mut vm, "close_callback", std::slice::from_ref(&callback));
    assert_eq!(
        auth.fixture_live_oauth_flow_count().expect("closed flow"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 3);
    let wait = vm.resolve_exported_callable("wait").expect("wait export");
    let stale_callback = vm
        .invoke_callable(wait, std::slice::from_ref(&callback_alias))
        .expect_err("callback alias must be stale before wait");
    assert!(
        stale_callback
            .to_string()
            .contains("resource_already_closed"),
        "{stale_callback}"
    );
    assert_eq!(callback_waiter.wait_count(), 0);

    invoke(&mut vm, "close_verifier", std::slice::from_ref(&verifier));
    let close_verifier = vm
        .resolve_exported_callable("close_verifier")
        .expect("close verifier export");
    let stale_verifier = vm
        .invoke_callable(close_verifier, std::slice::from_ref(&verifier_alias))
        .expect_err("verifier alias must be stale after close");
    assert!(
        stale_verifier
            .to_string()
            .contains("resource_already_closed"),
        "{stale_verifier}"
    );
    assert_eq!(auth.fixture_live_oauth_flow_count().expect("no flow"), 0);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn reload_keeps_admitted_callback_generation_and_advances_new_bind() {
    use rustscript_agent::auth::oauth::{
        ScriptedBrowser, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
    };

    let mut old_vm = compile_contract(&contract_source());
    let mut new_vm = compile_contract(&contract_source());
    let home = TempHome::new("reload-generation");
    let callback_waiter = Arc::new(CountingCallback::new(None));
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        callback_waiter,
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth)
    .with_oauth_callback_fixture();
    let old_home = auth.bind_vm(&mut old_vm).expect("old bind");
    assert_eq!(
        auth.fixture_policy_generation(&mut old_vm)
            .expect("old generation"),
        1
    );
    let old_begun = invoke(
        &mut old_vm,
        "begin",
        &[field(&old_home, "host_home"), fixture_intent()],
    );
    assert_eq!(auth.fixture_live_oauth_flow_count().expect("old flow"), 1);

    assert_eq!(auth.reload().expect("reload"), 2);
    assert_eq!(
        auth.fixture_policy_generation(&mut old_vm)
            .expect("frozen generation"),
        1
    );
    let new_home = auth.bind_vm(&mut new_vm).expect("new bind");
    assert_eq!(
        auth.fixture_policy_generation(&mut new_vm)
            .expect("new generation"),
        2
    );
    let new_begun = invoke(
        &mut new_vm,
        "begin",
        &[field(&new_home, "host_home"), fixture_intent()],
    );

    let old_callback = field(&old_begun, "callback_handle");
    let old_verifier = field(&old_begun, "verifier_handle");
    let new_callback = field(&new_begun, "callback_handle");
    let new_verifier = field(&new_begun, "verifier_handle");
    auth.fixture_inject_matching_callback(&mut old_vm, &old_callback, "FIXTURE_OLD_GENERATION")
        .expect("old flow callback");
    auth.fixture_inject_matching_callback(&mut new_vm, &new_callback, "FIXTURE_NEW_GENERATION")
        .expect("new flow callback");
    let old_waited = invoke(&mut old_vm, "wait", std::slice::from_ref(&old_callback));
    let new_waited = invoke(&mut new_vm, "wait", std::slice::from_ref(&new_callback));
    assert_eq!(field(&old_waited, "outcome"), Value::string("success"));
    assert_eq!(field(&new_waited, "outcome"), Value::string("success"));

    for (vm, callback, verifier, waited) in [
        (&mut old_vm, old_callback, old_verifier, old_waited),
        (&mut new_vm, new_callback, new_verifier, new_waited),
    ] {
        let code = field(&waited, "code_handle");
        invoke(vm, "close_callback", std::slice::from_ref(&callback));
        invoke(vm, "close_verifier", std::slice::from_ref(&verifier));
        invoke(vm, "close_code", std::slice::from_ref(&code));
    }
    assert_eq!(
        auth.fixture_live_oauth_flow_count().expect("closed flows"),
        0
    );
    assert_eq!(old_vm.host_context().resource_count(), 2);
    assert_eq!(new_vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn begin_resource_quota_rejects_before_browser_or_callback_effects() {
    use rustscript_agent::auth::oauth::{
        ScriptedBrowser, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
    };

    let mut vm = compile_contract(&contract_source());
    let home = TempHome::new("begin-quota");
    let callback_waiter = Arc::new(CountingCallback::new(None));
    let browser = Arc::new(ScriptedBrowser::new());
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        callback_waiter.clone(),
        browser.clone(),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth)
    .with_oauth_callback_fixture();
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let fillers = fill_resource_arena(&mut vm, 62);
    let begin = vm.resolve_exported_callable("begin").expect("begin");
    let failure = vm
        .invoke_callable(
            begin,
            &[
                field(&owner, "host_home"),
                public_intent(
                    "/codex/device",
                    "authorization_code_pkce",
                    "browser",
                    vec![public_query("client_id", "public-client-id")],
                ),
            ],
        )
        .expect_err("quota must be reserved before PKCE effects");
    assert!(failure.to_string().contains("resource_limit"), "{failure}");
    assert_eq!(auth.fixture_live_oauth_flow_count().expect("no flow"), 0);
    assert_eq!(vm.host_context().resource_count(), 63);
    assert!(browser.opened().is_empty());
    assert_eq!(callback_waiter.wait_count(), 0);
    close_quota_resources(&mut vm, fillers);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn callback_code_resource_quota_failure_rolls_back_flow_and_aliases() {
    use rustscript_agent::auth::oauth::{
        ScriptedBrowser, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
    };

    let mut vm = compile_contract(&contract_source());
    let home = TempHome::new("callback-code-quota");
    let callback_waiter = Arc::new(CountingCallback::new(None));
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        callback_waiter.clone(),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth)
    .with_oauth_callback_fixture();
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let begun = invoke(
        &mut vm,
        "begin",
        &[field(&owner, "host_home"), fixture_intent()],
    );
    let callback = field(&begun, "callback_handle");
    assert_eq!(vm.host_context().resource_count(), 4);
    auth.fixture_inject_matching_callback(&mut vm, &callback, SYNTHETIC_CODE)
        .expect("inject fixture callback");
    let fillers = fill_resource_arena(&mut vm, 64);

    let wait = vm.resolve_exported_callable("wait").expect("wait");
    let failure = vm
        .invoke_callable(wait.clone(), std::slice::from_ref(&callback))
        .expect_err("code resource allocation must fail at the quota");
    assert!(failure.to_string().contains("resource_limit"), "{failure}");
    assert_eq!(callback_waiter.wait_count(), 1);
    assert_eq!(
        auth.fixture_live_oauth_flow_count().expect("rolled back"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 62);
    let stale = vm
        .invoke_callable(wait, std::slice::from_ref(&callback))
        .expect_err("rollback closes callback aliases");
    assert!(
        stale.to_string().contains("resource_already_closed"),
        "{stale}"
    );

    close_quota_resources(&mut vm, fillers);
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn real_rss_rejects_untrusted_intent_before_primitive_effects() {
    use rustscript_agent::auth::oauth::{
        ScriptedBrowser, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
    };

    let mut vm = compile_contract(&contract_source());
    let home = TempHome::new("rss-invalid-intent");
    let callback_waiter = Arc::new(CountingCallback::new(None));
    let browser = Arc::new(ScriptedBrowser::new());
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        callback_waiter.clone(),
        browser.clone(),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth)
    .with_oauth_callback_fixture();
    let host_context = auth.bind_vm(&mut vm).expect("bind owner");
    let home_resource = field(&host_context, "host_home");

    let cases = [
        (
            public_intent(
                "/codex/device",
                "device_code",
                "manual",
                vec![public_query("client_id", "public-client-id")],
            ),
            "oauth_flow_unsupported",
        ),
        (
            public_intent(
                "/codex/device",
                "authorization_code_pkce",
                "popup",
                vec![public_query("client_id", "public-client-id")],
            ),
            "oauth_callback_mode_unsupported",
        ),
        (
            public_intent(
                "https://attacker.invalid/authorize",
                "authorization_code_pkce",
                "browser",
                vec![public_query("client_id", "public-client-id")],
            ),
            "oauth_path_denied",
        ),
        (
            public_intent(
                "/unauthorized/path",
                "authorization_code_pkce",
                "browser",
                vec![public_query("client_id", "public-client-id")],
            ),
            "path_denied",
        ),
        (
            public_intent(
                "/codex/device?redirect_uri=https://attacker.invalid",
                "authorization_code_pkce",
                "browser",
                vec![public_query("client_id", "public-client-id")],
            ),
            "oauth_path_denied",
        ),
        (
            public_intent(
                "/codex/device#fragment",
                "authorization_code_pkce",
                "browser",
                vec![public_query("client_id", "public-client-id")],
            ),
            "oauth_path_denied",
        ),
        (
            public_intent(
                "/codex/device",
                "authorization_code_pkce",
                "browser",
                vec![public_query("state", "replacement")],
            ),
            "oauth_intent_invalid",
        ),
        (
            public_intent(
                "/codex/device",
                "authorization_code_pkce",
                "browser",
                vec![
                    public_query("client_id", "one"),
                    public_query("client_id", "two"),
                ],
            ),
            "oauth_intent_invalid",
        ),
        (
            public_intent(
                "/codex/device",
                "authorization_code_pkce",
                "browser",
                (0..33)
                    .map(|index| public_query(&format!("public_{index}"), "value"))
                    .collect(),
            ),
            "oauth_intent_too_large",
        ),
        (
            public_intent(
                "/codex/device",
                "authorization_code_pkce",
                "browser",
                vec![public_query("client_id", &"x".repeat(2048))],
            ),
            "oauth_intent_invalid",
        ),
        (
            public_intent_with_scopes(
                "/codex/device",
                "authorization_code_pkce",
                "browser",
                vec![public_query("client_id", "public-client-id")],
                (0..33)
                    .map(|index| Value::string(format!("scope_{index}")))
                    .collect(),
            ),
            "oauth_intent_too_large",
        ),
    ];
    let begin = vm
        .resolve_exported_callable("begin")
        .expect("typed RSS intent entry");
    for (intent, expected) in cases {
        let failure = vm
            .invoke_callable(begin.clone(), &[home_resource.clone(), intent])
            .expect_err("invalid intent must be rejected");
        assert!(failure.to_string().contains(expected), "{failure}");
        assert_eq!(auth.fixture_live_oauth_flow_count().expect("flow count"), 0);
        assert_eq!(vm.host_context().resource_count(), 2);
        assert!(browser.opened().is_empty());
        assert_eq!(callback_waiter.wait_count(), 0);
    }
}

#[cfg(feature = "config-fixture")]
#[test]
fn callback_failures_revoke_flow_and_release_resources() {
    use rustscript_agent::auth::oauth::{
        OAuthHost, RawCallbackInput, ScriptedBrowser, ScriptedCallback, ScriptedCancel,
        ScriptedClock, ScriptedHttpsTransport,
    };

    let mut vm = compile_contract(&contract_source());
    let home = TempHome::new("callback-failures");
    let callback_waiter = Arc::new(ScriptedCallback::new());
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        callback_waiter.clone(),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth)
    .with_oauth_callback_fixture();
    let host_context = auth.bind_vm(&mut vm).expect("bind owner");
    let home_resource = field(&host_context, "host_home");
    let begin = vm.resolve_exported_callable("begin").expect("begin export");
    let wait = vm.resolve_exported_callable("wait").expect("wait export");

    let cases = [
        (
            RawCallbackInput::Query {
                state: "wrong-state-fixture".to_string(),
                code: "FIXTURE_BAD_CALLBACK_CODE".to_string(),
            },
            "state_mismatch",
        ),
        (
            RawCallbackInput::ManualUrl("not-a-callback-url".to_string()),
            "malformed_response",
        ),
        (RawCallbackInput::Timeout, "callback_timeout"),
        (RawCallbackInput::Cancelled, "callback_cancelled"),
    ];
    for (input, expected) in cases {
        callback_waiter.push(input);
        let begun = vm
            .invoke_callable(begin.clone(), &[home_resource.clone(), fixture_intent()])
            .expect("PKCE begin");
        let callback = field(&begun, "callback_handle");
        let failure = vm
            .invoke_callable(wait.clone(), std::slice::from_ref(&callback))
            .expect_err("callback failure must remain typed");
        assert!(failure.to_string().contains(expected), "{failure}");
        assert!(!failure.to_string().contains("FIXTURE_BAD_CALLBACK_CODE"));
        assert_eq!(auth.fixture_live_oauth_flow_count().expect("flow count"), 0);
        assert_eq!(vm.host_context().resource_count(), 2);
    }
}

#[cfg(feature = "config-fixture")]
#[test]
fn owner_cancellation_after_waiter_return_revokes_callback_result() {
    use rustscript_agent::auth::oauth::{
        ScriptedBrowser, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
    };

    let mut vm = compile_contract(&contract_source());
    let home = TempHome::new("owner-cancel-after-wait");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let callback_waiter = Arc::new(CountingCallback::new(Some(cancellation.clone())));
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        callback_waiter.clone(),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(home.0.clone(), cancellation)
        .expect("host")
        .with_oauth_host(oauth)
        .with_oauth_callback_fixture();
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let begun = invoke(
        &mut vm,
        "begin",
        &[field(&owner, "host_home"), fixture_intent()],
    );
    let callback = field(&begun, "callback_handle");
    auth.fixture_inject_matching_callback(&mut vm, &callback, "FIXTURE_POST_WAIT_CANCEL")
        .expect("inject fixture callback");

    let wait = vm.resolve_exported_callable("wait").expect("wait");
    let failure = vm
        .invoke_callable(wait, std::slice::from_ref(&callback))
        .expect_err("post-wait cancellation rejects callback result");
    assert!(
        failure.to_string().contains("callback_cancelled"),
        "{failure}"
    );
    assert!(!failure.to_string().contains("FIXTURE_POST_WAIT_CANCEL"));
    assert_eq!(callback_waiter.wait_count(), 1);
    assert_eq!(
        auth.fixture_live_oauth_flow_count().expect("revoked flow"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn callback_expiry_is_finite_and_cleans_flow_before_waiter_effect() {
    use rustscript_agent::auth::oauth::{
        ScriptedBrowser, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
    };

    let mut vm = compile_contract(&contract_source());
    let home = TempHome::new("callback-expiry");
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let callback_waiter = Arc::new(CountingCallback::new(None));
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        callback_waiter.clone(),
        Arc::new(ScriptedBrowser::new()),
        clock.clone(),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth)
    .with_oauth_callback_fixture();
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let begun = invoke(
        &mut vm,
        "begin",
        &[field(&owner, "host_home"), fixture_intent()],
    );
    let callback = field(&begun, "callback_handle");
    assert_eq!(auth.fixture_live_oauth_flow_count().expect("flow"), 1);
    clock.expire();

    let wait = vm.resolve_exported_callable("wait").expect("wait");
    let failure = vm
        .invoke_callable(wait, std::slice::from_ref(&callback))
        .expect_err("expired callback must not wait");
    assert!(
        failure.to_string().contains("callback_timeout"),
        "{failure}"
    );
    assert_eq!(callback_waiter.wait_count(), 0);
    assert_eq!(
        auth.fixture_live_oauth_flow_count().expect("expired flow"),
        0
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}

#[cfg(feature = "config-fixture")]
#[test]
fn vm_reset_revokes_callback_flow_and_resources() {
    use rustscript_agent::auth::oauth::{
        ScriptedBrowser, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
    };

    let mut vm = compile_contract(&contract_source());
    let home = TempHome::new("vm-reset");
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(CountingCallback::new(None)),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth)
    .with_oauth_callback_fixture();
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let _begun = invoke(
        &mut vm,
        "begin",
        &[field(&owner, "host_home"), fixture_intent()],
    );
    assert_eq!(auth.fixture_live_oauth_flow_count().expect("flow"), 1);

    vm.reset_for_reuse().expect("reset VM");
    assert!(matches!(vm.run().expect("rerun root"), VmStatus::Halted));
    assert_eq!(auth.fixture_live_oauth_flow_count().expect("reset flow"), 0);
    assert_eq!(vm.host_context().resource_count(), 0);
}

#[cfg(feature = "config-fixture")]
#[test]
fn vm_drop_revokes_callback_flow() {
    use rustscript_agent::auth::oauth::{
        OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
        ScriptedHttpsTransport,
    };

    let mut vm = compile_contract(&contract_source());
    let home = TempHome::new("vm-drop");
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("host")
    .with_oauth_host(oauth)
    .with_oauth_callback_fixture();
    let owner = auth.bind_vm(&mut vm).expect("bind owner");
    let _begun = invoke(
        &mut vm,
        "begin",
        &[field(&owner, "host_home"), fixture_intent()],
    );
    assert_eq!(auth.fixture_live_oauth_flow_count().expect("flow count"), 1);

    drop(vm);

    assert_eq!(
        auth.fixture_live_oauth_flow_count()
            .expect("drained flow count"),
        0
    );
}

#[cfg(feature = "config-fixture")]
#[test]
fn owner_cancellation_revokes_wait_and_returns_fixed_cancellation_error() {
    use rustscript_agent::auth::oauth::{
        ScriptedBrowser, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
    };

    let mut vm = compile_contract(&contract_source());
    let home = TempHome::new("owner-cancel");
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    let callback_waiter = Arc::new(CountingCallback::new(None));
    let oauth = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        callback_waiter.clone(),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let auth = AuthHost::new(home.0.clone(), cancellation.clone())
        .expect("host")
        .with_oauth_host(oauth)
        .with_oauth_callback_fixture();
    let host_context = auth.bind_vm(&mut vm).expect("bind owner");
    let begun = invoke(
        &mut vm,
        "begin",
        &[field(&host_context, "host_home"), fixture_intent()],
    );
    let callback = field(&begun, "callback_handle");
    auth.fixture_inject_matching_callback(&mut vm, &callback, "FIXTURE_CANCEL_CALLBACK")
        .expect("inject fixture callback");
    cancellation.request(CancellationReason::Requested);

    let wait = vm.resolve_exported_callable("wait").expect("wait export");
    let failure = vm
        .invoke_callable(wait, &[callback])
        .expect_err("owner cancellation must stop callback wait");
    assert!(
        failure.to_string().contains("callback_cancelled"),
        "{failure}"
    );
    assert!(!failure.to_string().contains("FIXTURE_CANCEL_CALLBACK"));
    assert_eq!(auth.fixture_live_oauth_flow_count().expect("flow count"), 0);
    assert_eq!(vm.host_context().resource_count(), 2);
    assert_eq!(callback_waiter.wait_count(), 0);
}

#[test]
fn callback_contract_rss_does_not_accept_raw_secret_parameters() {
    let source = contract_source();
    assert!(source.contains("pub fn begin("));
    assert!(source.contains("intent: BoundedPublicOAuthIntent"));
    assert!(source.contains("oauth::pkce_begin(&snapshot.policy_handle, intent)"));
    assert!(!source.contains("fixture-codex"));
    assert!(!source.contains("/codex/device"));
    assert!(!source.contains("begin_with_intent"));
    assert!(!source.contains("code: string"));
    assert!(!source.contains("verifier: string"));
    assert!(!source.contains("state: string"));
    assert!(!source.contains("access_token"));
    assert!(!source.contains("refresh_token"));
}
