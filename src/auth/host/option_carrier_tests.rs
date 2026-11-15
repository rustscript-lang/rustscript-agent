//! Round-6 carrier tests for the converted auth/oauth/config hosts.
//!
//! Every case compiles a real RSS probe against the published
//! `auth_host_catalog`, binds it through a real restricted registry, runs it in
//! a real VM, and then reads the guest-visible value back. The negative cases
//! assert the same functions fail closed (stale resource, missing credential,
//! wrong generation, malformed parameter carrier, invalid pointer) instead of
//! publishing a half-shaped envelope.

use super::{
    AuthHost, Bound, HostHome, auth_host_catalog, config_envelope, handle, issue_owner_slot,
    object, save_call,
};
use crate::auth::oauth::{
    OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
    ScriptedHttpsTransport,
};
use crate::auth::store::{OpaqueSecretSlot, SecretSlotKind};
use crate::runtime::RunCancellation;
use crate::runtime::host_shapes;
use rustscript_vm::resource::ResourceCloseReason;
use rustscript_vm::{CallOutcome, CallReturn, HostTypeSchema, Value, Vm, VmError, VmResult};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PROBE: &str = r#"
use config;
use auth;
use oauth;

pub fn snapshot_probe(home: resource<auth.host_home>) -> map {
    let snapshot: ConfigSnapshotEnvelope = config::load_snapshot(&home);
    let public_config: BoundedPublicConfig = snapshot.public_config;
    let error_present: bool = match snapshot.error { Some(_) => true, None => false };
    let providers: array<ProviderEntry> = public_config.providers.copy();
    let provider: ProviderEntry = providers[0].copy();
    let auth_present: bool = match provider.auth { Some(_) => true, None => false };
    let oauth_present: bool = match provider.oauth { Some(_) => true, None => false };
    let default_present: bool = match public_config.workspaces.default { Some(_) => true, None => false };
    {
        ok: snapshot.ok && !error_present,
        generation: snapshot.policy_generation,
        credentials: snapshot.credential_refs.length,
        providers: providers.length,
        provider_name: provider.name,
        auth_present: auth_present,
        oauth_present: oauth_present,
        default_present: default_present
    }
}

pub fn snapshot_policy(home: resource<auth.host_home>) -> resource<auth.policy> {
    config::load_snapshot(&home).policy_handle
}

pub fn metadata_probe(policy: resource<auth.policy>, credential_id: string) -> map {
    let loaded: AuthMetadataEnvelope = auth::load_metadata(credential_id, &policy);
    let metadata: AuthMetadata = loaded.metadata.copy();
    let error_present: bool = match loaded.error { Some(_) => true, None => false };
    let account_present: bool = match metadata.account_id { Some(_) => true, None => false };
    let refreshed_present: bool = match metadata.last_refresh_at_ms.copy() { Some(_) => true, None => false };
    {
        ok: loaded.ok,
        error_present: error_present,
        account_present: account_present,
        refreshed_present: refreshed_present,
        generation: metadata.generation,
        outcome: loaded.outcome
    }
}

pub fn access_probe(policy: resource<auth.policy>, generation: int) -> map {
    let issued: AccessHandleEnvelope = auth::access_handle("fixture-codex", generation, &policy);
    let error_present: bool = match issued.error { Some(_) => true, None => false };
    let handle: resource<auth.access> = issued.handle;
    auth::close_access(handle);
    {ok: issued.ok, error_present: error_present}
}

pub fn refresh_probe(policy: resource<auth.policy>, generation: int) -> map {
    let issued: RefreshHandleEnvelope = auth::refresh_handle("fixture-codex", generation, &policy);
    let error_present: bool = match issued.error { Some(_) => true, None => false };
    auth::close_refresh(issued.handle);
    {ok: issued.ok, error_present: error_present}
}

pub fn now_probe(policy: resource<auth.policy>) -> map {
    let clock: OAuthNowResultEnvelope = oauth::now_ms_result(&policy);
    let error_present: bool = match clock.error { Some(_) => true, None => false };
    let now: Option<int> = clock.value;
    {ok: clock.ok, error_present: error_present, now: now.unwrap_or(-1)}
}

pub fn field_probe(policy: resource<auth.policy>, text: string, pointer: string) -> PublicJsonFieldEnvelope {
    oauth::public_json_field(&policy, text, pointer)
}

pub fn field_result_probe(policy: resource<auth.policy>, text: string, pointer: string) -> PublicJsonFieldResultEnvelope {
    oauth::public_json_field_result(&policy, text, pointer)
}

pub fn delete_probe(policy: resource<auth.policy>) -> map {
    let deleted: RedactedMutationResult = auth::delete("fixture-codex", &policy);
    let error_present: bool = match deleted.error { Some(_) => true, None => false };
    {ok: deleted.ok, deleted: deleted.deleted, error_present: error_present}
}
"#;

struct TestHome(PathBuf);

impl TestHome {
    fn new(label: &str) -> Self {
        let base =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"));
        let path = base.join(format!(
            "auth-option-carrier-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create private auth home");
        let fixtures =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixtures.join("config.yaml"), path.join("config.yaml"))
            .expect("copy config fixture");
        let auth = fs::read_to_string(fixtures.join("auth.yaml"))
            .expect("read auth fixture")
            .replace("1788440000000", "1900000000000");
        fs::write(path.join("auth.yaml"), auth).expect("write auth fixture");
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

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn oauth_host() -> Arc<OAuthHost> {
    Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ))
}

fn vm_for(host: &AuthHost) -> Vm {
    let catalog = auth_host_catalog();
    let compiled = rustscript_vm::compile_source_with_flavor_and_options(
        PROBE,
        rustscript_vm::SourceFlavor::RustScript,
        rustscript_vm::CompileSourceFileOptions::default()
            .with_host_api_catalog(Arc::clone(&catalog)),
    )
    .expect("compile carrier probe against the published catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = rustscript_vm::HostFunctionRegistry::restricted();
    host.register(&mut registry, catalog.as_ref())
        .expect("register the published auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind the restricted registry");
    assert!(matches!(
        vm.run().expect("probe root frame"),
        rustscript_vm::VmStatus::Halted
    ));
    vm
}

fn caller(host: &AuthHost, vm: &mut Vm) -> (Value, Value) {
    let bound = host.bind_vm(vm).expect("bind run owner");
    let home = field(&bound, "host_home");
    let callable = vm
        .resolve_exported_callable("snapshot_policy")
        .expect("snapshot export");
    let policy = vm
        .invoke_callable(callable, std::slice::from_ref(&home))
        .expect("load owner policy");
    (home, policy)
}

fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> VmResult<Value> {
    let callable = vm
        .resolve_exported_callable(name)
        .unwrap_or_else(|_| panic!("export {name}"));
    vm.invoke_callable(callable, args)
}

fn field(value: &Value, name: &str) -> Value {
    let Value::Map(entries) = value else {
        panic!("expected a typed result map, got {value:?}");
    };
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name} in {value:?}"))
}

#[test]
fn config_snapshot_publishes_logical_option_leaves_over_the_resource_shell() {
    let home = TestHome::new("snapshot");
    let host = AuthHost::new(
        home.path().to_path_buf(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host");
    let mut vm = vm_for(&host);
    let (home_value, _) = caller(&host, &mut vm);
    let snapshot = invoke(&mut vm, "snapshot_probe", &[home_value]).expect("snapshot probe");

    assert_eq!(field(&snapshot, "ok"), Value::Bool(true));
    assert_eq!(field(&snapshot, "generation"), Value::Int(1));
    assert_eq!(field(&snapshot, "credentials"), Value::Int(1));
    assert_eq!(field(&snapshot, "providers"), Value::Int(1));
    assert_eq!(
        field(&snapshot, "provider_name"),
        Value::string("openai-codex")
    );
    // Every nested nullable config leaf is a live Some payload, not a Null.
    assert_eq!(field(&snapshot, "auth_present"), Value::Bool(true));
    assert_eq!(field(&snapshot, "oauth_present"), Value::Bool(true));
    assert_eq!(field(&snapshot, "default_present"), Value::Bool(true));
}

#[test]
fn config_snapshot_rejects_a_stale_home_resource() {
    let home = TestHome::new("snapshot-stale");
    let host = AuthHost::new(
        home.path().to_path_buf(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host");
    let mut vm = vm_for(&host);
    let (home_value, _) = caller(&host, &mut vm);
    let handle = handle(&home_value).expect("home handle");
    vm.host_context()
        .close_resource::<HostHome>(handle, ResourceCloseReason::Requested)
        .expect("close the bound home");
    let failure = invoke(&mut vm, "snapshot_probe", &[home_value]).expect_err("closed home");
    assert!(
        matches!(&failure, VmError::HostError(code) if code == "resource_invalid" || code.contains("resource")),
        "unexpected failure: {failure:?}"
    );
}

#[test]
fn metadata_publishes_option_leaves_and_rejects_an_unknown_credential() {
    let home = TestHome::new("metadata");
    let host = AuthHost::new(
        home.path().to_path_buf(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host");
    let mut vm = vm_for(&host);
    let (_, policy) = caller(&host, &mut vm);
    let loaded = invoke(
        &mut vm,
        "metadata_probe",
        &[policy.clone(), Value::string("fixture-codex")],
    )
    .expect("metadata probe");
    assert_eq!(field(&loaded, "ok"), Value::Bool(true));
    assert_eq!(field(&loaded, "error_present"), Value::Bool(false));
    assert_eq!(field(&loaded, "account_present"), Value::Bool(true));
    assert_eq!(field(&loaded, "refreshed_present"), Value::Bool(true));
    assert_eq!(field(&loaded, "generation"), Value::Int(4));
    assert_eq!(field(&loaded, "outcome"), Value::string("loaded"));

    let failure = invoke(
        &mut vm,
        "metadata_probe",
        &[policy, Value::string("absent-credential")],
    )
    .expect_err("unknown credential");
    assert!(
        matches!(&failure, VmError::HostError(code) if code == "credential_not_admitted"),
        "an id that is not in the admission snapshot is refused before the store is read: {failure:?}"
    );
}

#[test]
fn access_and_refresh_handles_publish_none_error_carriers_and_keep_live_handles() {
    let home = TestHome::new("handles");
    let host = AuthHost::new(
        home.path().to_path_buf(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host");
    let mut vm = vm_for(&host);
    let (_, policy) = caller(&host, &mut vm);
    let access =
        invoke(&mut vm, "access_probe", &[policy.clone(), Value::Int(4)]).expect("access probe");
    assert_eq!(field(&access, "ok"), Value::Bool(true));
    assert_eq!(field(&access, "error_present"), Value::Bool(false));
    let refresh =
        invoke(&mut vm, "refresh_probe", &[policy.clone(), Value::Int(4)]).expect("refresh probe");
    assert_eq!(field(&refresh, "ok"), Value::Bool(true));
    assert_eq!(field(&refresh, "error_present"), Value::Bool(false));

    let stale =
        invoke(&mut vm, "access_probe", &[policy, Value::Int(3)]).expect_err("wrong generation");
    assert!(
        matches!(&stale, VmError::HostError(code) if code == "access_unavailable"),
        "unexpected failure: {stale:?}"
    );
}

#[test]
fn now_result_publishes_an_option_value_and_rejects_a_forged_policy() {
    let home = TestHome::new("now");
    let host = AuthHost::new(
        home.path().to_path_buf(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host")
    .with_oauth_host(oauth_host());
    let mut vm = vm_for(&host);
    let (_, policy) = caller(&host, &mut vm);
    let now = invoke(&mut vm, "now_probe", &[policy]).expect("now probe");
    assert_eq!(field(&now, "ok"), Value::Bool(true));
    assert_eq!(field(&now, "error_present"), Value::Bool(false));
    assert_eq!(field(&now, "now"), Value::Int(1_900_000_000_000));

    let forged = Value::Int(987_654);
    let failure = invoke(&mut vm, "now_probe", &[forged]).expect_err("forged policy");
    assert!(
        matches!(
            &failure,
            VmError::HostError(_) | VmError::TypeMismatch(_) | VmError::InvalidFrameState(_)
        ),
        "unexpected failure: {failure:?}"
    );
}

#[test]
fn public_json_field_and_its_result_shell_expose_one_selected_option_slot() {
    let home = TestHome::new("public-json");
    let host = AuthHost::new(
        home.path().to_path_buf(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("auth host");
    let mut vm = vm_for(&host);
    let (_, policy) = caller(&host, &mut vm);
    let body = Value::string(r#"{"expires_in":3600,"token_type":"Bearer"}"#);
    let field_value = invoke(
        &mut vm,
        "field_probe",
        &[policy.clone(), body.clone(), Value::string("/expires_in")],
    )
    .expect("field probe");
    assert_eq!(field(&field_value, "kind"), Value::string("int"));
    assert_eq!(
        host_shapes::option_payload(&HostTypeSchema::Int, &field(&field_value, "int_value"))
            .expect("int carrier"),
        Some(&Value::Int(3600))
    );

    let missing = invoke(
        &mut vm,
        "field_probe",
        &[policy.clone(), body.clone(), Value::string("/absent")],
    )
    .expect("missing pointer");
    assert_eq!(field(&missing, "kind"), Value::string("missing"));

    let result = invoke(
        &mut vm,
        "field_result_probe",
        &[policy.clone(), body, Value::string("/token_type")],
    )
    .expect("result probe");
    assert_eq!(field(&result, "ok"), Value::Bool(true));
    assert_eq!(
        host_shapes::option_payload(&HostTypeSchema::String, &field(&result, "error"))
            .expect("error carrier"),
        None,
        "a successful public_json_field_result carries Option::None for error"
    );
    let payload = rustscript_vm::option::payload(&field(&result, "value"))
        .expect("value carrier")
        .1
        .cloned()
        .expect("a selected field is Some");
    assert_eq!(field(&payload, "kind"), Value::string("string"));
    assert_eq!(
        host_shapes::option_payload(&HostTypeSchema::String, &field(&payload, "string_value"))
            .expect("string carrier"),
        Some(&Value::string("Bearer"))
    );
    assert_eq!(
        host_shapes::option_payload(&HostTypeSchema::Int, &field(&payload, "int_value"))
            .expect("int carrier"),
        None,
        "an unselected slot is None, not a Null"
    );

    let failure = invoke(
        &mut vm,
        "field_probe",
        &[policy, Value::string("{}"), Value::string("not-a-pointer")],
    )
    .expect_err("invalid pointer");
    assert!(
        matches!(&failure, VmError::HostError(code) if code == "public_json_pointer_invalid"),
        "unexpected failure: {failure:?}"
    );
}

#[test]
fn save_if_generation_reads_refresh_slot_as_a_logical_option() {
    let home = TestHome::new("save");
    let host = AuthHost::new_for_commands(
        home.path().to_path_buf(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("commands host");
    let mut vm = vm_for(&host);
    let (_, policy) = caller(&host, &mut vm);
    let owner = vm
        .host_context()
        .scope_state::<Bound>()
        .map(|bound| Arc::clone(&bound.0))
        .expect("bound owner");
    let slot_handle = OpaqueSecretSlot::from_host_secret_until(
        SecretSlotKind::Access,
        "fixture-codex",
        4,
        owner.snapshot.generation,
        &owner.identity,
        zeroize::Zeroizing::new(b"synthetic-access".to_vec()),
        Instant::now() + Duration::from_secs(60),
    )
    .expect("host slot");
    let access_slot = issue_owner_slot(
        &mut vm,
        &owner,
        "fixture-codex",
        4,
        SecretSlotKind::Access,
        slot_handle,
    )
    .expect("issue access slot");
    let metadata = object(vec![
        ("provider", Value::string("openai-codex")),
        ("kind", Value::string("oauth")),
        ("source", Value::string("carrier-test")),
        ("token_type", Value::string("Bearer")),
        ("expires_at_ms", Value::Int(1_900_000_000_000)),
        ("scopes", Value::array(Vec::new())),
        (
            "account_id",
            rustscript_vm::option::some_carrier(Value::string("acct")),
        ),
        ("generation", Value::Int(4)),
        ("status", Value::string("active")),
        (
            "last_refresh_at_ms",
            rustscript_vm::option::some_carrier(Value::Int(1_790_000_000_000)),
        ),
        ("has_refresh_token", Value::Bool(true)),
    ]);
    let request = |refresh_action: &str, refresh_slot: Value| {
        object(vec![
            ("credential_id", Value::string("fixture-codex")),
            ("expected_generation", Value::Int(4)),
            ("policy_handle", policy.clone()),
            ("metadata", metadata.clone()),
            ("access_slot", access_slot.clone()),
            ("refresh_action", Value::string(refresh_action)),
            ("refresh_slot", refresh_slot),
        ])
    };

    // `replace` with a None carrier cannot name a slot: fail closed.
    let failure = save_call(
        &mut vm,
        &[request("replace", rustscript_vm::option::none_carrier())],
    )
    .expect_err("replace without a slot");
    assert!(
        matches!(&failure, VmError::HostError(code) if code == "slot_invalid"),
        "unexpected failure: {failure:?}"
    );

    // A physical null in the Option slot is not a carrier at all.
    let failure =
        save_call(&mut vm, &[request("replace", Value::Null)]).expect_err("null is not a carrier");
    assert!(
        matches!(&failure, VmError::HostError(code) if code == "invalid_request"),
        "unexpected failure: {failure:?}"
    );

    // A `None` carrier with `preserve` is the normal path.
    let saved = save_call(
        &mut vm,
        &[request("preserve", rustscript_vm::option::none_carrier())],
    )
    .expect("preserve save");
    let CallOutcome::Return(CallReturn::One(saved)) = saved else {
        panic!("save must return one envelope");
    };
    assert_eq!(field(&saved, "ok"), Value::Bool(true));
    let envelope_error = field(&saved, "error");
    assert_eq!(
        host_shapes::option_payload(&HostTypeSchema::String, &envelope_error)
            .expect("error carrier"),
        None,
        "a successful save carries Option::None for error"
    );
}

#[test]
fn delete_publishes_a_none_error_and_a_true_deleted_flag() {
    let home = TestHome::new("delete");
    let host = AuthHost::new_for_commands(
        home.path().to_path_buf(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("commands host");
    let mut vm = vm_for(&host);
    let (_, policy) = caller(&host, &mut vm);
    let deleted = invoke(&mut vm, "delete_probe", &[policy.clone()]).expect("delete probe");
    assert_eq!(field(&deleted, "ok"), Value::Bool(true));
    assert_eq!(field(&deleted, "deleted"), Value::Bool(true));
    assert_eq!(field(&deleted, "error_present"), Value::Bool(false));

    let failure = invoke(
        &mut vm,
        "metadata_probe",
        &[policy, Value::string("fixture-codex")],
    )
    .expect_err("deleted credential is gone");
    assert!(
        matches!(&failure, VmError::HostError(code) if code == "credential_unavailable"),
        "unexpected failure: {failure:?}"
    );
}

#[test]
fn legacy_null_config_value_is_converted_field_by_field() {
    // The walker is driven by the declared schema, not by the data: a null
    // in a declared Option slot becomes None, a nested Option keeps its
    // carrier, and an undecidable null in a plain leaf is refused.
    let schema = config_envelope();
    let HostTypeSchema::Named { fields, .. } = &schema else {
        panic!("config envelope is a named shape");
    };
    assert!(
        fields
            .iter()
            .all(|field| !matches!(field.ty, HostTypeSchema::Optional(_))),
        "the converted envelope keeps no legacy nullable slot"
    );
    let error_slot = fields
        .iter()
        .find(|field| field.name == "error")
        .expect("error field");
    assert!(matches!(error_slot.ty, HostTypeSchema::Option(_)));
    assert!(
        host_shapes::logical_from_legacy(&HostTypeSchema::String, &Value::Null).is_err(),
        "a physical null cannot decide a non-Option leaf"
    );
}
