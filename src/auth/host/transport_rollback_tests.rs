//! Round-8 regression tests for the converted `oauth::transport` family.
//!
//! Two things are proven here, both through a real compiled RSS source, the
//! published `auth_host_catalog`, a real restricted registry and a real VM:
//!
//! * the response slots are logical `Option<resource<…>>` carriers whose `Some`
//!   payload is still a **live** handle (the guest closes it, which only works
//!   for a live resource of that exact type) and whose `None` is a tag, not a
//!   null;
//! * when the adapter issues handles and then fails afterwards — here the
//!   exchange pair cannot be published because the resource table is full — the
//!   rollback inside the issuing scope closes what it already issued and the
//!   typed error code survives.

use super::{AuthHost, LIMIT, auth_host_catalog};
use crate::auth::oauth::{
    OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
    ScriptedHttpsTransport,
};
use crate::runtime::RunCancellation;
use rustscript_vm::{Value, Vm, VmError, VmResult};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const PROBE: &str = r#"
use config;
use auth;
use oauth;

pub fn policy(home: resource<auth.host_home>) -> resource<auth.policy> {
    config::load_snapshot(&home).policy_handle
}

/// Issue one live access handle and hand it back, so the resource table fills
/// up deterministically from real host calls and the caller keeps it live.
pub fn pin_access(policy: resource<auth.policy>) -> resource<auth.access> {
    auth::access_handle("fixture-codex", 4, &policy).handle
}

pub fn start_device(policy: resource<auth.policy>) -> TransportResponseEnvelope {
    let request: TransportPublicRequest = {
        policy_handle: policy,
        credential_id: "fixture-codex",
        method: "POST",
        path: "/api/accounts/deviceauth/usercode",
        public_headers: [{name: "content-type", value: "application/json"}],
        public_body: "{\"client_id\":\"public-client-id\"}"
    };
    let usage: TransportCredentialUse = {kind: "none"};
    oauth::transport(&request, &usage)
}

/// A capture that publishes an exchange pair, i.e. it issues the two secret
/// slots first and only then has to publish the pair.
pub fn capture(policy: resource<auth.policy>, device: resource<oauth.device_session>) -> TransportCaptureEnvelope {
    let request: TransportPublicRequest = {
        policy_handle: policy,
        credential_id: "fixture-codex",
        method: "POST",
        path: "/oauth/token",
        public_headers: [{name: "content-type", value: "application/json"}],
        public_body: "{\"grant_type\":\"device_code\"}"
    };
    let usage: TransportCredentialUse = {kind: "device_session", device_handle: Some(device)};
    let payload: TransportPayloadIntent = {
        encoding: "json_object",
        secret_fields: "device",
        device_field: "device_id"
    };
    let capture: TransportCaptureIntent = {
        code_field: "authorization_code",
        redirect_uri: "https://auth.openai.com/deviceauth/callback"
    };
    oauth::transport_capture(&request, &usage, payload, capture)
}

/// One plain token transport that issues both secret slots (access and refresh)
/// and returns only the status, so the caller never touches the handles.
pub fn transport_status(policy: resource<auth.policy>) -> int {
    let request: TransportPublicRequest = {
        policy_handle: policy,
        credential_id: "fixture-codex",
        method: "POST",
        path: "/oauth/token",
        public_headers: [{name: "content-type", value: "application/json"}],
        public_body: "{\"grant_type\":\"authorization_code\"}"
    };
    let usage: TransportCredentialUse = {kind: "none"};
    let response: TransportResponseEnvelope = oauth::transport(&request, &usage);
    response.status
}

/// Closes one published secret slot. The close only succeeds for a live
/// resource of this exact type, so it is the proof that the `Some` payload is
/// still a handle rather than text or a bare number.
fn close_one_slot(slot: resource<auth.secret_slot>) -> bool {
    auth::close_slot(slot);
    true
}

fn close_one_device(device: resource<oauth.device_session>) -> bool {
    oauth::close_device(device);
    true
}

/// Reads the converted response the way the guest has to: an exhaustive Option
/// match per slot. The envelope carries live resources, so it is move-only —
/// every field is consumed exactly once and nothing is copied.
pub fn transport_frame(home: resource<auth.host_home>) -> map {
    let policy: resource<auth.policy> = config::load_snapshot(&home).policy_handle;
    let request: TransportPublicRequest = {
        policy_handle: policy,
        credential_id: "fixture-codex",
        method: "POST",
        path: "/api/accounts/deviceauth/usercode",
        public_headers: [{name: "content-type", value: "application/json"}],
        public_body: "{\"client_id\":\"public-client-id\"}"
    };
    let usage: TransportCredentialUse = {kind: "none"};
    let response: TransportResponseEnvelope = oauth::transport(&request, &usage);
    let error_present: bool = match response.error { Some(_) => true, None => false };
    let retry_present: bool = match response.retry_after_ms { Some(_) => true, None => false };
    let access_closed: bool = match response.access_slot {
        Some(slot) => close_one_slot(slot),
        None => false
    };
    let device_closed: bool = match response.device_handle {
        Some(device) => close_one_device(device),
        None => false
    };
    {
        ok: response.ok,
        error_present: error_present,
        retry_present: retry_present,
        status: response.status,
        body: response.body_without_secret_fields,
        access_closed: access_closed,
        device_closed: device_closed
    }
}
"#;

struct TestHome(PathBuf);

impl TestHome {
    fn new(label: &str) -> Self {
        let base =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"));
        let path = base.join(format!(
            "auth-transport-rollback-{label}-{}-{}",
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

fn vm_for(host: &AuthHost) -> Vm {
    let catalog = auth_host_catalog();
    let compiled = rustscript_vm::compile_source_with_flavor_and_options(
        PROBE,
        rustscript_vm::SourceFlavor::RustScript,
        rustscript_vm::CompileSourceFileOptions::default()
            .with_host_api_catalog(Arc::clone(&catalog)),
    )
    .expect("compile the transport probe against the published catalog");
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

/// The device-start wire body the fixture's `codex-device` flow expects.
const DEVICE_BODY: &str = "{\"device_code\":\"DEVICE-PRIVATE\",\"user_code\":\"TEST-USER\",\"verification_uri\":\"https://auth.openai.com/device\",\"expires_in\":900,\"interval\":5}";

/// A token response that carries one fresh access and one fresh refresh secret,
/// i.e. two slots the adapter has to issue in the same call.
const TOKEN_BODY: &str = "{\"access_token\":\"ACCESS-PRIVATE\",\"refresh_token\":\"REFRESH-PRIVATE\",\"token_type\":\"Bearer\",\"public\":\"refreshed\"}";

fn scripted_host(
    home: &TestHome,
    cancellation: RunCancellation,
    transport: Arc<ScriptedHttpsTransport>,
) -> Arc<AuthHost> {
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    Arc::new(
        AuthHost::new(home.path().to_path_buf(), cancellation)
            .expect("auth host")
            .with_oauth_host(oauth),
    )
}

fn bind_policy(host: &AuthHost, vm: &mut Vm) -> Value {
    let bound = host.bind_vm(vm).expect("bind run owner");
    let home = field(&bound, "host_home");
    invoke(vm, "policy", &[home]).expect("owner policy")
}

#[test]
fn transport_response_slots_are_live_handles_behind_option_carriers() {
    let home = TestHome::new("shape");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, DEVICE_BODY);
    let host = scripted_host(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        transport,
    );
    let mut vm = vm_for(&host);
    let bound = host.bind_vm(&mut vm).expect("bind run owner");
    let home_value = field(&bound, "host_home");

    let frame = invoke(&mut vm, "transport_frame", &[home_value]).expect("transport frame");

    assert_eq!(field(&frame, "ok"), Value::Bool(true));
    assert_eq!(field(&frame, "status"), Value::Int(200));
    // The success branch carries `None` carriers, not nulls.
    assert_eq!(field(&frame, "error_present"), Value::Bool(false));
    assert_eq!(field(&frame, "retry_present"), Value::Bool(false));
    // The device slot was a `Some`, and the guest closed it as a *live*
    // `oauth.device_session`: the payload crossed as a handle, not as text or a
    // plain int. A device-only response issues no secret slots, so the access
    // slot matched `None`.
    assert_eq!(
        field(&frame, "device_closed"),
        Value::Bool(true),
        "frame: {frame:?}"
    );
    assert_eq!(field(&frame, "access_closed"), Value::Bool(false));
    // No private value from the provider body leaks into the public frame.
    let body = field(&frame, "body");
    let Value::String(body) = body else {
        panic!("body is not text: {body:?}");
    };
    assert!(!body.contains("DEVICE-PRIVATE"), "{body}");
}

#[test]
fn transport_rollback_closes_the_slot_it_issued_before_the_failure() {
    let home = TestHome::new("rollback");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, TOKEN_BODY);
    let host = scripted_host(
        &home,
        RunCancellation::with_timeout(Duration::from_secs(30)),
        transport,
    );
    let mut vm = vm_for(&host);
    let policy = bind_policy(&host, &mut vm);

    // Fill the resource table with real, live access handles until exactly one
    // more handle fits. The response issues its access slot into that last slot
    // and then fails issuing the refresh slot, so a handle really was issued
    // before the failure — and the rollback scope has to close it.
    let mut pinned = Vec::new();
    while vm.host_context().resource_count() < LIMIT - 1 {
        pinned
            .push(invoke(&mut vm, "pin_access", &[policy.clone()]).expect("pin an access handle"));
    }
    let before = vm.host_context().resource_count();
    assert_eq!(before, LIMIT - 1, "exactly one handle still fits");

    let failure = invoke(&mut vm, "transport_status", &[policy]).expect_err(
        "an issue that runs out of resource table must fail the call, not publish a half response",
    );
    assert!(
        matches!(&failure, VmError::HostError(code) if code == "resource_limit"),
        "unexpected failure: {failure:?}"
    );
    // The access slot issued inside this call was closed by the rollback scope,
    // so the table is exactly where it was before the call.
    assert_eq!(
        vm.host_context().resource_count(),
        before,
        "the handle issued before the failure must be closed, not leaked"
    );
}
