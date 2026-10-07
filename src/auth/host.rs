//! Resource-backed, run-scoped config and credential host functions.
//! The RSS boundary carries only typed public records and Core arena resources.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Instant;

use rustscript_vm::resource::{
    CloseProgress, HostResource, ResourceCloseReason, ResourceHandle, ResourceResult,
};
use rustscript_vm::{
    CallOutcome, CallReturn, HostApiCatalog, HostFunctionDescriptor, HostFunctionRegistry,
    HostFunctionSchema, HostModuleDescriptor, HostParamPassing, HostParamSchema, HostResourceType,
    HostResourceTypeMeta, HostStructField, HostTypeSchema, ResourceTypeKey, Value, Vm, VmError,
    VmResult,
};
use serde_json::{Value as Json, json};
use url::Url;
use uuid::Uuid;

use crate::auth::config::CredentialConfig;
use crate::auth::oauth::{
    CredentialUse, NativeTransportIntents, OAuthHost, OpaqueExchangePair, ProviderRequest,
    SanitizedProviderResponse, TrustedEndpoint, TrustedTransportPolicy,
};
use crate::auth::store::{
    AuthMetadata, AuthStore, AuthStoreError, OpaqueAccessHandle, OpaqueRefreshHandle,
    OpaqueSecretSlot, RefreshSecretAction, SaveCredentialRequest as StoreSaveRequest,
    SecretSlotKind,
};
use crate::auth::token::CredentialId;
use crate::config_file::{AgentPaths, ConfigFile};
use crate::domain::json_to_vm_value;
use crate::runtime::rss_runner::RunCancellation;

const LIMIT: usize = 64;

mod authorization_io;
mod capture;
mod cli_io;
mod device;
mod fallible;
mod flow;
mod paths;
mod payload;
mod public_json;
mod timing;
mod transients;

pub use authorization_io::{
    AuthorizationInstructionSender, PublicAuthorizationInstruction,
    authorization_instruction_channel,
};

pub use crate::auth::device_output::NativeDeviceInstructionOutput;
pub use cli_io::{
    DeviceInstructionSender, DeviceInstructionSink, PublicDeviceInstruction, RunOAuthCancel,
    SystemOAuthClock, device_instruction_channel,
};
pub use paths::ConfigPathHost;
pub(crate) use paths::PATH_IMPORT_NAME;

macro_rules! resource {
    ($name:ident, $key:literal, $description:literal) => {
        impl HostResource for $name {
            fn resource_type_key() -> Option<ResourceTypeKey> {
                Some(ResourceTypeKey::new($key).expect("static resource key"))
            }
            fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
                Ok(CloseProgress::Ready)
            }
        }
        impl HostResourceType for $name {
            const KEY: &'static str = $key;
            const DESCRIPTION: &'static str = $description;
        }
    };
}

struct HostHome {
    owner: Arc<Owner>,
}
struct Policy {
    owner: Arc<Owner>,
}
struct Access {
    owner: Arc<Owner>,
    handle: OpaqueAccessHandle,
}
struct Refresh {
    owner: Arc<Owner>,
    handle: OpaqueRefreshHandle,
}
struct SecretSlot {
    owner: Arc<Owner>,
    slot: OpaqueSecretSlot,
}
resource!(HostHome, "auth.host_home", "Trusted host home for this run");
resource!(Policy, "auth.policy", "Frozen credential admission policy");
impl HostResource for Access {
    fn resource_type_key() -> Option<ResourceTypeKey> {
        Some(ResourceTypeKey::new(Self::KEY).expect("static key"))
    }
    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        self.handle.force_expire();
        Ok(CloseProgress::Ready)
    }
}
impl HostResourceType for Access {
    const KEY: &'static str = "auth.access";
    const DESCRIPTION: &'static str = "One-shot access credential";
}
impl HostResource for Refresh {
    fn resource_type_key() -> Option<ResourceTypeKey> {
        Some(ResourceTypeKey::new(Self::KEY).expect("static key"))
    }
    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        self.handle.force_expire();
        Ok(CloseProgress::Ready)
    }
}
impl HostResourceType for Refresh {
    const KEY: &'static str = "auth.refresh";
    const DESCRIPTION: &'static str = "Single-flight refresh credential";
}
impl HostResource for SecretSlot {
    fn resource_type_key() -> Option<ResourceTypeKey> {
        Some(ResourceTypeKey::new(Self::KEY).expect("static key"))
    }
    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        self.slot.revoke();
        Ok(CloseProgress::Ready)
    }
}
impl HostResourceType for SecretSlot {
    const KEY: &'static str = "auth.secret_slot";
    const DESCRIPTION: &'static str = "One-shot host-issued secret slot";
}

struct Snapshot {
    config: ConfigFile,
    allowed: BTreeSet<String>,
    credential_generations: BTreeMap<String, u64>,
    generation: u64,
}
struct Owner {
    identity: String,
    deadline: Instant,
    cancellation: RunCancellation,
    revoked: AtomicBool,
    policy: Mutex<Option<ResourceHandle>>,
    snapshot: Arc<Snapshot>,
    store: AuthStore,
    oauth: Option<Arc<OAuthHost>>,
    oauth_callback_fixture: bool,
    oauth_callback_native: bool,
    device_instruction_sender: Option<DeviceInstructionSender>,
    authorization_instruction_sender: Option<AuthorizationInstructionSender>,
}
impl Owner {
    fn check(&self) -> VmResult<()> {
        if self.revoked.load(Ordering::Acquire)
            || self.cancellation.token().is_cancelled()
            || Instant::now() >= self.deadline
        {
            return Err(error("policy_inactive"));
        }
        Ok(())
    }
    fn authorize(&self, id: &str) -> VmResult<()> {
        self.check()?;
        if !self.snapshot.allowed.contains(id) {
            return Err(error("credential_not_admitted"));
        }
        CredentialId::new(id.to_owned()).map_err(|_| error("invalid_credential_id"))?;
        Ok(())
    }
    fn oauth_callback_available(&self) -> bool {
        self.oauth_callback_fixture || self.oauth_callback_native
    }
}
struct Bound(Arc<Owner>);

/// Trusted home and immutable admission snapshots. Reload affects future binds only.
enum AdmissionMode {
    Strict,
    Enrollment(String),
    Login,
    Commands,
}

pub struct AuthHost {
    paths: AgentPaths,
    store: AuthStore,
    cancellation: RunCancellation,
    admission: AdmissionMode,
    published: Mutex<Arc<Snapshot>>,
    next_generation: AtomicU64,
    owners: Mutex<Vec<std::sync::Weak<Owner>>>,
    oauth: Option<Arc<OAuthHost>>,
    oauth_callback_fixture: bool,
    device_instruction_sender: Option<DeviceInstructionSender>,
    authorization_instruction_sender: Option<AuthorizationInstructionSender>,
}

impl AuthHost {
    pub fn new(home: impl Into<PathBuf>, cancellation: RunCancellation) -> Result<Self, String> {
        Self::construct(home.into(), cancellation, AdmissionMode::Strict)
    }

    /// Trusted native opt-in to enroll one explicitly configured credential.
    pub fn new_for_enrollment(
        home: impl Into<PathBuf>,
        cancellation: RunCancellation,
        credential_id: impl Into<String>,
    ) -> Result<Self, String> {
        let credential_id = credential_id.into();
        CredentialId::new(credential_id.clone()).map_err(|_| "invalid_credential_id")?;
        Self::construct(
            home.into(),
            cancellation,
            AdmissionMode::Enrollment(credential_id),
        )
    }

    /// Trusted native opt-in for login using configured credential references only.
    pub fn new_for_login(
        home: impl Into<PathBuf>,
        cancellation: RunCancellation,
    ) -> Result<Self, String> {
        Self::construct(home.into(), cancellation, AdmissionMode::Login)
    }

    /// Trusted native opt-in for bounded auth-command diagnostics and mutations.
    pub fn new_for_commands(
        home: impl Into<PathBuf>,
        cancellation: RunCancellation,
    ) -> Result<Self, String> {
        Self::construct(home.into(), cancellation, AdmissionMode::Commands)
    }

    fn construct(
        home: PathBuf,
        cancellation: RunCancellation,
        admission: AdmissionMode,
    ) -> Result<Self, String> {
        let deadline = cancellation
            .deadline_instant()
            .ok_or("finite_deadline_required")?;
        if deadline <= Instant::now() || cancellation.has_deadline_overflow() {
            return Err("finite_deadline_required".into());
        }
        let paths = AgentPaths::from_home(home).map_err(|_| "invalid_host_home")?;
        let store = match &admission {
            AdmissionMode::Commands | AdmissionMode::Login => {
                // Login must inspect config before RSS decides whether to save credentials.
                AuthStore::open_for_commands(paths.clone())
            }
            AdmissionMode::Strict | AdmissionMode::Enrollment(_) => AuthStore::open(paths.clone()),
        }
        .map_err(|_| "auth_store_unavailable")?;
        let snapshot = Arc::new(load_snapshot(&paths, &store, 1, &admission)?);
        Ok(Self {
            paths,
            store,
            cancellation,
            admission,
            published: Mutex::new(snapshot),
            next_generation: AtomicU64::new(2),
            owners: Mutex::new(Vec::new()),
            oauth: None,
            oauth_callback_fixture: false,
            device_instruction_sender: None,
            authorization_instruction_sender: None,
        })
    }

    /// Explicit transport dependency; no implicit network or fixture default.
    pub fn with_oauth_host(mut self, oauth: Arc<OAuthHost>) -> Self {
        self.oauth = Some(oauth);
        self
    }

    /// Attach an explicitly supplied bounded native device-instruction queue.
    pub fn with_device_instruction_sender(mut self, sender: DeviceInstructionSender) -> Self {
        self.device_instruction_sender = Some(sender);
        self
    }

    /// Attach a native bounded authorization-instruction queue explicitly.
    pub fn with_authorization_instruction_sender(
        mut self,
        sender: AuthorizationInstructionSender,
    ) -> Self {
        self.authorization_instruction_sender = Some(sender);
        self
    }

    /// Explicitly enable the synthetic callback bridge for fixture tests only.
    #[cfg(any(test, feature = "config-fixture"))]
    pub fn with_oauth_callback_fixture(mut self) -> Self {
        self.oauth_callback_fixture = true;
        self
    }

    /// Publish a newly validated snapshot; already bound VMs keep their old admission.
    pub fn reload(&self) -> Result<u64, String> {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let snapshot = Arc::new(load_snapshot(
            &self.paths,
            &self.store,
            generation,
            &self.admission,
        )?);
        *self.published.lock().unwrap_or_else(|p| p.into_inner()) = snapshot;
        Ok(generation)
    }

    /// Explicitly revoke every active run bound by this host.
    pub fn revoke(&self) {
        let mut owners = self.owners.lock().unwrap_or_else(|p| p.into_inner());
        owners.retain(|weak| {
            if let Some(owner) = weak.upgrade() {
                owner.revoked.store(true, Ordering::Release);
                if let Some(oauth) = &owner.oauth {
                    oauth.revoke_run(&owner.identity);
                }
                true
            } else {
                false
            }
        });
    }

    pub fn register(
        &self,
        registry: &mut HostFunctionRegistry,
        catalog: &HostApiCatalog,
    ) -> VmResult<()> {
        auth_host_module()
            .install_from_catalog(registry, catalog)
            .map(|_| ())
    }

    /// Install a fresh VM owner and return the only RSS entry context.
    pub fn bind_vm(&self, vm: &mut Vm) -> VmResult<Value> {
        let snapshot = self
            .published
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let deadline = self
            .cancellation
            .deadline_instant()
            .ok_or_else(|| error("finite_deadline_required"))?;
        let oauth = self.oauth.clone();
        let oauth_callback_native = oauth
            .as_ref()
            .is_some_and(|oauth| oauth.has_native_callbacks());
        let owner = Arc::new(Owner {
            identity: Uuid::new_v4().to_string(),
            deadline,
            cancellation: self.cancellation.clone(),
            revoked: AtomicBool::new(false),
            policy: Mutex::new(None),
            snapshot,
            store: self.store.clone(),
            oauth,
            oauth_callback_fixture: self.oauth_callback_fixture,
            oauth_callback_native,
            device_instruction_sender: self.device_instruction_sender.clone(),
            authorization_instruction_sender: self.authorization_instruction_sender.clone(),
        });
        owner.check()?;
        let mut context = vm.host_context();
        if context.scope_state::<Bound>().is_some()
            || context.scope_state::<paths::BoundPaths>().is_some()
        {
            return Err(error("already_bound"));
        }
        if context.resource_count() >= LIMIT {
            return Err(error("resource_limit"));
        }
        let home = context
            .push_resource(HostHome {
                owner: owner.clone(),
            })
            .map_err(|_| error("resource_unavailable"))?;
        if context
            .scope_state_or_insert_with(|| Bound(owner.clone()))
            .is_err()
        {
            let _ =
                context.close_resource::<HostHome>(home.handle(), ResourceCloseReason::Requested);
            return Err(error("resource_unavailable"));
        }
        self.owners
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(Arc::downgrade(&owner));
        Ok(object(vec![(
            "host_home",
            Value::Int(home.handle().raw() as i64),
        )]))
    }

    /// Derive a host-only OAuth transport view from a live, host-issued policy.
    pub fn trusted_transport_policy(
        &self,
        vm: &mut Vm,
        policy: &Value,
        credential_id: &str,
    ) -> VmResult<TrustedTransportPolicy> {
        let owner = policy_owner(vm, policy, credential_id)?;
        if !self
            .owners
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|weak| {
                weak.upgrade()
                    .is_some_and(|candidate| Arc::ptr_eq(&candidate, &owner))
            })
        {
            return Err(error("owner_mismatch"));
        }
        transport_policy(&owner, credential_id)
    }

    /// Host-only fixture slot issuer. Never exposed as an RSS host function.
    #[cfg(any(test, feature = "config-fixture"))]
    pub fn fixture_slot(
        &self,
        vm: &mut Vm,
        credential_id: &str,
        expected_generation: u64,
        refresh: bool,
        bytes: &str,
    ) -> VmResult<Value> {
        let owner = bound(vm)?;
        owner.authorize(credential_id)?;
        let kind = if refresh {
            SecretSlotKind::Refresh
        } else {
            SecretSlotKind::Access
        };
        let slot = owner
            .store
            .fixture_secret_slot(
                kind,
                credential_id,
                expected_generation,
                owner.snapshot.generation,
                &owner.identity,
                bytes,
            )
            .map_err(|_| error("slot_invalid"))?;
        self.issue_transport_slot(vm, credential_id, expected_generation, kind, slot)
    }

    /// Host-only fixture callback injection; no raw callback payload enters RSS.
    #[cfg(any(test, feature = "config-fixture"))]
    pub fn fixture_inject_matching_callback(
        &self,
        vm: &mut Vm,
        callback: &Value,
        code: &str,
    ) -> VmResult<()> {
        let owner = bound(vm)?;
        owner.check()?;
        self.ensure_owned_owner(&owner)?;
        flow::fixture_inject_matching_callback(vm, callback, code, &owner)
    }

    /// Host-only fixture assertion for OAuth primitive flow cleanup.
    #[cfg(any(test, feature = "config-fixture"))]
    pub fn fixture_live_oauth_flow_count(&self) -> VmResult<usize> {
        self.oauth
            .as_ref()
            .map(|oauth| oauth.live_flow_count())
            .ok_or_else(|| error("callback_unavailable"))
    }

    /// Host-only fixture assertion for an admitted run's frozen generation.
    #[cfg(any(test, feature = "config-fixture"))]
    pub fn fixture_policy_generation(&self, vm: &mut Vm) -> VmResult<u64> {
        let owner = bound(vm)?;
        self.ensure_owned_owner(&owner)?;
        owner.check()?;
        Ok(owner.snapshot.generation)
    }

    #[cfg(any(test, feature = "config-fixture"))]
    fn ensure_owned_owner(&self, owner: &Arc<Owner>) -> VmResult<()> {
        if self
            .owners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .any(|weak| {
                weak.upgrade()
                    .is_some_and(|candidate| Arc::ptr_eq(&candidate, owner))
            })
        {
            Ok(())
        } else {
            Err(error("owner_mismatch"))
        }
    }

    /// Transport-side insertion; only Rust callers can supply the opaque payload.
    #[allow(dead_code)] // Fixture issuer is feature-gated; the bridge uses issue_owner_slot.
    pub(crate) fn issue_transport_slot(
        &self,
        vm: &mut Vm,
        credential_id: &str,
        expected_generation: u64,
        kind: SecretSlotKind,
        slot: OpaqueSecretSlot,
    ) -> VmResult<Value> {
        let owner = bound(vm)?;
        if !self
            .owners
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|weak| {
                weak.upgrade()
                    .is_some_and(|candidate| Arc::ptr_eq(&candidate, &owner))
            })
        {
            return Err(error("owner_mismatch"));
        }
        issue_owner_slot(vm, &owner, credential_id, expected_generation, kind, slot)
    }
}

fn transport_policy(owner: &Arc<Owner>, credential_id: &str) -> VmResult<TrustedTransportPolicy> {
    let mut endpoints = Vec::new();
    for provider in owner.snapshot.config.providers.values() {
        if provider.auth.as_deref() != Some(credential_id) {
            continue;
        }
        let base = trusted_url_endpoint(&provider.base_url)?;
        let base_authority = base.authority.clone();
        push_endpoint(&mut endpoints, base);
        if let Some(oauth) = &provider.oauth {
            if let Some(token) = &oauth.token_endpoint {
                push_endpoint(&mut endpoints, trusted_url_endpoint(token)?);
            }
            let issuer_authority = oauth
                .issuer
                .as_deref()
                .map(trusted_url_endpoint)
                .transpose()?
                .map_or(base_authority, |issuer| issuer.authority);
            for path in [
                &oauth.authorization_path,
                &oauth.device_user_code_path,
                &oauth.device_poll_path,
            ]
            .into_iter()
            .flatten()
            {
                if !path.starts_with('/')
                    || path.starts_with("//")
                    || path.contains("..")
                    || path.contains("://")
                    || path.contains('?')
                    || path.contains('#')
                {
                    return Err(error("transport_endpoint_invalid"));
                }
                push_endpoint(
                    &mut endpoints,
                    TrustedEndpoint {
                        authority: issuer_authority.clone(),
                        path_prefix: trusted_path_prefix(path),
                    },
                );
            }
        }
    }
    if endpoints.is_empty() {
        return Err(error("transport_endpoint_unavailable"));
    }
    // OAuthHost selects the first matching prefix without considering authority.
    // Refuse any path that could select a different authority by list order.
    for (index, left) in endpoints.iter().enumerate() {
        for right in &endpoints[index + 1..] {
            if left.authority != right.authority
                && (transport_prefix_matches(&left.path_prefix, &right.path_prefix)
                    || transport_prefix_matches(&right.path_prefix, &left.path_prefix))
            {
                return Err(error("transport_endpoint_ambiguous"));
            }
        }
    }
    owner.check()?;
    Ok(TrustedTransportPolicy {
        generation: owner.snapshot.generation,
        run_id: owner.identity.clone(),
        deadline: owner.deadline,
        endpoints,
        allowed_header_names: BTreeSet::from(["accept".into(), "content-type".into()]),
    })
}

fn issue_owner_slot(
    vm: &mut Vm,
    owner: &Arc<Owner>,
    credential_id: &str,
    expected_generation: u64,
    kind: SecretSlotKind,
    slot: OpaqueSecretSlot,
) -> VmResult<Value> {
    let issued = (|| {
        owner.authorize(credential_id)?;
        slot.validate_for_request(
            kind,
            credential_id,
            expected_generation,
            owner.snapshot.generation,
            &owner.identity,
        )
        .map_err(|_| error("slot_provenance_invalid"))?;
        let value = issue(
            vm,
            SecretSlot {
                owner: owner.clone(),
                slot: slot.clone(),
            },
        )?;
        if let Err(failure) = owner.check() {
            close_issued_slot(vm, &value);
            return Err(failure);
        }
        Ok(value)
    })();
    if issued.is_err() {
        slot.revoke();
    }
    issued
}

fn close_issued_slot(vm: &mut Vm, value: &Value) {
    if let Ok(handle) = handle(value) {
        let _ = vm
            .host_context()
            .close_resource::<SecretSlot>(handle, ResourceCloseReason::Requested);
    }
}

fn trusted_url_endpoint(value: &str) -> VmResult<TrustedEndpoint> {
    let url = Url::parse(value).map_err(|_| error("transport_endpoint_invalid"))?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(error("transport_endpoint_invalid"));
    }
    let host = url
        .host()
        .ok_or_else(|| error("transport_endpoint_invalid"))?;
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    Ok(TrustedEndpoint {
        authority,
        path_prefix: trusted_path_prefix(url.path()),
    })
}

fn trusted_path_prefix(path: &str) -> String {
    path.trim_end_matches('/').to_string()
}

fn push_endpoint(endpoints: &mut Vec<TrustedEndpoint>, endpoint: TrustedEndpoint) {
    if !endpoints.contains(&endpoint) {
        endpoints.push(endpoint);
    }
}

fn transport_prefix_matches(prefix: &str, path: &str) -> bool {
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn load_snapshot(
    paths: &AgentPaths,
    store: &AuthStore,
    generation: u64,
    admission: &AdmissionMode,
) -> Result<Snapshot, String> {
    let config = ConfigFile::load(&paths.config).map_err(|_| "config_invalid")?;
    let auth = store.load().map_err(|_| "auth_invalid")?;
    let configured: BTreeSet<String> = config
        .providers
        .values()
        .filter_map(|provider| provider.auth.clone())
        .collect();
    let allowed = match admission {
        AdmissionMode::Strict => {
            config
                .validate_auth_references(&auth)
                .map_err(|_| "credential_reference_invalid")?;
            configured
        }
        AdmissionMode::Enrollment(id) => {
            if !configured.contains(id) {
                return Err("credential_not_admitted".into());
            }
            if !auth.credentials.contains_key(id) {
                // Exempt only the selected absent reference during validation.
                // Keep the published config intact for public and transport policy.
                let mut validation_config = config.clone();
                for provider in validation_config.providers.values_mut() {
                    if provider.auth.as_deref() == Some(id) {
                        provider.auth = None;
                    }
                }
                validation_config
                    .validate_auth_references(&auth)
                    .map_err(|_| "credential_reference_invalid")?;
            } else {
                config
                    .validate_auth_references(&auth)
                    .map_err(|_| "credential_reference_invalid")?;
            }
            BTreeSet::from([id.clone()])
        }
        AdmissionMode::Login => {
            if configured.len() > LIMIT {
                return Err("credential_limit_exceeded".into());
            }
            for id in &configured {
                CredentialId::new(id.clone()).map_err(|_| "invalid_credential_id")?;
            }
            // Login admission is config-scoped; only Commands includes orphan store entries.
            configured
        }
        AdmissionMode::Commands => {
            let mut union = configured;
            union.extend(auth.credentials.keys().cloned());
            if union.len() > LIMIT {
                return Err("credential_limit_exceeded".into());
            }
            for id in &union {
                CredentialId::new(id.clone()).map_err(|_| "invalid_credential_id")?;
            }
            union
        }
    };
    let mut credential_generations: BTreeMap<String, u64> = auth
        .credentials
        .iter()
        .map(|(id, credential)| (id.clone(), credential.generation))
        .collect();
    for id in &allowed {
        credential_generations.entry(id.clone()).or_insert(0);
    }
    Ok(Snapshot {
        config,
        allowed,
        credential_generations,
        generation,
    })
}
fn error(code: &str) -> VmError {
    VmError::HostError(code.to_string())
}

const PROVIDER_JSON_MAX_DEPTH: usize = 64;
const PROVIDER_JSON_MAX_NODES: usize = 65_536;

pub(crate) fn validate_provider_json_resources(vm: &mut Vm, value: &Value) -> VmResult<()> {
    let resource_types = auth_host_module()
        .resources
        .iter()
        .map(|resource_type| resource_type())
        .collect::<Vec<_>>();
    let mut remaining = PROVIDER_JSON_MAX_NODES;
    validate_provider_json_node(vm, value, 0, &mut remaining, &resource_types)
}

fn validate_provider_json_node(
    vm: &mut Vm,
    value: &Value,
    depth: usize,
    remaining: &mut usize,
    resource_types: &[HostResourceTypeMeta],
) -> VmResult<()> {
    if depth > PROVIDER_JSON_MAX_DEPTH || *remaining == 0 {
        return Err(error("serialization_bound_exceeded"));
    }
    *remaining -= 1;
    match value {
        Value::Int(raw) if *raw > 0 => {
            let Ok(raw) = u64::try_from(*raw) else {
                return Ok(());
            };
            let Ok(handle) = ResourceHandle::from_raw(raw) else {
                return Ok(());
            };
            for resource_type in resource_types {
                if vm
                    .host_context()
                    .execution_scope()
                    .resources()
                    .validate_resource_type_key(handle, &resource_type.schema.key)
                    .is_ok()
                {
                    return Err(error("opaque_nonserializable"));
                }
            }
        }
        Value::Map(entries) => {
            for (key, child) in entries.iter() {
                validate_provider_json_node(vm, key, depth + 1, remaining, resource_types)?;
                validate_provider_json_node(vm, child, depth + 1, remaining, resource_types)?;
            }
        }
        Value::Array(values) => {
            for child in values.iter() {
                validate_provider_json_node(vm, child, depth + 1, remaining, resource_types)?;
            }
        }
        _ => {}
    }
    Ok(())
}
#[allow(dead_code)] // Fixture-only slot issuer borrows the run owner.
fn bound(vm: &mut Vm) -> VmResult<Arc<Owner>> {
    vm.host_context()
        .scope_state::<Bound>()
        .map(|b| b.0.clone())
        .ok_or_else(|| error("host_unbound"))
}
fn handle(value: &Value) -> VmResult<ResourceHandle> {
    let Value::Int(raw) = value else {
        return Err(error("resource_invalid"));
    };
    ResourceHandle::from_raw((*raw).try_into().map_err(|_| error("resource_invalid"))?)
        .map_err(|_| error("resource_invalid"))
}
fn borrowed<T: HostResource + HostResourceType + OwnerResource>(
    vm: &mut Vm,
    value: &Value,
) -> VmResult<Arc<Owner>> {
    let context = vm.host_context();
    let entry = context
        .borrow_resource_with_key::<T>(
            handle(value)?,
            &ResourceTypeKey::new(T::KEY).expect("static key"),
        )
        .map_err(|_| error("resource_invalid"))?;
    let owner = entry.owner();
    let bound = context
        .scope_state::<Bound>()
        .ok_or_else(|| error("host_unbound"))?;
    if !Arc::ptr_eq(&owner, &bound.0) {
        return Err(error("owner_mismatch"));
    }
    owner.check()?;
    Ok(owner)
}
trait OwnerResource {
    fn owner(&self) -> Arc<Owner>;
}
impl OwnerResource for HostHome {
    fn owner(&self) -> Arc<Owner> {
        self.owner.clone()
    }
}
impl OwnerResource for Policy {
    fn owner(&self) -> Arc<Owner> {
        self.owner.clone()
    }
}
impl OwnerResource for Access {
    fn owner(&self) -> Arc<Owner> {
        self.owner.clone()
    }
}
impl OwnerResource for Refresh {
    fn owner(&self) -> Arc<Owner> {
        self.owner.clone()
    }
}
impl OwnerResource for SecretSlot {
    fn owner(&self) -> Arc<Owner> {
        self.owner.clone()
    }
}
fn issue<T: HostResource + HostResourceType + OwnerResource>(
    vm: &mut Vm,
    resource: T,
) -> VmResult<Value> {
    let track = transients::tracks(T::KEY);
    if track {
        transients::prepare(vm)?;
    }
    let owner = resource.owner();
    let handle = {
        let mut context = vm.host_context();
        if context.resource_count() >= LIMIT {
            return Err(error("resource_limit"));
        }
        let token = context
            .push_resource(resource)
            .map_err(|_| error("resource_unavailable"))?;
        token.handle()
    };
    if track && let Err(failure) = transients::register::<T>(vm, handle, Arc::downgrade(&owner)) {
        let _ = vm
            .host_context()
            .close_resource::<T>(handle, ResourceCloseReason::Requested);
        return Err(failure);
    }
    Ok(Value::Int(handle.raw() as i64))
}
fn object(fields: Vec<(&str, Value)>) -> Value {
    Value::map(
        fields
            .into_iter()
            .map(|(k, v)| (Value::string(k), v))
            .collect(),
    )
}
fn field<'a>(value: &'a Value, name: &str) -> VmResult<&'a Value> {
    if let Value::Map(entries) = value {
        entries
            .iter()
            .find_map(|(key, v)| match key {
                Value::String(s) if s.as_ref() == name => Some(v),
                _ => None,
            })
            .ok_or_else(|| error("invalid_request"))
    } else {
        Err(error("invalid_request"))
    }
}
fn string(value: &Value) -> VmResult<&str> {
    if let Value::String(s) = value {
        Ok(s)
    } else {
        Err(error("invalid_request"))
    }
}
fn natural(value: &Value) -> VmResult<u64> {
    if let Value::Int(n) = value {
        (*n).try_into().map_err(|_| error("invalid_request"))
    } else {
        Err(error("invalid_request"))
    }
}
fn result(value: Value) -> VmResult<CallOutcome> {
    Ok(CallOutcome::Return(CallReturn::One(value)))
}
fn key(name: &str) -> HostTypeSchema {
    HostTypeSchema::Resource(ResourceTypeKey::new(name).expect("static key"))
}
fn opt(ty: HostTypeSchema) -> HostTypeSchema {
    HostTypeSchema::Optional(Box::new(ty))
}
fn array(ty: HostTypeSchema) -> HostTypeSchema {
    HostTypeSchema::Array(Box::new(ty))
}
fn named(name: &str, fields: Vec<(&str, HostTypeSchema)>) -> HostTypeSchema {
    HostTypeSchema::named_struct(
        name,
        fields
            .into_iter()
            .map(|(n, t)| HostStructField::new(n, t))
            .collect(),
    )
}
fn metadata_type() -> HostTypeSchema {
    named(
        "AuthMetadata",
        vec![
            ("credential_id", HostTypeSchema::String),
            ("provider", HostTypeSchema::String),
            ("kind", HostTypeSchema::String),
            ("source", HostTypeSchema::String),
            ("token_type", HostTypeSchema::String),
            ("expires_at_ms", HostTypeSchema::Int),
            ("scopes", array(HostTypeSchema::String)),
            ("account_id", opt(HostTypeSchema::String)),
            ("generation", HostTypeSchema::Int),
            ("status", HostTypeSchema::String),
            ("last_refresh_at_ms", opt(HostTypeSchema::Int)),
            ("has_refresh_token", HostTypeSchema::Bool),
        ],
    )
}
fn credential_type() -> HostTypeSchema {
    named(
        "CredentialMetadata",
        vec![
            ("provider", HostTypeSchema::String),
            ("kind", HostTypeSchema::String),
            ("source", HostTypeSchema::String),
            ("token_type", HostTypeSchema::String),
            ("expires_at_ms", HostTypeSchema::Int),
            ("scopes", array(HostTypeSchema::String)),
            ("account_id", opt(HostTypeSchema::String)),
            ("generation", HostTypeSchema::Int),
            ("status", HostTypeSchema::String),
            ("last_refresh_at_ms", opt(HostTypeSchema::Int)),
            ("has_refresh_token", HostTypeSchema::Bool),
        ],
    )
}
fn config_type() -> HostTypeSchema {
    let s = HostTypeSchema::String;
    let i = HostTypeSchema::Int;
    let oauth = named(
        "OAuthConfig",
        vec![
            ("flow", opt(s.clone())),
            ("issuer", opt(s.clone())),
            ("client_id", opt(s.clone())),
            ("device_user_code_path", opt(s.clone())),
            ("device_poll_path", opt(s.clone())),
            ("authorization_path", opt(s.clone())),
            ("token_endpoint", opt(s.clone())),
            ("redirect_uri", opt(s.clone())),
            ("refresh_skew_seconds", i.clone()),
            ("scopes", opt(array(s.clone()))),
            (
                "authorization_parameters",
                opt(array(flow::public_query_entry_type())),
            ),
        ],
    );
    named(
        "BoundedPublicConfig",
        vec![
            ("version", i.clone()),
            (
                "agent",
                named(
                    "AgentConfig",
                    vec![
                        ("source", s.clone()),
                        ("max_turns", i.clone()),
                        ("max_tool_calls", i.clone()),
                        ("max_tool_output_bytes", i.clone()),
                    ],
                ),
            ),
            (
                "model",
                named(
                    "ModelConfig",
                    vec![("provider", s.clone()), ("model", s.clone())],
                ),
            ),
            (
                "providers",
                array(named(
                    "ProviderEntry",
                    vec![
                        ("name", s.clone()),
                        ("protocol", s.clone()),
                        ("base_url", s.clone()),
                        ("auth", opt(s.clone())),
                        ("oauth", opt(oauth)),
                    ],
                )),
            ),
            (
                "workspaces",
                named(
                    "WorkspaceConfig",
                    vec![
                        ("allowed_roots", array(s.clone())),
                        ("default", opt(s.clone())),
                    ],
                ),
            ),
            (
                "approvals",
                named(
                    "ApprovalConfig",
                    vec![
                        ("read", s.clone()),
                        ("write", s.clone()),
                        ("process", s.clone()),
                    ],
                ),
            ),
            (
                "compaction",
                named(
                    "CompactionConfig",
                    vec![
                        ("enabled", HostTypeSchema::Bool),
                        ("max_context_messages", i.clone()),
                        ("retained_tail", i),
                    ],
                ),
            ),
        ],
    )
}
fn envelope(name: &str, fields: Vec<(&str, HostTypeSchema)>) -> HostTypeSchema {
    let mut all = vec![
        ("ok", HostTypeSchema::Bool),
        ("error", opt(HostTypeSchema::String)),
    ];
    all.extend(fields);
    named(name, all)
}
fn config_envelope() -> HostTypeSchema {
    envelope(
        "ConfigSnapshotEnvelope",
        vec![
            ("public_config", config_type()),
            ("credential_refs", array(HostTypeSchema::String)),
            ("policy_handle", key(Policy::KEY)),
            ("policy_generation", HostTypeSchema::Int),
            (
                "policy_summary",
                named(
                    "PolicySummary",
                    vec![("credential_count", HostTypeSchema::Int)],
                ),
            ),
        ],
    )
}
fn metadata_envelope() -> HostTypeSchema {
    envelope(
        "AuthMetadataEnvelope",
        vec![
            ("metadata", metadata_type()),
            ("outcome", HostTypeSchema::String),
        ],
    )
}
fn handle_envelope(name: &str, ty: &str) -> HostTypeSchema {
    envelope(name, vec![("handle", key(ty))])
}
fn mutation_envelope() -> HostTypeSchema {
    envelope(
        "RedactedMutationResult",
        vec![("deleted", HostTypeSchema::Bool)],
    )
}
fn save_type() -> HostTypeSchema {
    named(
        "SaveCredentialRequest",
        vec![
            ("credential_id", HostTypeSchema::String),
            ("expected_generation", HostTypeSchema::Int),
            ("policy_handle", key(Policy::KEY)),
            ("metadata", credential_type()),
            ("access_slot", key(SecretSlot::KEY)),
            ("refresh_action", HostTypeSchema::String),
            ("refresh_slot", opt(key(SecretSlot::KEY))),
        ],
    )
}
fn public_header_type() -> HostTypeSchema {
    named(
        "PublicHeader",
        vec![
            ("name", HostTypeSchema::String),
            ("value", HostTypeSchema::String),
        ],
    )
}
fn transport_request_type() -> HostTypeSchema {
    named(
        "TransportPublicRequest",
        vec![
            ("policy_handle", key(Policy::KEY)),
            ("credential_id", HostTypeSchema::String),
            ("method", HostTypeSchema::String),
            ("path", HostTypeSchema::String),
            ("public_headers", array(public_header_type())),
            ("public_body", HostTypeSchema::String),
        ],
    )
}
fn transport_use_type() -> HostTypeSchema {
    named(
        "TransportCredentialUse",
        vec![
            ("kind", HostTypeSchema::String),
            ("access_handle", opt(key(Access::KEY))),
            ("refresh_handle", opt(key(Refresh::KEY))),
            ("code_handle", opt(key("oauth.authorization_code"))),
            ("verifier_handle", opt(key("oauth.verifier"))),
            ("device_handle", opt(key(device::DEVICE_KEY))),
        ],
    )
}
fn transport_response_type() -> HostTypeSchema {
    envelope(
        "TransportResponseEnvelope",
        vec![
            ("status", HostTypeSchema::Int),
            ("public_headers", array(public_header_type())),
            ("body_without_secret_fields", HostTypeSchema::String),
            ("retry_after_ms", opt(HostTypeSchema::Int)),
            ("access_slot", opt(key(SecretSlot::KEY))),
            ("refresh_slot", opt(key(SecretSlot::KEY))),
            ("device_handle", opt(key(device::DEVICE_KEY))),
        ],
    )
}
fn param(n: &'static str, ty: HostTypeSchema) -> HostParamSchema {
    HostParamSchema::value(n, ty)
}
fn borrow(n: &'static str, ty: HostTypeSchema) -> HostParamSchema {
    HostParamSchema::with_passing(n, ty, HostParamPassing::Borrow)
}
fn desc(
    name: &'static str,
    params: Vec<HostParamSchema>,
    output: HostTypeSchema,
    adapter: fn(&mut Vm, &[Value]) -> VmResult<CallOutcome>,
) -> HostFunctionDescriptor {
    let schema = HostFunctionSchema::with_return(name, params, output);
    let effects = rustscript_vm::vm::host_extension::guest_resource_effects(&schema);
    let mut descriptor = crate::runtime::host_compose::static_stack_descriptor(schema, adapter);
    descriptor.effects = effects;
    descriptor
}
fn config_desc() -> HostFunctionDescriptor {
    desc(
        "config::load_snapshot",
        vec![borrow("host_home", key(HostHome::KEY))],
        config_envelope(),
        config_call,
    )
}
fn transport_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::transport",
        vec![
            borrow("request", transport_request_type()),
            borrow("credential_use", transport_use_type()),
        ],
        transport_response_type(),
        transport_call,
    )
}
fn transport_payload_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::transport_payload",
        vec![
            borrow("request", transport_request_type()),
            borrow("credential_use", transport_use_type()),
            param("payload", payload::intent_type()),
        ],
        transport_response_type(),
        transport_payload_call,
    )
}
fn transport_capture_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::transport_capture",
        vec![
            borrow("request", transport_request_type()),
            borrow("credential_use", transport_use_type()),
            param("payload", payload::intent_type()),
            param("capture", capture::intent_type()),
        ],
        capture::envelope_type(),
        transport_capture_call,
    )
}
fn metadata_desc() -> HostFunctionDescriptor {
    desc(
        "auth::load_metadata",
        vec![
            param("credential_id", HostTypeSchema::String),
            borrow("policy_handle", key(Policy::KEY)),
        ],
        metadata_envelope(),
        metadata_call,
    )
}
fn access_desc() -> HostFunctionDescriptor {
    desc(
        "auth::access_handle",
        vec![
            param("credential_id", HostTypeSchema::String),
            param("expected_generation", HostTypeSchema::Int),
            borrow("policy_handle", key(Policy::KEY)),
        ],
        handle_envelope("AccessHandleEnvelope", Access::KEY),
        access_call,
    )
}
fn refresh_desc() -> HostFunctionDescriptor {
    desc(
        "auth::refresh_handle",
        vec![
            param("credential_id", HostTypeSchema::String),
            param("expected_generation", HostTypeSchema::Int),
            borrow("policy_handle", key(Policy::KEY)),
        ],
        handle_envelope("RefreshHandleEnvelope", Refresh::KEY),
        refresh_call,
    )
}
fn save_desc() -> HostFunctionDescriptor {
    desc(
        "auth::save_if_generation",
        vec![borrow("request", save_type())],
        metadata_envelope(),
        save_call,
    )
}
fn delete_desc() -> HostFunctionDescriptor {
    desc(
        "auth::delete",
        vec![
            param("credential_id", HostTypeSchema::String),
            borrow("policy_handle", key(Policy::KEY)),
        ],
        mutation_envelope(),
        delete_call,
    )
}
fn close_access_desc() -> HostFunctionDescriptor {
    desc(
        "auth::close_access",
        vec![HostParamSchema::with_passing(
            "handle",
            key(Access::KEY),
            HostParamPassing::TakeOwned,
        )],
        HostTypeSchema::Null,
        close_access,
    )
}
fn close_refresh_desc() -> HostFunctionDescriptor {
    desc(
        "auth::close_refresh",
        vec![HostParamSchema::with_passing(
            "handle",
            key(Refresh::KEY),
            HostParamPassing::TakeOwned,
        )],
        HostTypeSchema::Null,
        close_refresh,
    )
}
fn close_slot_desc() -> HostFunctionDescriptor {
    desc(
        "auth::close_slot",
        vec![HostParamSchema::with_passing(
            "handle",
            key(SecretSlot::KEY),
            HostParamPassing::TakeOwned,
        )],
        HostTypeSchema::Null,
        close_slot,
    )
}
fn host_home_meta() -> HostResourceTypeMeta {
    HostResourceTypeMeta::of::<HostHome>()
}
fn policy_meta() -> HostResourceTypeMeta {
    HostResourceTypeMeta::of::<Policy>()
}
fn access_meta() -> HostResourceTypeMeta {
    HostResourceTypeMeta::of::<Access>()
}
fn refresh_meta() -> HostResourceTypeMeta {
    HostResourceTypeMeta::of::<Refresh>()
}
fn slot_meta() -> HostResourceTypeMeta {
    HostResourceTypeMeta::of::<SecretSlot>()
}
pub fn auth_host_module() -> HostModuleDescriptor {
    HostModuleDescriptor {
        name: "auth",
        functions: &[
            config_desc,
            paths::resolved_path_result_desc,
            transport_desc,
            transport_payload_desc,
            transport_capture_desc,
            fallible::transport_result_desc,
            fallible::transport_payload_result_desc,
            fallible::transport_capture_result_desc,
            fallible::save_if_generation_result_desc,
            fallible::load_metadata_result_desc,
            fallible::access_handle_result_desc,
            fallible::delete_result_desc,
            fallible::now_ms_result_desc,
            fallible::wait_ms_result_desc,
            fallible::emit_device_instruction_result_desc,
            fallible::emit_authorization_instruction_result_desc,
            fallible::public_json_field_result_desc,
            transients::cleanup_desc,
            public_json::public_json_field_desc,
            metadata_desc,
            access_desc,
            refresh_desc,
            save_desc,
            delete_desc,
            close_access_desc,
            close_refresh_desc,
            close_slot_desc,
            device::close_desc,
            timing::now_ms_desc,
            timing::wait_ms_desc,
            flow::pkce_begin_desc,
            flow::pkce_begin_result_desc,
            flow::callback_wait_desc,
            flow::callback_wait_result_desc,
            flow::code_generation_result_desc,
            flow::close_callback_desc,
            flow::close_verifier_desc,
            flow::close_code_desc,
        ],
        resources: &[
            host_home_meta,
            paths::home_meta,
            policy_meta,
            access_meta,
            refresh_meta,
            slot_meta,
            device::meta,
            flow::callback_meta,
            flow::verifier_meta,
            flow::code_meta,
        ],
    }
}
pub fn auth_host_catalog() -> Arc<HostApiCatalog> {
    crate::runtime::host_compose::compose_with_standard(&[auth_host_module()])
}

fn config_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let owner = borrowed::<HostHome>(vm, args.first().ok_or_else(|| error("invalid_request"))?)?;
    let mut policy_guard = owner.policy.lock().unwrap_or_else(|p| p.into_inner());
    let policy = if let Some(existing) = *policy_guard {
        let value = Value::Int(existing.raw() as i64);
        borrowed::<Policy>(vm, &value)?;
        value
    } else {
        let value = issue(
            vm,
            Policy {
                owner: owner.clone(),
            },
        )?;
        *policy_guard = Some(handle(&value)?);
        value
    };
    drop(policy_guard);
    let mut public =
        serde_json::to_value(&owner.snapshot.config).map_err(|_| error("config_invalid"))?;
    if let Json::Object(ref mut fields) = public {
        fields.insert("providers".into(), Json::Array(owner.snapshot.config.providers.iter().map(|(name,provider)| json!({"name":name,"protocol":provider.protocol,"base_url":provider.base_url,"auth":provider.auth,"oauth":provider.oauth})).collect()));
    }
    result(object(vec![
        ("ok", Value::Bool(true)),
        ("error", Value::Null),
        ("public_config", json_to_vm_value(&public)),
        (
            "credential_refs",
            Value::array(owner.snapshot.allowed.iter().map(Value::string).collect()),
        ),
        ("policy_handle", policy),
        (
            "policy_generation",
            Value::Int(owner.snapshot.generation as i64),
        ),
        (
            "policy_summary",
            object(vec![(
                "credential_count",
                Value::Int(owner.snapshot.allowed.len() as i64),
            )]),
        ),
    ]))
}
fn optional_field<'a>(value: &'a Value, name: &str) -> VmResult<Option<&'a Value>> {
    let Value::Map(entries) = value else {
        return Err(error("invalid_request"));
    };
    Ok(entries.iter().find_map(|(key, value)| match key {
        Value::String(key) if key.as_ref() == name && !matches!(value, Value::Null) => Some(value),
        _ => None,
    }))
}

fn canonical_json_content_type(value: &str) -> bool {
    fn token(value: &str) -> bool {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    }

    fn ows(text: &str) -> &str {
        text.trim_matches([' ', '\t'])
    }
    let mut parts = value.split(';');
    if !parts
        .next()
        .is_some_and(|media| ows(media).eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    parts.all(|parameter| {
        let Some((name, value)) = ows(parameter).split_once('=') else {
            return false;
        };
        let value = ows(value);
        token(ows(name))
            && (token(value)
                || (value.len() >= 2
                    && value.starts_with('"')
                    && value.ends_with('"')
                    && value.as_bytes()[1..value.len() - 1]
                        .iter()
                        .all(|byte| (0x20..=0x7e).contains(byte) && *byte != b'"')))
    })
}

fn revoke_response(oauth: &OAuthHost, response: &SanitizedProviderResponse) {
    if let Some(slot) = &response.access_slot {
        slot.revoke();
    }
    if let Some(slot) = &response.refresh_slot {
        slot.revoke();
    }
    if let Some(device) = &response.device_handle {
        let _ = oauth.terminal(device);
    }
}

fn finalize_transport_response(
    oauth: &OAuthHost,
    owner_inactive: bool,
    sent: Result<SanitizedProviderResponse, crate::auth::oauth::OAuthError>,
    closed: VmResult<()>,
) -> VmResult<SanitizedProviderResponse> {
    let response = sent.map_err(|failure| {
        if failure.code() == "cancelled" && owner_inactive {
            error("policy_inactive")
        } else {
            error(failure.code())
        }
    })?;
    if let Err(failure) = closed {
        revoke_response(oauth, &response);
        return Err(failure);
    }
    Ok(response)
}

enum TransportCredential {
    None,
    Access(ResourceHandle, OpaqueAccessHandle),
    Refresh(ResourceHandle, OpaqueRefreshHandle),
    CodeVerifier(flow::TransportFlowPair),
    Device(device::TransportDevice),
}

impl TransportCredential {
    fn generation(&self) -> u64 {
        match self {
            Self::None => 0,
            Self::Access(_, handle) => handle.generation(),
            Self::Refresh(_, handle) => handle.generation(),
            Self::CodeVerifier(pair) => pair.credential_generation(),
            Self::Device(device) => device.generation(),
        }
    }

    fn for_send(&self) -> CredentialUse {
        match self {
            Self::None => CredentialUse::None,
            Self::Access(_, handle) => CredentialUse::Access(handle.clone()),
            Self::Refresh(_, handle) => CredentialUse::Refresh(handle.clone()),
            Self::CodeVerifier(pair) => pair.for_send(),
            Self::Device(device) => device.for_send(),
        }
    }

    fn slot_generation_override(&self) -> Option<u64> {
        match self {
            Self::CodeVerifier(pair) => Some(pair.credential_generation()),
            Self::Device(device) => Some(device.generation()),
            Self::None | Self::Access(_, _) | Self::Refresh(_, _) => None,
        }
    }

    fn close_if_terminal(&self, vm: &mut Vm) -> VmResult<()> {
        match self {
            Self::None => Ok(()),
            Self::Access(resource, handle) if handle.is_terminal() => vm
                .host_context()
                .close_resource::<Access>(*resource, ResourceCloseReason::Requested)
                .map(|_| ())
                .map_err(|_| error("resource_invalid")),
            Self::Refresh(resource, handle) if handle.is_terminal() => vm
                .host_context()
                .close_resource::<Refresh>(*resource, ResourceCloseReason::Requested)
                .map(|_| ())
                .map_err(|_| error("resource_invalid")),
            Self::CodeVerifier(pair) if pair.owner_inactive() || !pair.callback_result_live() => {
                pair.rollback(vm);
                Ok(())
            }
            Self::Device(device) => device.close_if_terminal(vm),
            Self::Access(_, _) | Self::Refresh(_, _) | Self::CodeVerifier(_) => Ok(()),
        }
    }
}

fn transport_credential(
    vm: &mut Vm,
    usage: &Value,
    owner: &Arc<Owner>,
    credential_id: &str,
) -> VmResult<TransportCredential> {
    validate_transport_use_keys(usage)?;
    let access = optional_field(usage, "access_handle")?;
    let refresh = optional_field(usage, "refresh_handle")?;
    let code = optional_field(usage, "code_handle")?;
    let verifier = optional_field(usage, "verifier_handle")?;
    let device = optional_field(usage, "device_handle")?;
    match (
        string(field(usage, "kind")?)?,
        access,
        refresh,
        code,
        verifier,
        device,
    ) {
        ("none", None, None, None, None, None) => Ok(TransportCredential::None),
        ("access", Some(value), None, None, None, None) => {
            borrowed::<Access>(vm, value)?;
            let context = vm.host_context();
            let entry = context
                .borrow_resource_with_key::<Access>(
                    handle(value)?,
                    &ResourceTypeKey::new(Access::KEY).expect("static key"),
                )
                .map_err(|_| error("resource_invalid"))?;
            if !Arc::ptr_eq(owner, &entry.owner) {
                return Err(error("owner_mismatch"));
            }
            Ok(TransportCredential::Access(
                handle(value)?,
                entry.handle.clone(),
            ))
        }
        ("refresh", None, Some(value), None, None, None) => {
            borrowed::<Refresh>(vm, value)?;
            let context = vm.host_context();
            let entry = context
                .borrow_resource_with_key::<Refresh>(
                    handle(value)?,
                    &ResourceTypeKey::new(Refresh::KEY).expect("static key"),
                )
                .map_err(|_| error("resource_invalid"))?;
            if !Arc::ptr_eq(owner, &entry.owner) {
                return Err(error("owner_mismatch"));
            }
            Ok(TransportCredential::Refresh(
                handle(value)?,
                entry.handle.clone(),
            ))
        }
        ("code_verifier", None, None, Some(code), Some(verifier), None) => {
            let policy_generation = owner.snapshot.generation;
            flow::transport_pair(vm, code, verifier, owner, credential_id, policy_generation)
                .map(TransportCredential::CodeVerifier)
        }
        ("device_session", None, None, None, None, Some(value)) => {
            device::transport(vm, value, owner, credential_id).map(TransportCredential::Device)
        }
        _ => Err(error("credential_use_unsupported")),
    }
}

fn admit_transport(
    vm: &mut Vm,
    owner: &Arc<Owner>,
    credential: &TransportCredential,
    request: &Value,
    id: &str,
) -> VmResult<(Arc<OAuthHost>, TrustedTransportPolicy, ProviderRequest)> {
    let prepared = (|| {
        let oauth = owner
            .oauth
            .as_ref()
            .ok_or_else(|| error("transport_unavailable"))?
            .clone();
        let headers = field(request, "public_headers")?;
        let Value::Array(headers) = headers else {
            return Err(error("invalid_request"));
        };
        if headers.len() > 64 {
            return Err(error("request_too_large"));
        }
        let mut public_headers = BTreeMap::new();
        for header in headers.iter() {
            let name = string(field(header, "name")?)?;
            let value = string(field(header, "value")?)?;
            if name.len().saturating_add(value.len()) > 8192
                || public_headers
                    .insert(name.to_owned(), value.to_owned())
                    .is_some()
            {
                return Err(error("invalid_headers"));
            }
        }
        let policy = transport_policy(owner, id)?;
        owner.check()?;
        let public_request = ProviderRequest {
            method: string(field(request, "method")?)?.to_owned(),
            path: string(field(request, "path")?)?.to_owned(),
            public_headers,
            public_body: string(field(request, "public_body")?)?.to_owned(),
            credential_id: id.to_owned(),
        };
        Ok((oauth, policy, public_request))
    })();
    match prepared {
        Ok(prepared) => Ok(prepared),
        Err(failure) => {
            if owner.check().is_err() {
                match credential {
                    TransportCredential::CodeVerifier(pair) => pair.rollback(vm),
                    TransportCredential::Device(device) => {
                        let _ = device.terminate(vm);
                    }
                    _ => {}
                }
            }
            Err(failure)
        }
    }
}

fn validate_transport_use_keys(usage: &Value) -> VmResult<()> {
    let Value::Map(entries) = usage else {
        return Err(error("invalid_request"));
    };
    let mut seen = BTreeSet::new();
    for (key, _) in entries.iter() {
        let Value::String(key) = key else {
            return Err(error("credential_use_unsupported"));
        };
        let name = key.as_str();
        if !matches!(
            name,
            "kind"
                | "access_handle"
                | "refresh_handle"
                | "code_handle"
                | "verifier_handle"
                | "device_handle"
        ) || !seen.insert(name)
        {
            return Err(error("credential_use_unsupported"));
        }
    }
    Ok(())
}

fn transport_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    transport_call_shared(vm, args, None, None)
}

fn transport_payload_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let payload = args.get(2).ok_or_else(|| error("invalid_request"))?;
    transport_call_shared(vm, args, Some(payload), None)
}

fn transport_capture_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let payload = args.get(2).ok_or_else(|| error("invalid_request"))?;
    let capture_intent = args.get(3).ok_or_else(|| error("invalid_request"))?;
    transport_call_shared(vm, args, Some(payload), Some(capture_intent))
}

fn transport_call_shared(
    vm: &mut Vm,
    args: &[Value],
    payload: Option<&Value>,
    capture_value: Option<&Value>,
) -> VmResult<CallOutcome> {
    let request = args.first().ok_or_else(|| error("invalid_request"))?;
    let usage = args.get(1).ok_or_else(|| error("invalid_request"))?;
    let id = string(field(request, "credential_id")?)?;
    let owner = match policy_owner(vm, field(request, "policy_handle")?, id) {
        Ok(owner) => owner,
        Err(failure) => {
            cleanup_inactive_code_pair(vm, request, usage, id);
            device::cleanup_inactive(vm, request, usage, id);
            return Err(failure);
        }
    };
    let credential = transport_credential(vm, usage, &owner, id)?;
    let generation = credential.generation();
    let (oauth, policy, public_request) = admit_transport(vm, &owner, &credential, request, id)?;
    let request_body = match payload {
        Some(raw) => match payload::parse(raw) {
            Ok(intent) => Some(intent),
            Err(failure) => {
                cleanup_inactive_transport_credential(vm, &owner, &credential);
                return Err(failure);
            }
        },
        None => None,
    };
    let capture_intent = match capture_value {
        Some(raw) => match capture::parse(raw) {
            Ok(intent) => Some(intent),
            Err(failure) => {
                cleanup_inactive_transport_credential(vm, &owner, &credential);
                return Err(failure);
            }
        },
        None => None,
    };
    if capture_intent.is_some() && !capture::compatible(&credential, request_body) {
        cleanup_inactive_transport_credential(vm, &owner, &credential);
        return Err(error("capture_intent_invalid"));
    }

    let mut native_pair: Option<OpaqueExchangePair> = None;
    let sent = if request_body.is_some() || capture_intent.is_some() {
        oauth
            .transport_with_intents_scoped(
                &policy,
                public_request,
                credential.for_send(),
                NativeTransportIntents {
                    request_body,
                    exchange_response: capture_intent,
                },
                flow::owner_cancellation(&owner),
                credential.slot_generation_override(),
            )
            .map(|exchange| {
                native_pair = exchange.pair;
                exchange.response
            })
    } else {
        oauth.transport_scoped(
            &policy,
            public_request,
            credential.for_send(),
            flow::owner_cancellation(&owner),
            credential.slot_generation_override(),
        )
    };
    // A local admission failure keeps the live resource available for retry.
    // Once the store entry is terminal, close the Core alias even on send errors.
    let closed = credential.close_if_terminal(vm);
    let owner_inactive = owner.check().is_err();
    let response = match finalize_transport_response(&oauth, owner_inactive, sent, closed) {
        Ok(response) => response,
        Err(failure) => {
            if let Some(pair) = native_pair.take() {
                capture::revoke_native_pair(&oauth, pair);
            }
            return Err(failure);
        }
    };
    let mut access = None;
    let mut refresh = None;
    let mut device_handle = None;
    let mut published_pair: Option<flow::PublishedExchangePair> = None;
    let processed = (|| {
        owner.check()?;
        if response.code_handle.is_some() {
            if let TransportCredential::Device(device) = &credential {
                let _ = device.terminate(vm);
            }
            return Err(error("response_handle_unsupported"));
        }
        if response.device_handle.is_some() {
            match &credential {
                TransportCredential::None => {}
                TransportCredential::Device(device) => {
                    let _ = device.terminate(vm);
                    return Err(error("response_handle_unsupported"));
                }
                _ => return Err(error("response_handle_unsupported")),
            }
        }
        let body = serde_json::to_string(&response.body_without_secret_fields)
            .map_err(|_| error("malformed_response"))?;
        if body.len() > 64 * 1024 {
            return Err(error("response_too_large"));
        }
        if response.public_headers.len() > 64
            || response
                .public_headers
                .iter()
                .map(|(k, v)| k.len().saturating_add(v.len()))
                .sum::<usize>()
                > 64 * 1024
        {
            return Err(error("response_too_large"));
        }
        if let Some(slot) = &response.access_slot {
            access = Some(issue_owner_slot(
                vm,
                &owner,
                id,
                generation,
                SecretSlotKind::Access,
                slot.clone(),
            )?);
        }
        if let Some(slot) = &response.refresh_slot {
            refresh = Some(issue_owner_slot(
                vm,
                &owner,
                id,
                generation,
                SecretSlotKind::Refresh,
                slot.clone(),
            )?);
        }
        if let Some(native) = &response.device_handle {
            device_handle = Some(device::issue(vm, &owner, id, native.clone())?);
        }
        owner.check()?;
        let public_response = object(vec![
            ("ok", Value::Bool(true)),
            ("error", Value::Null),
            ("status", Value::Int(i64::from(response.status))),
            (
                "public_headers",
                Value::array(
                    response
                        .public_headers
                        .iter()
                        .filter(|(name, value)| {
                            name.eq_ignore_ascii_case("content-type")
                                && canonical_json_content_type(value)
                        })
                        .map(|_| {
                            object(vec![
                                ("name", Value::string("content-type")),
                                ("value", Value::string("application/json")),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("body_without_secret_fields", Value::string(body)),
            (
                "retry_after_ms",
                response
                    .retry_after_ms
                    .and_then(|n| i64::try_from(n).ok())
                    .map(Value::Int)
                    .unwrap_or(Value::Null),
            ),
            ("access_slot", access.clone().unwrap_or(Value::Null)),
            ("refresh_slot", refresh.clone().unwrap_or(Value::Null)),
            (
                "device_handle",
                device_handle.clone().unwrap_or(Value::Null),
            ),
        ]);
        if capture_value.is_none() {
            return result(public_response);
        }

        let (code_handle, verifier_handle) = if let Some(pair) = native_pair.take() {
            let published = flow::publish_exchange_pair(vm, &owner, id, generation, pair)?;
            let code = published.code_handle.clone();
            let verifier = published.verifier_handle.clone();
            published_pair = Some(published);
            (code, verifier)
        } else {
            (Value::Null, Value::Null)
        };
        owner.check()?;
        let envelope = object(vec![
            ("ok", Value::Bool(true)),
            ("error", Value::Null),
            ("response", public_response),
            ("code_handle", code_handle),
            ("verifier_handle", verifier_handle),
        ]);
        owner.check()?;
        result(envelope)
    })();
    if processed.is_err() {
        if let TransportCredential::Device(device) = &credential {
            let _ = device.terminate(vm);
        }
        if let Some(value) = &access {
            close_issued_slot(vm, value);
        }
        if let Some(value) = &refresh {
            close_issued_slot(vm, value);
        }
        if let Some(value) = &device_handle {
            device::close_issued(vm, value);
        }
        revoke_response(&oauth, &response);
        if let Some(pair) = native_pair.take() {
            capture::revoke_native_pair(&oauth, pair);
        }
        if let Some(pair) = &published_pair {
            pair.rollback(vm);
        }
    }
    processed
}

fn cleanup_inactive_transport_credential(
    vm: &mut Vm,
    owner: &Arc<Owner>,
    credential: &TransportCredential,
) {
    if owner.check().is_ok() {
        return;
    }
    match credential {
        TransportCredential::CodeVerifier(pair) => pair.rollback(vm),
        TransportCredential::Device(device) => {
            let _ = device.terminate(vm);
        }
        TransportCredential::None
        | TransportCredential::Access(_, _)
        | TransportCredential::Refresh(_, _) => {}
    }
}

fn metadata_value(meta: &AuthMetadata) -> Value {
    json_to_vm_value(
        &json!({"credential_id":meta.credential_id,"provider":meta.provider,"kind":meta.kind,"source":meta.source,"token_type":meta.token_type,"expires_at_ms":meta.expires_at_ms,"scopes":meta.scopes,"account_id":meta.account_id,"generation":meta.generation,"status":meta.status,"last_refresh_at_ms":meta.last_refresh_at_ms,"has_refresh_token":meta.has_refresh_token}),
    )
}
fn meta_result(meta: &AuthMetadata, outcome: &str) -> VmResult<CallOutcome> {
    result(object(vec![
        ("ok", Value::Bool(true)),
        ("error", Value::Null),
        ("metadata", metadata_value(meta)),
        ("outcome", Value::string(outcome)),
    ]))
}
fn policy_owner(vm: &mut Vm, value: &Value, id: &str) -> VmResult<Arc<Owner>> {
    let owner = borrowed::<Policy>(vm, value)?;
    owner.authorize(id)?;
    Ok(owner)
}

fn policy_owner_for_cleanup(vm: &mut Vm, value: &Value) -> VmResult<Arc<Owner>> {
    let owner = {
        let context = vm.host_context();
        let entry = context
            .borrow_resource_with_key::<Policy>(
                handle(value)?,
                &ResourceTypeKey::new(Policy::KEY).expect("static key"),
            )
            .map_err(|_| error("resource_invalid"))?;
        entry.owner.clone()
    };
    let bound = vm
        .host_context()
        .scope_state::<Bound>()
        .map(|bound| Arc::clone(&bound.0))
        .ok_or_else(|| error("host_unbound"))?;
    if !Arc::ptr_eq(&owner, &bound) {
        return Err(error("owner_mismatch"));
    }
    Ok(owner)
}

fn cleanup_inactive_code_pair(vm: &mut Vm, request: &Value, usage: &Value, id: &str) {
    let Ok(kind) = field(usage, "kind") else {
        return;
    };
    if string(kind).ok() != Some("code_verifier") {
        return;
    }
    let Ok(access) = optional_field(usage, "access_handle") else {
        return;
    };
    let Ok(refresh) = optional_field(usage, "refresh_handle") else {
        return;
    };
    let (Some(code), Some(verifier)) = (
        optional_field(usage, "code_handle").ok().flatten(),
        optional_field(usage, "verifier_handle").ok().flatten(),
    ) else {
        return;
    };
    let Ok(device) = optional_field(usage, "device_handle") else {
        return;
    };
    if access.is_some()
        || refresh.is_some()
        || device.is_some()
        || validate_transport_use_keys(usage).is_err()
    {
        return;
    }
    let Ok(policy) = field(request, "policy_handle") else {
        return;
    };
    let Ok(owner) = policy_owner_for_cleanup(vm, policy) else {
        return;
    };
    if owner.check().is_ok() {
        return;
    }
    let Ok(pair) = flow::transport_pair(vm, code, verifier, &owner, id, owner.snapshot.generation)
    else {
        return;
    };
    if pair.owner_inactive() {
        pair.rollback(vm);
    }
}

fn metadata_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let id = string(&args[0])?;
    let owner = policy_owner(vm, &args[1], id)?;
    let meta = owner
        .store
        .load_metadata(id)
        .map_err(|_| error("credential_unavailable"))?;
    owner.check()?;
    meta_result(&meta, "loaded")
}

fn metadata_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let id = string(args.first().ok_or_else(|| error("invalid_request"))?)?;
    let policy = args.get(1).ok_or_else(|| error("invalid_request"))?;
    let owner = policy_owner(vm, policy, id)?;
    let metadata = owner.store.load_metadata(id).map_err(|failure| {
        error(
            if matches!(&failure, AuthStoreError::CredentialNotFound { .. }) {
                "credential_not_found"
            } else {
                failure.code()
            },
        )
    })?;
    owner.check()?;
    meta_result(&metadata, "loaded")
}

fn access_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let id = string(&args[0])?;
    let generation = natural(&args[1])?;
    let owner = policy_owner(vm, &args[2], id)?;
    let h = owner
        .store
        .issue_access_handle_until(
            id,
            generation,
            owner.snapshot.generation,
            &owner.identity,
            owner.deadline,
        )
        .map_err(|_| error("access_unavailable"))?;
    if let Err(e) = owner.check() {
        h.force_expire();
        return Err(e);
    }
    let value = issue(
        vm,
        Access {
            owner,
            handle: h.clone(),
        },
    )
    .inspect_err(|_| h.force_expire())?;
    result(object(vec![
        ("ok", Value::Bool(true)),
        ("error", Value::Null),
        ("handle", value),
    ]))
}
fn refresh_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let id = string(&args[0])?;
    let generation = natural(&args[1])?;
    let owner = policy_owner(vm, &args[2], id)?;
    let h = owner
        .store
        .issue_refresh_handle_until(
            id,
            generation,
            owner.snapshot.generation,
            &owner.identity,
            owner.deadline,
        )
        .map_err(|_| error("refresh_unavailable"))?;
    if let Err(e) = owner.check() {
        h.force_expire();
        return Err(e);
    }
    let value = issue(
        vm,
        Refresh {
            owner,
            handle: h.clone(),
        },
    )
    .inspect_err(|_| h.force_expire())?;
    result(object(vec![
        ("ok", Value::Bool(true)),
        ("error", Value::Null),
        ("handle", value),
    ]))
}
fn slot(vm: &mut Vm, value: &Value, owner: &Arc<Owner>) -> VmResult<OpaqueSecretSlot> {
    borrowed::<SecretSlot>(vm, value)?;
    let context = vm.host_context();
    let entry = context
        .borrow_resource_with_key::<SecretSlot>(
            handle(value)?,
            &ResourceTypeKey::new(SecretSlot::KEY).unwrap(),
        )
        .map_err(|_| error("slot_invalid"))?;
    if !Arc::ptr_eq(owner, &entry.owner) {
        return Err(error("slot_owner_mismatch"));
    }
    Ok(entry.slot.clone())
}
fn save_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let req = &args[0];
    let id = string(field(req, "credential_id")?)?;
    let owner = policy_owner(vm, field(req, "policy_handle")?, id)?;
    let expected = natural(field(req, "expected_generation")?)?;
    let metadata = crate::domain::vm_value_to_json(field(req, "metadata")?);
    let metadata: CredentialConfig =
        serde_json::from_value(metadata).map_err(|_| error("metadata_invalid"))?;
    let access = slot(vm, field(req, "access_slot")?, &owner)?;
    let refresh = match string(field(req, "refresh_action")?)? {
        "preserve" => RefreshSecretAction::Preserve,
        "clear" => RefreshSecretAction::Clear,
        "replace" => RefreshSecretAction::Replace(slot(vm, field(req, "refresh_slot")?, &owner)?),
        _ => return Err(error("refresh_action_invalid")),
    };
    owner.check()?;
    let mut candidates = vec![(handle(field(req, "access_slot")?)?, access.clone())];
    if let RefreshSecretAction::Replace(ref replacement) = refresh {
        candidates.push((handle(field(req, "refresh_slot")?)?, replacement.clone()));
    }
    let id = CredentialId::new(id.to_owned()).map_err(|_| error("invalid_credential_id"))?;
    let request = StoreSaveRequest::new(
        id,
        expected,
        owner.snapshot.generation,
        owner.identity.clone(),
        metadata,
        access,
        refresh,
    );
    let saved = owner.store.save_if_generation_guarded(request, &|| {
        owner.check().map_err(|_| AuthStoreError::MutationInactive)
    });
    // CAS conflict and adoption revoke slots. A guarded rejection leaves live
    // candidates retryable; only terminal candidates leave the Core arena.
    for (handle, slot) in candidates {
        if slot.is_terminal() {
            let closed = vm
                .host_context()
                .close_resource::<SecretSlot>(handle, ResourceCloseReason::Requested);
            if saved.is_ok() {
                closed.map_err(|_| error("slot_close_failed"))?;
            }
        }
    }
    let saved = saved.map_err(|_| error("save_rejected"))?;
    meta_result(
        saved.metadata(),
        if saved.is_adopted() {
            "adopted"
        } else {
            "committed"
        },
    )
}
fn delete_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let id = string(&args[0])?;
    let owner = policy_owner(vm, &args[1], id)?;
    owner
        .store
        .delete_guarded(id, &|| {
            owner.check().map_err(|_| AuthStoreError::MutationInactive)
        })
        .map_err(|_| error("delete_rejected"))?;
    result(object(vec![
        ("ok", Value::Bool(true)),
        ("error", Value::Null),
        ("deleted", Value::Bool(true)),
    ]))
}
fn close_access(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    borrowed::<Access>(vm, &args[0])?;
    vm.host_context()
        .close_resource::<Access>(handle(&args[0])?, ResourceCloseReason::Requested)
        .map_err(|_| error("resource_invalid"))?;
    result(Value::Null)
}
fn close_refresh(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    borrowed::<Refresh>(vm, &args[0])?;
    vm.host_context()
        .close_resource::<Refresh>(handle(&args[0])?, ResourceCloseReason::Requested)
        .map_err(|_| error("resource_invalid"))?;
    result(Value::Null)
}
fn close_slot(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    borrowed::<SecretSlot>(vm, &args[0])?;
    vm.host_context()
        .close_resource::<SecretSlot>(handle(&args[0])?, ResourceCloseReason::Requested)
        .map_err(|_| error("resource_invalid"))?;
    result(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CancellationReason;
    use crate::auth::oauth::{
        ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
    };
    use rustscript_vm::{
        CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, VmStatus,
        compile_source_at_path_with_flavor_and_options,
    };
    use std::{fs, path::PathBuf, time::Duration};
    use zeroize::Zeroizing;

    fn scripted_oauth() -> OAuthHost {
        OAuthHost::new(
            Arc::new(ScriptedHttpsTransport::new()),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(0)),
            Arc::new(ScriptedCancel::new()),
        )
    }

    struct PrivateAuthHome(PathBuf);

    impl PrivateAuthHome {
        fn new() -> Self {
            let root = PathBuf::from(
                std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned private test temp"),
            );
            let path = root.join(format!("sc01-inactive-owner-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).expect("create private auth home");
            let fixture =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
            fs::copy(fixture.join("config.yaml"), path.join("config.yaml"))
                .expect("copy synthetic config");
            let auth = fs::read_to_string(fixture.join("auth.yaml"))
                .expect("read synthetic auth fixture")
                .replace("1788440000000", "1900000000000");
            fs::write(path.join("auth.yaml"), auth).expect("copy synthetic auth");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("private auth home mode");
                for name in ["config.yaml", "auth.yaml"] {
                    fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                        .expect("private auth file mode");
                }
            }
            Self(path)
        }
    }

    impl Drop for PrivateAuthHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn code_exchange_vm(auth: &AuthHost) -> Vm {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/code_exchange_contract.rss");
        let source = fs::read_to_string(&path).expect("read actual code exchange RSS");
        let catalog = auth_host_catalog();
        let compiled = compile_source_at_path_with_flavor_and_options(
            &path,
            &source,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
        )
        .expect("compile code exchange RSS against exact auth catalog");
        let mut vm = Vm::new_shared(Arc::new(compiled.program));
        let mut registry = HostFunctionRegistry::restricted();
        auth.register(&mut registry, catalog.as_ref())
            .expect("register exact auth catalog");
        registry
            .bind_vm_cached(&mut vm)
            .expect("bind exact auth catalog");
        assert!(matches!(vm.run().expect("run RSS root"), VmStatus::Halted));
        vm
    }

    fn test_field(value: &Value, name: &str) -> Value {
        let Value::Map(entries) = value else {
            panic!("expected RSS record");
        };
        entries
            .iter()
            .find_map(|(key, value)| match key {
                Value::String(key) if key.as_ref() == name => Some(value.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing RSS field {name}"))
    }

    fn test_record(fields: Vec<(&str, Value)>) -> Value {
        Value::map(
            fields
                .into_iter()
                .map(|(name, value)| (Value::string(name), value))
                .collect(),
        )
    }

    fn call_rss(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
        let entry = vm.resolve_exported_callable(name).expect("RSS export");
        vm.invoke_callable(entry, args).expect("RSS call")
    }

    fn ready_code_pair(
        auth: &AuthHost,
        vm: &mut Vm,
        policy: &Value,
        credential_id: &str,
    ) -> (Value, Value, Value) {
        let intent = test_record(vec![
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
                    test_record(vec![
                        ("name", Value::string("client_id")),
                        ("value", Value::string("public-client-id")),
                    ]),
                    test_record(vec![
                        ("name", Value::string("response_type")),
                        ("value", Value::string("code")),
                    ]),
                ]),
            ),
        ]);
        let begun = call_rss(vm, "begin", &[policy.clone(), intent]);
        let callback = test_field(&begun, "callback_handle");
        let verifier = test_field(&begun, "verifier_handle");
        auth.fixture_inject_matching_callback(vm, &callback, "SC01_SYNTHETIC_CALLBACK_CODE")
            .expect("inject synthetic callback");
        let waited = call_rss(vm, "wait", std::slice::from_ref(&callback));
        let code = test_field(&waited, "code_handle");
        (callback, code, verifier)
    }

    fn transport_request(policy: &Value, credential_id: &str) -> Value {
        test_record(vec![
            ("policy_handle", policy.clone()),
            ("credential_id", Value::string(credential_id)),
            ("method", Value::string("POST")),
            ("path", Value::string("/oauth/token")),
            ("public_headers", Value::array(vec![])),
            ("public_body", Value::string("client_id=synthetic")),
        ])
    }

    fn transport_usage(code: &Value, verifier: &Value) -> Value {
        test_record(vec![
            ("kind", Value::string("code_verifier")),
            ("code_handle", code.clone()),
            ("verifier_handle", verifier.clone()),
        ])
    }

    #[test]
    fn inactive_owner_admission_failure_rolls_back_only_submitted_code_flow() {
        const CREDENTIAL_ID: &str = "fixture-codex";
        let home = PrivateAuthHome::new();
        let transport = Arc::new(ScriptedHttpsTransport::new());
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let oauth = Arc::new(OAuthHost::new(
            transport.clone(),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(1_900_000_000_000)),
            Arc::new(ScriptedCancel::new()),
        ));
        let auth = AuthHost::new(home.0.clone(), cancellation.clone())
            .expect("auth host")
            .with_oauth_host(oauth)
            .with_oauth_callback_fixture();
        let mut vm = code_exchange_vm(&auth);
        let bound = auth.bind_vm(&mut vm).expect("bind VM owner");
        let snapshot = call_rss(&mut vm, "snapshot", &[test_field(&bound, "host_home")]);
        let policy = test_field(&snapshot, "policy_handle");
        let (callback, code, verifier) = ready_code_pair(&auth, &mut vm, &policy, CREDENTIAL_ID);
        let (_other_callback, other_code, other_verifier) =
            ready_code_pair(&auth, &mut vm, &policy, CREDENTIAL_ID);
        let request = transport_request(&policy, CREDENTIAL_ID);
        let usage = transport_usage(&code, &verifier);
        let other_usage = transport_usage(&other_code, &other_verifier);

        let owner = policy_owner(&mut vm, &policy, CREDENTIAL_ID).expect("active policy owner");
        assert!(Arc::ptr_eq(
            &owner,
            &policy_owner(&mut vm, &policy, CREDENTIAL_ID).expect("same policy owner")
        ));
        let credential = transport_credential(&mut vm, &usage, &owner, CREDENTIAL_ID)
            .expect("valid same-owner code/verifier pair");
        let other_credential = transport_credential(&mut vm, &other_usage, &owner, CREDENTIAL_ID)
            .expect("independent same-owner code/verifier pair");
        assert!(matches!(&credential, TransportCredential::CodeVerifier(_)));
        assert!(matches!(
            &other_credential,
            TransportCredential::CodeVerifier(_)
        ));
        assert!(transport_policy(&owner, CREDENTIAL_ID).is_ok());
        assert_eq!(vm.host_context().resource_count(), 8);
        assert_eq!(
            auth.fixture_live_oauth_flow_count().expect("native flows"),
            2
        );
        assert!(transport.take_sent().is_empty());

        owner.cancellation.request(CancellationReason::Requested);
        assert!(
            matches!(owner.check(), Err(VmError::HostError(code)) if code == "policy_inactive")
        );
        let failure = match admit_transport(&mut vm, &owner, &credential, &request, CREDENTIAL_ID) {
            Err(failure) => failure,
            Ok(_) => panic!("inactive owner must fail transport admission"),
        };
        assert!(matches!(&failure, VmError::HostError(code) if code == "policy_inactive"));
        assert_eq!(
            vm.host_context().resource_count(),
            5,
            "only the submitted callback/code/verifier family is reclaimed"
        );
        assert_eq!(
            auth.fixture_live_oauth_flow_count().expect("native flows"),
            1
        );
        assert!(
            transport.take_sent().is_empty(),
            "no native send before admission"
        );
        for (name, handle) in [
            ("close_callback", &callback),
            ("close_code", &code),
            ("close_verifier", &verifier),
        ] {
            let entry = vm
                .resolve_exported_callable(name)
                .expect("RSS close export");
            let failure = vm
                .invoke_callable(entry, std::slice::from_ref(handle))
                .expect_err("reclaimed aliases cannot be closed again");
            let failure = failure.to_string();
            assert!(
                failure.contains("resource_invalid") || failure.contains("resource_already_closed"),
                "{name} must report a closed resource, got {failure}"
            );
        }

        let other_credential = transport_credential(&mut vm, &other_usage, &owner, CREDENTIAL_ID)
            .expect("unrelated same-VM flow remains live");
        let TransportCredential::CodeVerifier(other_pair) = other_credential else {
            panic!("second flow keeps the code/verifier credential kind");
        };
        assert!(other_pair.callback_result_live());
        assert_eq!(vm.host_context().resource_count(), 5);
        assert_eq!(
            auth.fixture_live_oauth_flow_count().expect("native flows"),
            1
        );
        other_pair.rollback(&mut vm);
        assert_eq!(vm.host_context().resource_count(), 2);
        assert_eq!(
            auth.fixture_live_oauth_flow_count().expect("native flows"),
            0
        );
    }

    #[test]
    fn transport_close_failure_revokes_response_slots() {
        let oauth = scripted_oauth();
        let secret = "synthetic-close-error-secret";
        let slot = |kind| {
            OpaqueSecretSlot::from_host_secret_until(
                kind,
                "credential",
                1,
                2,
                "run",
                Zeroizing::new(secret.as_bytes().to_vec()),
                Instant::now() + Duration::from_secs(60),
            )
            .expect("host slot")
        };
        let access = slot(SecretSlotKind::Access);
        let refresh = slot(SecretSlotKind::Refresh);
        for (kind, slot) in [
            (SecretSlotKind::Access, &access),
            (SecretSlotKind::Refresh, &refresh),
        ] {
            assert!(
                slot.validate_for_request(kind, "credential", 1, 2, "run")
                    .is_ok()
            );
        }
        let response = SanitizedProviderResponse {
            status: 200,
            public_headers: BTreeMap::new(),
            body_without_secret_fields: json!({}),
            retry_after_ms: None,
            access_slot: Some(access.clone()),
            refresh_slot: Some(refresh.clone()),
            device_handle: None,
            code_handle: None,
        };
        let failure = finalize_transport_response(
            &oauth,
            false,
            Ok(response),
            Err(error("resource_invalid")),
        )
        .expect_err("failed close must reject the response");
        assert!(matches!(&failure, VmError::HostError(code) if code == "resource_invalid"));
        assert!(!failure.to_string().contains(secret));
        for (kind, slot) in [
            (SecretSlotKind::Access, &access),
            (SecretSlotKind::Refresh, &refresh),
        ] {
            assert!(
                slot.validate_for_request(kind, "credential", 1, 2, "run")
                    .is_err()
            );
        }
    }

    #[test]
    fn transport_clean_close_returns_live_response_slot() {
        let oauth = scripted_oauth();
        let access = OpaqueSecretSlot::from_host_secret_until(
            SecretSlotKind::Access,
            "credential",
            1,
            2,
            "run",
            Zeroizing::new(b"synthetic-access".to_vec()),
            Instant::now() + Duration::from_secs(60),
        )
        .expect("host slot");
        let response = SanitizedProviderResponse {
            status: 200,
            public_headers: BTreeMap::new(),
            body_without_secret_fields: json!({}),
            retry_after_ms: None,
            access_slot: Some(access.clone()),
            refresh_slot: None,
            device_handle: None,
            code_handle: None,
        };
        let returned =
            finalize_transport_response(&oauth, false, Ok(response), Ok(())).expect("response");
        assert_eq!(returned.status, 200);
        assert!(
            returned
                .access_slot
                .expect("access slot")
                .validate_for_request(SecretSlotKind::Access, "credential", 1, 2, "run")
                .is_ok()
        );
    }

    #[test]
    fn owner_cancelled_transport_keeps_policy_inactive_error() {
        let failure = finalize_transport_response(
            &scripted_oauth(),
            true,
            Err(crate::auth::oauth::OAuthError::Cancelled),
            Ok(()),
        )
        .expect_err("inactive owner cancellation");
        assert!(matches!(&failure, VmError::HostError(code) if code == "policy_inactive"));
    }

    #[test]
    fn transport_failure_precedes_close_failure() {
        let failure = finalize_transport_response(
            &scripted_oauth(),
            false,
            Err(crate::auth::oauth::OAuthError::Cancelled),
            Err(error("resource_invalid")),
        )
        .expect_err("transport failure");
        assert!(failure.to_string().contains("cancelled"));
        assert!(!failure.to_string().contains("resource_invalid"));
    }
}
