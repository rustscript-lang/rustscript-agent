//! Resource-backed, run-scoped config and credential host functions.
//! The RSS boundary carries only typed public records and Core arena resources.

use std::collections::BTreeSet;
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
use crate::auth::oauth::{TrustedEndpoint, TrustedTransportPolicy};
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
}
struct Bound(Arc<Owner>);

/// Trusted home and immutable admission snapshots. Reload affects future binds only.
pub struct AuthHost {
    paths: AgentPaths,
    store: AuthStore,
    cancellation: RunCancellation,
    published: Mutex<Arc<Snapshot>>,
    next_generation: AtomicU64,
    owners: Mutex<Vec<std::sync::Weak<Owner>>>,
}

impl AuthHost {
    pub fn new(home: impl Into<PathBuf>, cancellation: RunCancellation) -> Result<Self, String> {
        let deadline = cancellation
            .deadline_instant()
            .ok_or("finite_deadline_required")?;
        if deadline <= Instant::now() || cancellation.has_deadline_overflow() {
            return Err("finite_deadline_required".into());
        }
        let paths = AgentPaths::from_home(home.into()).map_err(|_| "invalid_host_home")?;
        let store = AuthStore::open(paths.clone()).map_err(|_| "auth_store_unavailable")?;
        let snapshot = Arc::new(load_snapshot(&paths, &store, 1)?);
        Ok(Self {
            paths,
            store,
            cancellation,
            published: Mutex::new(snapshot),
            next_generation: AtomicU64::new(2),
            owners: Mutex::new(Vec::new()),
        })
    }

    /// Publish a newly validated snapshot; already bound VMs keep their old admission.
    pub fn reload(&self) -> Result<u64, String> {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let snapshot = Arc::new(load_snapshot(&self.paths, &self.store, generation)?);
        *self.published.lock().unwrap_or_else(|p| p.into_inner()) = snapshot;
        Ok(generation)
    }

    /// Explicitly revoke every active run bound by this host.
    pub fn revoke(&self) {
        let mut owners = self.owners.lock().unwrap_or_else(|p| p.into_inner());
        owners.retain(|weak| {
            if let Some(owner) = weak.upgrade() {
                owner.revoked.store(true, Ordering::Release);
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
        let owner = Arc::new(Owner {
            identity: Uuid::new_v4().to_string(),
            deadline,
            cancellation: self.cancellation.clone(),
            revoked: AtomicBool::new(false),
            policy: Mutex::new(None),
            snapshot,
            store: self.store.clone(),
        });
        owner.check()?;
        let mut context = vm.host_context();
        if context.scope_state::<Bound>().is_some() {
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

    /// Transport-side insertion; only Rust callers can supply the opaque payload.
    #[allow(dead_code)] // Consumed by the later OAuth transport adapter.
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
        owner.authorize(credential_id)?;
        slot.validate_for_request(
            kind,
            credential_id,
            expected_generation,
            owner.snapshot.generation,
            &owner.identity,
        )
        .map_err(|_| error("slot_provenance_invalid"))?;
        issue(vm, SecretSlot { owner, slot })
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
) -> Result<Snapshot, String> {
    let config = ConfigFile::load(&paths.config).map_err(|_| "config_invalid")?;
    let auth = store.load().map_err(|_| "auth_invalid")?;
    config
        .validate_auth_references(&auth)
        .map_err(|_| "credential_reference_invalid")?;
    let allowed = config
        .providers
        .values()
        .filter_map(|provider| provider.auth.clone())
        .collect();
    Ok(Snapshot {
        config,
        allowed,
        generation,
    })
}
fn error(code: &str) -> VmError {
    VmError::HostError(code.to_string())
}
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
fn issue<T: HostResource>(vm: &mut Vm, resource: T) -> VmResult<Value> {
    let mut context = vm.host_context();
    if context.resource_count() >= LIMIT {
        return Err(error("resource_limit"));
    }
    let token = context
        .push_resource(resource)
        .map_err(|_| error("resource_unavailable"))?;
    Ok(Value::Int(token.handle().raw() as i64))
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
            metadata_desc,
            access_desc,
            refresh_desc,
            save_desc,
            delete_desc,
            close_access_desc,
            close_refresh_desc,
            close_slot_desc,
        ],
        resources: &[
            host_home_meta,
            policy_meta,
            access_meta,
            refresh_meta,
            slot_meta,
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
