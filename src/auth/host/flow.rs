use std::sync::{Arc, Mutex, atomic::Ordering};
use std::time::Instant;

use rustscript_vm::resource::{
    CloseProgress, HostResource, ResourceCloseReason, ResourceHandle, ResourceResult,
};
use rustscript_vm::{
    CallOutcome, HostFunctionDescriptor, HostParamPassing, HostParamSchema, HostResourceType,
    HostResourceTypeMeta, HostTypeSchema, ResourceTypeKey, Value, Vm, VmResult,
};

use crate::auth::oauth::{
    BoundedPublicOAuthIntent, CallbackMode, CallbackOutcome, OAuthCancel, OAuthFlowKind,
    OpaqueAuthorizationCodeHandle, OpaqueCallbackHandle, OpaqueVerifierHandle,
};

use super::{
    Bound, LIMIT, Owner, OwnerResource, borrow, desc, envelope, error, field, handle, issue, key,
    named, object, opt, policy_owner, result, string, transport_policy,
};

const CALLBACK_KEY: &str = "oauth.callback";
const VERIFIER_KEY: &str = "oauth.verifier";
const CODE_KEY: &str = "oauth.authorization_code";
const MAX_INTENT_STRING_BYTES: usize = 2048;
const MAX_SCOPE_ENTRIES: usize = 32;
const MAX_SCOPE_BYTES: usize = 2048;
const MAX_QUERY_ENTRIES: usize = 32;
const MAX_QUERY_BYTES: usize = 2048;

struct FlowResources {
    owner: Arc<Owner>,
    credential_id: String,
    policy_generation: u64,
    callback: OpaqueCallbackHandle,
    verifier: OpaqueVerifierHandle,
    code: Mutex<Option<OpaqueAuthorizationCodeHandle>>,
    callback_resource: Mutex<Option<ResourceHandle>>,
    verifier_resource: Mutex<Option<ResourceHandle>>,
    code_resource: Mutex<Option<ResourceHandle>>,
}

struct CallbackResource {
    flow: Arc<FlowResources>,
}

struct VerifierResource {
    flow: Arc<FlowResources>,
}

struct CodeResource {
    flow: Arc<FlowResources>,
}

impl HostResource for CallbackResource {
    fn resource_type_key() -> Option<ResourceTypeKey> {
        Some(ResourceTypeKey::new(CALLBACK_KEY).expect("static resource key"))
    }

    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        if let Some(oauth) = &self.flow.owner.oauth {
            let _ = oauth.close_callback_resource(&self.flow.callback);
        }
        Ok(CloseProgress::Ready)
    }
}

impl HostResourceType for CallbackResource {
    const KEY: &'static str = CALLBACK_KEY;
    const DESCRIPTION: &'static str = "One-use callback wait capability";
}

impl HostResource for VerifierResource {
    fn resource_type_key() -> Option<ResourceTypeKey> {
        Some(ResourceTypeKey::new(VERIFIER_KEY).expect("static resource key"))
    }

    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        if let Some(oauth) = &self.flow.owner.oauth {
            let _ = oauth.close_verifier_resource(&self.flow.verifier);
        }
        Ok(CloseProgress::Ready)
    }
}

impl HostResourceType for VerifierResource {
    const KEY: &'static str = VERIFIER_KEY;
    const DESCRIPTION: &'static str = "Opaque PKCE verifier capability";
}

impl HostResource for CodeResource {
    fn resource_type_key() -> Option<ResourceTypeKey> {
        Some(ResourceTypeKey::new(CODE_KEY).expect("static resource key"))
    }

    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        if let (Some(oauth), Some(code)) = (
            self.flow.owner.oauth.as_ref(),
            self.flow
                .code
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref(),
        ) {
            let _ = oauth.close_code_resource(code);
        }
        Ok(CloseProgress::Ready)
    }
}

impl HostResourceType for CodeResource {
    const KEY: &'static str = CODE_KEY;
    const DESCRIPTION: &'static str = "Opaque authorization-code capability";
}

impl OwnerResource for CallbackResource {
    fn owner(&self) -> Arc<Owner> {
        self.flow.owner.clone()
    }
}

impl OwnerResource for VerifierResource {
    fn owner(&self) -> Arc<Owner> {
        self.flow.owner.clone()
    }
}

impl OwnerResource for CodeResource {
    fn owner(&self) -> Arc<Owner> {
        self.flow.owner.clone()
    }
}

struct OwnerCancellation(Arc<Owner>);

impl OAuthCancel for OwnerCancellation {
    fn is_cancelled(&self) -> bool {
        self.0.revoked.load(Ordering::Acquire) || self.0.cancellation.token().is_cancelled()
    }
}

pub(super) fn callback_meta() -> HostResourceTypeMeta {
    HostResourceTypeMeta::of::<CallbackResource>()
}

pub(super) fn verifier_meta() -> HostResourceTypeMeta {
    HostResourceTypeMeta::of::<VerifierResource>()
}

pub(super) fn code_meta() -> HostResourceTypeMeta {
    HostResourceTypeMeta::of::<CodeResource>()
}

fn resource(name: &str) -> HostTypeSchema {
    HostTypeSchema::Resource(ResourceTypeKey::new(name).expect("static resource key"))
}

fn array(ty: HostTypeSchema) -> HostTypeSchema {
    HostTypeSchema::Array(Box::new(ty))
}

fn public_query_entry_type() -> HostTypeSchema {
    named(
        "PublicQueryEntry",
        vec![
            ("name", HostTypeSchema::String),
            ("value", HostTypeSchema::String),
        ],
    )
}

fn public_intent_type() -> HostTypeSchema {
    named(
        "BoundedPublicOAuthIntent",
        vec![
            ("credential_id", HostTypeSchema::String),
            ("path", HostTypeSchema::String),
            ("flow", HostTypeSchema::String),
            ("callback_mode", HostTypeSchema::String),
            ("scopes", array(HostTypeSchema::String)),
            ("public_query", array(public_query_entry_type())),
        ],
    )
}

fn pkce_begin_envelope() -> HostTypeSchema {
    envelope(
        "PkceBeginEnvelope",
        vec![
            ("authorization_url", HostTypeSchema::String),
            ("redirect_uri", HostTypeSchema::String),
            ("code_challenge", HostTypeSchema::String),
            ("code_challenge_method", HostTypeSchema::String),
            ("callback_handle", resource(CALLBACK_KEY)),
            ("verifier_handle", resource(VERIFIER_KEY)),
        ],
    )
}

fn callback_envelope() -> HostTypeSchema {
    envelope(
        "CallbackEnvelope",
        vec![
            ("outcome", HostTypeSchema::String),
            ("code_handle", opt(resource(CODE_KEY))),
        ],
    )
}

pub(super) fn pkce_begin_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::pkce_begin",
        vec![
            borrow("policy_handle", key("auth.policy")),
            super::param("public_intent", public_intent_type()),
        ],
        pkce_begin_envelope(),
        pkce_begin_call,
    )
}

pub(super) fn callback_wait_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::callback_wait",
        vec![borrow("callback_handle", resource(CALLBACK_KEY))],
        callback_envelope(),
        callback_wait_call,
    )
}

fn close_desc(
    name: &'static str,
    resource_key: &'static str,
    adapter: fn(&mut Vm, &[Value]) -> VmResult<CallOutcome>,
) -> HostFunctionDescriptor {
    let schema = rustscript_vm::HostFunctionSchema::with_return(
        name,
        vec![HostParamSchema::with_passing(
            "handle",
            resource(resource_key),
            HostParamPassing::TakeOwned,
        )],
        HostTypeSchema::Null,
    );
    let effects = rustscript_vm::vm::host_extension::guest_resource_effects(&schema);
    let mut descriptor = crate::runtime::host_compose::static_stack_descriptor(schema, adapter);
    descriptor.effects = effects;
    descriptor
}

pub(super) fn close_callback_desc() -> HostFunctionDescriptor {
    close_desc("oauth::close_callback", CALLBACK_KEY, close_callback_call)
}

pub(super) fn close_verifier_desc() -> HostFunctionDescriptor {
    close_desc("oauth::close_verifier", VERIFIER_KEY, close_verifier_call)
}

pub(super) fn close_code_desc() -> HostFunctionDescriptor {
    close_desc("oauth::close_code", CODE_KEY, close_code_call)
}

fn pkce_begin_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let policy_value = args.first().ok_or_else(|| error("invalid_request"))?;
    let public_intent = args.get(1).ok_or_else(|| error("invalid_request"))?;
    let (intent, credential_id) = parse_public_intent(public_intent)?;
    let owner = policy_owner(vm, policy_value, &credential_id)?;
    if !owner.oauth_callback_fixture {
        return Err(error("callback_unavailable"));
    }
    let oauth = owner
        .oauth
        .as_ref()
        .ok_or_else(|| error("callback_unavailable"))?
        .clone();
    let policy = transport_policy(&owner, &credential_id)?;
    owner.check()?;
    {
        let context = vm.host_context();
        if context.resource_count().saturating_add(2) > LIMIT {
            return Err(error("resource_limit"));
        }
    }

    let begun = oauth
        .pkce_begin(&policy, intent)
        .map_err(|failure| error(failure.code()))?;
    if let Err(failure) = owner.check() {
        let _ = oauth.revoke_callback_flow(&begun.callback_handle);
        return Err(failure);
    }
    let flow = Arc::new(FlowResources {
        owner: owner.clone(),
        credential_id,
        policy_generation: policy.generation,
        callback: begun.callback_handle,
        verifier: begun.verifier_handle,
        code: Mutex::new(None),
        callback_resource: Mutex::new(None),
        verifier_resource: Mutex::new(None),
        code_resource: Mutex::new(None),
    });

    let callback_value = match issue(vm, CallbackResource { flow: flow.clone() }) {
        Ok(value) => value,
        Err(failure) => {
            let _ = oauth.revoke_callback_flow(&flow.callback);
            return Err(failure);
        }
    };
    *flow
        .callback_resource
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(handle(&callback_value)?);
    let verifier_value = match issue(vm, VerifierResource { flow: flow.clone() }) {
        Ok(value) => value,
        Err(failure) => {
            rollback_resources(vm, &flow);
            return Err(failure);
        }
    };
    *flow
        .verifier_resource
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(handle(&verifier_value)?);
    if let Err(failure) = owner.check() {
        rollback_resources(vm, &flow);
        return Err(failure);
    }

    result(object(vec![
        ("ok", Value::Bool(true)),
        ("error", Value::Null),
        ("authorization_url", Value::string(begun.authorization_url)),
        ("redirect_uri", Value::string(begun.redirect_uri)),
        ("code_challenge", Value::string(begun.code_challenge)),
        (
            "code_challenge_method",
            Value::string(begun.code_challenge_method),
        ),
        ("callback_handle", callback_value),
        ("verifier_handle", verifier_value),
    ]))
}

fn callback_wait_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let callback_value = args.first().ok_or_else(|| error("invalid_request"))?;
    let flow = flow_for_callback(vm, callback_value)?;
    let owner = &flow.owner;
    if let Err(failure) = callback_owner_check(owner, &flow.credential_id) {
        revoke_flow(&flow);
        rollback_resources(vm, &flow);
        return Err(failure);
    }
    if !owner.oauth_callback_fixture || owner.snapshot.generation != flow.policy_generation {
        revoke_flow(&flow);
        return Err(error("policy_inactive"));
    }
    let oauth = owner
        .oauth
        .as_ref()
        .ok_or_else(|| error("callback_unavailable"))?
        .clone();
    let policy = match transport_policy(owner, &flow.credential_id) {
        Ok(policy) if policy.generation == flow.policy_generation => policy,
        Ok(_) => {
            revoke_flow(&flow);
            return Err(error("policy_inactive"));
        }
        Err(failure) => {
            revoke_flow(&flow);
            return Err(failure);
        }
    };
    let cancellation: Arc<dyn OAuthCancel> = Arc::new(OwnerCancellation(owner.clone()));
    let waited = oauth.callback_wait_scoped(&policy, &flow.callback, cancellation);
    let waited = match waited {
        Ok(waited) => waited,
        Err(failure) => {
            if failure.code() == "handle_replayed" && oauth.callback_result_live(&flow.callback) {
                return Err(error(failure.code()));
            }
            revoke_flow(&flow);
            rollback_resources(vm, &flow);
            return Err(error(failure.code()));
        }
    };
    if let Err(failure) = callback_owner_check(owner, &flow.credential_id) {
        revoke_flow(&flow);
        rollback_resources(vm, &flow);
        return Err(failure);
    }
    if waited.outcome != CallbackOutcome::Success {
        revoke_flow(&flow);
        rollback_resources(vm, &flow);
        return Err(error("callback_result_invalid"));
    }
    let Some(code) = waited.code_handle else {
        revoke_flow(&flow);
        rollback_resources(vm, &flow);
        return Err(error("callback_result_invalid"));
    };
    *flow
        .code
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(code);
    let code_value = match issue(vm, CodeResource { flow: flow.clone() }) {
        Ok(value) => value,
        Err(failure) => {
            revoke_flow(&flow);
            rollback_resources(vm, &flow);
            return Err(failure);
        }
    };
    *flow
        .code_resource
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(handle(&code_value)?);
    if let Err(failure) = owner.check() {
        revoke_flow(&flow);
        rollback_resources(vm, &flow);
        return Err(failure);
    }

    result(object(vec![
        ("ok", Value::Bool(true)),
        ("error", Value::Null),
        ("outcome", Value::string("success")),
        ("code_handle", code_value),
    ]))
}

fn close_callback_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    close_resource::<CallbackResource>(vm, args)
}

fn close_verifier_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    close_resource::<VerifierResource>(vm, args)
}

fn close_code_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    close_resource::<CodeResource>(vm, args)
}

fn close_resource<T: HostResource + HostResourceType + OwnerResource>(
    vm: &mut Vm,
    args: &[Value],
) -> VmResult<CallOutcome> {
    let value = args.first().ok_or_else(|| error("invalid_request"))?;
    let owner = owner_for_cleanup::<T>(vm, value)?;
    let closed = vm
        .host_context()
        .close_resource::<T>(handle(value)?, ResourceCloseReason::Requested)
        .map_err(|_| error("resource_invalid"));
    owner.check()?;
    closed?;
    result(Value::Null)
}

fn owner_for_cleanup<T: HostResource + HostResourceType + OwnerResource>(
    vm: &mut Vm,
    value: &Value,
) -> VmResult<Arc<Owner>> {
    let context = vm.host_context();
    let entry = context
        .borrow_resource_with_key::<T>(
            handle(value)?,
            &ResourceTypeKey::new(T::KEY).expect("static resource key"),
        )
        .map_err(|_| error("resource_invalid"))?;
    let owner = entry.owner();
    let bound = context
        .scope_state::<Bound>()
        .ok_or_else(|| error("host_unbound"))?;
    if !Arc::ptr_eq(&owner, &bound.0) {
        return Err(error("owner_mismatch"));
    }
    Ok(owner)
}

fn flow_for_callback(vm: &mut Vm, value: &Value) -> VmResult<Arc<FlowResources>> {
    let context = vm.host_context();
    let entry = context
        .borrow_resource_with_key::<CallbackResource>(
            handle(value)?,
            &ResourceTypeKey::new(CALLBACK_KEY).expect("static callback key"),
        )
        .map_err(|_| error("resource_invalid"))?;
    let flow = entry.flow.clone();
    let bound = context
        .scope_state::<Bound>()
        .ok_or_else(|| error("host_unbound"))?;
    if !Arc::ptr_eq(&flow.owner, &bound.0) {
        return Err(error("owner_mismatch"));
    }
    Ok(flow)
}

fn rollback_resources(vm: &mut Vm, flow: &FlowResources) {
    revoke_flow(flow);
    if let Some(resource) = *flow
        .callback_resource
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
    {
        let _ = vm
            .host_context()
            .close_resource::<CallbackResource>(resource, ResourceCloseReason::Requested);
    }
    if let Some(resource) = *flow
        .verifier_resource
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
    {
        let _ = vm
            .host_context()
            .close_resource::<VerifierResource>(resource, ResourceCloseReason::Requested);
    }
    if let Some(resource) = *flow
        .code_resource
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
    {
        let _ = vm
            .host_context()
            .close_resource::<CodeResource>(resource, ResourceCloseReason::Requested);
    }
}

fn callback_owner_check(owner: &Owner, credential_id: &str) -> VmResult<()> {
    if owner.revoked.load(Ordering::Acquire) {
        return Err(error("policy_inactive"));
    }
    if owner.cancellation.token().is_cancelled() {
        return Err(error("callback_cancelled"));
    }
    if Instant::now() >= owner.deadline {
        return Err(error("callback_timeout"));
    }
    owner.authorize(credential_id)
}

fn revoke_flow(flow: &FlowResources) {
    if let Some(oauth) = &flow.owner.oauth {
        let _ = oauth.revoke_callback_flow(&flow.callback);
    }
}

fn parse_public_intent(value: &Value) -> VmResult<(BoundedPublicOAuthIntent, String)> {
    let credential_id = bounded_string(field(value, "credential_id")?, 128, "invalid_request")?;
    let path = bounded_string(
        field(value, "path")?,
        MAX_INTENT_STRING_BYTES,
        "invalid_request",
    )?;
    let flow = match string(field(value, "flow")?)? {
        "authorization_code_pkce" => OAuthFlowKind::AuthorizationCodePkce,
        _ => return Err(error("oauth_flow_unsupported")),
    };
    let callback_mode = match string(field(value, "callback_mode")?)? {
        "browser" => CallbackMode::Browser,
        "manual" => CallbackMode::Manual,
        "none" => CallbackMode::None,
        _ => return Err(error("oauth_callback_mode_unsupported")),
    };
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains("://")
        || path.contains("..")
        || path.contains(['?', '#'])
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(error("oauth_path_denied"));
    }

    let scopes_value = field(value, "scopes")?;
    let Value::Array(scope_values) = scopes_value else {
        return Err(error("invalid_request"));
    };
    if scope_values.len() > MAX_SCOPE_ENTRIES {
        return Err(error("oauth_intent_too_large"));
    }
    let mut scopes = Vec::with_capacity(scope_values.len());
    let mut scope_bytes = 0usize;
    for scope in scope_values.iter() {
        let scope = bounded_string(scope, MAX_SCOPE_BYTES, "invalid_request")?;
        scope_bytes = scope_bytes.saturating_add(scope.len());
        if scope.is_empty()
            || scope.bytes().any(|byte| byte.is_ascii_control())
            || scope_bytes > MAX_SCOPE_BYTES
        {
            return Err(error("oauth_intent_too_large"));
        }
        scopes.push(scope);
    }

    let query_values = field(value, "public_query")?;
    let Value::Array(query_values) = query_values else {
        return Err(error("invalid_request"));
    };
    if query_values.len() > MAX_QUERY_ENTRIES {
        return Err(error("oauth_intent_too_large"));
    }
    let mut query = std::collections::BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut query_bytes = 0usize;
    for entry in query_values.iter() {
        let name = bounded_string(field(entry, "name")?, 256, "invalid_request")?;
        let value = bounded_string(field(entry, "value")?, MAX_QUERY_BYTES, "invalid_request")?;
        query_bytes = query_bytes
            .saturating_add(name.len())
            .saturating_add(value.len());
        let lowered = name.to_ascii_lowercase();
        if name.is_empty()
            || value.bytes().any(|byte| byte.is_ascii_control())
            || name.bytes().any(|byte| byte.is_ascii_control())
            || query_bytes > MAX_QUERY_BYTES
            || !seen.insert(lowered.clone())
            || matches!(
                lowered.as_str(),
                "host"
                    | "authorization"
                    | "cookie"
                    | "redirect_uri"
                    | "code_verifier"
                    | "state"
                    | "code_challenge"
                    | "code_challenge_method"
                    | "url"
                    | "authority"
            )
        {
            return Err(error("oauth_intent_invalid"));
        }
        query.insert(name, value);
    }
    Ok((
        BoundedPublicOAuthIntent {
            flow,
            callback_mode,
            path,
            scopes,
            public_query: query,
            credential_id: credential_id.clone(),
        },
        credential_id,
    ))
}

fn bounded_string(value: &Value, max: usize, code: &'static str) -> VmResult<String> {
    let value = string(value)?;
    if value.len() > max {
        return Err(error(code));
    }
    Ok(value.to_owned())
}

#[cfg(any(test, feature = "config-fixture"))]
pub(super) fn fixture_inject_matching_callback(
    vm: &mut Vm,
    callback: &Value,
    code: &str,
    expected_owner: &Arc<Owner>,
) -> VmResult<()> {
    let flow = flow_for_callback(vm, callback)?;
    if !Arc::ptr_eq(&flow.owner, expected_owner) {
        return Err(error("owner_mismatch"));
    }
    flow.owner.check()?;
    if !flow.owner.oauth_callback_fixture {
        return Err(error("callback_unavailable"));
    }
    flow.owner
        .oauth
        .as_ref()
        .ok_or_else(|| error("callback_unavailable"))?
        .inject_matching_callback(&flow.callback, code)
        .map_err(|failure| error(failure.code()))
}
