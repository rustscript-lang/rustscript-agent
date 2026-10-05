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
    BoundedPublicOAuthIntent, CallbackMode, CallbackOutcome, CredentialUse, OAuthCancel,
    OAuthFlowKind, OpaqueAuthorizationCodeHandle, OpaqueCallbackHandle, OpaqueExchangePair,
    OpaqueVerifierHandle,
};

use super::{
    Bound, LIMIT, Owner, OwnerResource, PublicAuthorizationInstruction, TrustedTransportPolicy,
    borrow, desc, envelope, error, field, handle, issue, key, named, object, opt, policy_owner,
    result, string, transport_policy,
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
    credential_generation: u64,
    callback: Option<OpaqueCallbackHandle>,
    verifier: OpaqueVerifierHandle,
    code: Mutex<Option<OpaqueAuthorizationCodeHandle>>,
    public_authorization_instruction: Option<PublicAuthorizationInstruction>,
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
        if let (Some(oauth), Some(callback)) = (&self.flow.owner.oauth, &self.flow.callback) {
            let _ = oauth.close_callback_resource(callback);
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

pub(super) fn owner_cancellation(owner: &Arc<Owner>) -> Arc<dyn OAuthCancel> {
    Arc::new(OwnerCancellation(owner.clone()))
}

pub(super) struct TransportFlowPair {
    flow: Arc<FlowResources>,
    code: OpaqueAuthorizationCodeHandle,
    verifier: OpaqueVerifierHandle,
}

impl TransportFlowPair {
    pub(super) fn credential_generation(&self) -> u64 {
        self.flow.credential_generation
    }

    pub(super) fn for_send(&self) -> CredentialUse {
        CredentialUse::AuthorizationCode {
            code: self.code.clone(),
            verifier: self.verifier.clone(),
        }
    }

    // Kept under its legacy name for the existing host.rs caller.
    pub(super) fn callback_result_live(&self) -> bool {
        let Some(oauth) = &self.flow.owner.oauth else {
            return false;
        };
        match &self.flow.callback {
            Some(callback) => oauth.callback_result_live(callback),
            None => self
                .flow
                .code
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                .is_some_and(|code| {
                    oauth.exchange_pair_live(
                        code,
                        &self.flow.verifier,
                        self.flow.policy_generation,
                        &self.flow.owner.identity,
                        &self.flow.credential_id,
                    )
                }),
        }
    }

    pub(super) fn owner_inactive(&self) -> bool {
        self.flow.owner.check().is_err()
    }

    pub(super) fn rollback(&self, vm: &mut Vm) {
        rollback_resources(vm, &self.flow);
    }
}

#[allow(dead_code)]
pub(super) struct PublishedExchangePair {
    pub(super) code_handle: Value,
    pub(super) verifier_handle: Value,
    flow: Arc<FlowResources>,
}

impl PublishedExchangePair {
    #[allow(dead_code)]
    pub(super) fn rollback(&self, vm: &mut Vm) {
        rollback_resources(vm, &self.flow);
    }
}

#[allow(dead_code)]
pub(super) fn publish_exchange_pair(
    vm: &mut Vm,
    owner: &Arc<Owner>,
    credential_id: &str,
    credential_generation: u64,
    pair: OpaqueExchangePair,
) -> VmResult<PublishedExchangePair> {
    let bound_owner = vm
        .host_context()
        .scope_state::<Bound>()
        .map(|bound| Arc::clone(&bound.0))
        .ok_or_else(|| error("host_unbound"))?;
    if !Arc::ptr_eq(owner, &bound_owner) {
        return Err(error("owner_mismatch"));
    }
    let snapshot_generation = owner
        .snapshot
        .credential_generations
        .get(credential_id)
        .copied()
        .unwrap_or(0);
    if credential_generation != snapshot_generation {
        return Err(error("handle_provenance"));
    }
    let oauth = owner
        .oauth
        .as_ref()
        .ok_or_else(|| error("oauth_unavailable"))?;
    // This is the generation frozen into the bound credential snapshot, never caller input.
    let policy_generation = owner.snapshot.generation;
    if !oauth.exchange_pair_matches_binding(
        &pair.code_handle,
        &pair.verifier_handle,
        policy_generation,
        &owner.identity,
        credential_id,
    ) {
        return Err(error("handle_provenance"));
    }
    let revoke_pair = || {
        let _ = oauth.close_code_resource(&pair.code_handle);
        let _ = oauth.close_verifier_resource(&pair.verifier_handle);
    };
    if let Err(admission_failure) = owner.authorize(credential_id) {
        if let Err(inactive_failure) = owner.check() {
            revoke_pair();
            return Err(inactive_failure);
        }
        return Err(admission_failure);
    }
    if let Err(failure) = owner.check() {
        revoke_pair();
        return Err(failure);
    }
    if !oauth.exchange_pair_live(
        &pair.code_handle,
        &pair.verifier_handle,
        policy_generation,
        &owner.identity,
        credential_id,
    ) {
        revoke_pair();
        return Err(error("resource_invalid"));
    }
    if vm.host_context().resource_count().saturating_add(2) > LIMIT {
        revoke_pair();
        return Err(error("resource_limit"));
    }

    let flow = Arc::new(FlowResources {
        owner: owner.clone(),
        credential_id: credential_id.to_string(),
        policy_generation,
        credential_generation: snapshot_generation,
        callback: None,
        verifier: pair.verifier_handle,
        code: Mutex::new(Some(pair.code_handle)),
        public_authorization_instruction: None,
        callback_resource: Mutex::new(None),
        verifier_resource: Mutex::new(None),
        code_resource: Mutex::new(None),
    });
    let code_handle = match issue(vm, CodeResource { flow: flow.clone() }) {
        Ok(value) => value,
        Err(failure) => {
            rollback_resources(vm, &flow);
            return Err(failure);
        }
    };
    *flow
        .code_resource
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(handle(&code_handle)?);
    let verifier_handle = match issue(vm, VerifierResource { flow: flow.clone() }) {
        Ok(value) => value,
        Err(failure) => {
            rollback_resources(vm, &flow);
            return Err(failure);
        }
    };
    *flow
        .verifier_resource
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(handle(&verifier_handle)?);

    let current_owner = vm
        .host_context()
        .scope_state::<Bound>()
        .map(|bound| Arc::clone(&bound.0));
    if current_owner
        .as_ref()
        .is_none_or(|current| !Arc::ptr_eq(owner, current))
    {
        rollback_resources(vm, &flow);
        return Err(error("owner_mismatch"));
    }
    if let Err(failure) = owner.check() {
        rollback_resources(vm, &flow);
        return Err(failure);
    }
    if !oauth.exchange_pair_live(
        flow.code
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .expect("published native code handle"),
        &flow.verifier,
        flow.policy_generation,
        &owner.identity,
        credential_id,
    ) {
        rollback_resources(vm, &flow);
        return Err(error("resource_invalid"));
    }
    Ok(PublishedExchangePair {
        code_handle,
        verifier_handle,
        flow,
    })
}

pub(super) fn transport_pair(
    vm: &mut Vm,
    code_value: &Value,
    verifier_value: &Value,
    owner: &Arc<Owner>,
    credential_id: &str,
    policy_generation: u64,
) -> VmResult<TransportFlowPair> {
    let code_flow = {
        let context = vm.host_context();
        context
            .borrow_resource_with_key::<CodeResource>(
                handle(code_value)?,
                &ResourceTypeKey::new(CODE_KEY).expect("static code key"),
            )
            .map_err(|_| error("resource_invalid"))?
            .flow
            .clone()
    };
    let verifier_flow = {
        let context = vm.host_context();
        context
            .borrow_resource_with_key::<VerifierResource>(
                handle(verifier_value)?,
                &ResourceTypeKey::new(VERIFIER_KEY).expect("static verifier key"),
            )
            .map_err(|_| error("resource_invalid"))?
            .flow
            .clone()
    };
    let bound_owner = vm
        .host_context()
        .scope_state::<Bound>()
        .map(|bound| Arc::clone(&bound.0))
        .ok_or_else(|| error("host_unbound"))?;
    if !Arc::ptr_eq(owner, &bound_owner)
        || !Arc::ptr_eq(owner, &code_flow.owner)
        || !Arc::ptr_eq(owner, &verifier_flow.owner)
    {
        return Err(error("owner_mismatch"));
    }
    if !Arc::ptr_eq(&code_flow, &verifier_flow)
        || code_flow.credential_id != credential_id
        || code_flow.policy_generation != policy_generation
    {
        return Err(error("handle_provenance"));
    }
    let oauth = code_flow
        .owner
        .oauth
        .as_ref()
        .ok_or_else(|| error("oauth_unavailable"))?;
    if !oauth.exchange_pair_matches_binding(
        &code_flow
            .code
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .ok_or_else(|| error("resource_invalid"))?
            .clone(),
        &code_flow.verifier,
        code_flow.policy_generation,
        &code_flow.owner.identity,
        &code_flow.credential_id,
    ) {
        return Err(error("handle_provenance"));
    }
    let code = code_flow
        .code
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .ok_or_else(|| error("resource_invalid"))?;
    Ok(TransportFlowPair {
        flow: code_flow.clone(),
        code,
        verifier: code_flow.verifier.clone(),
    })
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

pub(super) fn public_query_entry_type() -> HostTypeSchema {
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
    if !owner.oauth_callback_available() {
        return Err(error("callback_unavailable"));
    }
    let credential_generation = owner
        .snapshot
        .credential_generations
        .get(&credential_id)
        .copied()
        .ok_or_else(|| error("credential_unavailable"))?;
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

    let cancellation: Arc<dyn OAuthCancel> = Arc::new(OwnerCancellation(owner.clone()));
    let begun = oauth
        .pkce_begin_scoped(&policy, intent, cancellation)
        .map_err(|failure| error(failure.code()))?;
    if let Err(failure) = owner.check() {
        let _ = oauth.revoke_callback_flow(&begun.callback_handle);
        return Err(failure);
    }
    let public_authorization_instruction = PublicAuthorizationInstruction {
        authorization_url: begun.authorization_url.clone(),
        redirect_uri: begun.redirect_uri.clone(),
    };
    let flow = Arc::new(FlowResources {
        owner: owner.clone(),
        credential_id,
        policy_generation: policy.generation,
        credential_generation,
        callback: Some(begun.callback_handle),
        verifier: begun.verifier_handle,
        code: Mutex::new(None),
        public_authorization_instruction: Some(public_authorization_instruction),
        callback_resource: Mutex::new(None),
        verifier_resource: Mutex::new(None),
        code_resource: Mutex::new(None),
    });

    let callback_value = match issue(vm, CallbackResource { flow: flow.clone() }) {
        Ok(value) => value,
        Err(failure) => {
            let _ = oauth.revoke_callback_flow(flow.callback.as_ref().expect("callback family"));
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
    if !owner.oauth_callback_available() || owner.snapshot.generation != flow.policy_generation {
        rollback_resources(vm, &flow);
        return Err(error("policy_inactive"));
    }
    let oauth = owner
        .oauth
        .as_ref()
        .ok_or_else(|| error("callback_unavailable"))?
        .clone();
    let policy = revalidate_callback_policy(vm, &flow)?;
    let cancellation: Arc<dyn OAuthCancel> = Arc::new(OwnerCancellation(owner.clone()));
    let callback = flow
        .callback
        .as_ref()
        .ok_or_else(|| error("callback_unavailable"))?;
    let waited = oauth.callback_wait_scoped(&policy, callback, cancellation);
    let waited = match waited {
        Ok(waited) => waited,
        Err(failure) => {
            if failure.code() == "handle_replayed" && oauth.callback_result_live(callback) {
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

fn revalidate_callback_policy(
    vm: &mut Vm,
    flow: &FlowResources,
) -> VmResult<TrustedTransportPolicy> {
    match transport_policy(&flow.owner, &flow.credential_id) {
        Ok(policy) if policy.generation == flow.policy_generation => Ok(policy),
        Ok(_) => {
            rollback_resources(vm, flow);
            Err(error("policy_inactive"))
        }
        Err(failure) => {
            rollback_resources(vm, flow);
            Err(failure)
        }
    }
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

pub(super) fn owner_for_callback_cleanup(vm: &mut Vm, value: &Value) -> VmResult<Arc<Owner>> {
    owner_for_cleanup::<CallbackResource>(vm, value)
}

pub(super) fn emit_authorization_instruction(
    vm: &mut Vm,
    callback_value: &Value,
    owner: &Arc<Owner>,
) -> VmResult<()> {
    let flow = flow_for_callback(vm, callback_value)?;
    if !Arc::ptr_eq(owner, &flow.owner) {
        return Err(error("owner_mismatch"));
    }
    callback_owner_check(owner, &flow.credential_id)
        .inspect_err(|_| rollback_resources(vm, &flow))?;
    if owner.snapshot.generation != flow.policy_generation {
        rollback_resources(vm, &flow);
        return Err(error("policy_inactive"));
    }
    let _policy = revalidate_callback_policy(vm, &flow)?;
    let instruction = flow
        .public_authorization_instruction
        .as_ref()
        .ok_or_else(|| error("ui_instruction_invalid"))?;
    if instruction.authorization_url.is_empty()
        || instruction.authorization_url.len() > 32_768
        || instruction
            .authorization_url
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || instruction.redirect_uri.is_empty()
        || instruction.redirect_uri.len() > 2_048
        || instruction
            .redirect_uri
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err(error("ui_instruction_invalid"));
    }
    let sender = owner
        .authorization_instruction_sender
        .as_ref()
        .ok_or_else(|| error("ui_unavailable"))?;
    sender.try_send(instruction.clone()).map_err(error)?;

    callback_owner_check(owner, &flow.credential_id)
        .inspect_err(|_| rollback_resources(vm, &flow))?;
    let current_owner = vm
        .host_context()
        .scope_state::<Bound>()
        .map(|bound| Arc::clone(&bound.0))
        .ok_or_else(|| error("host_unbound"))?;
    if !Arc::ptr_eq(owner, &current_owner) {
        rollback_resources(vm, &flow);
        return Err(error("owner_mismatch"));
    }
    Ok(())
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
        if let Some(callback) = &flow.callback {
            let _ = oauth.revoke_callback_flow(callback);
        } else if let Some(code) = flow
            .code
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            let _ = oauth.close_code_resource(code);
            let _ = oauth.close_verifier_resource(&flow.verifier);
        }
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
        .inject_matching_callback(
            flow.callback
                .as_ref()
                .ok_or_else(|| error("callback_unavailable"))?,
            code,
        )
        .map_err(|failure| error(failure.code()))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };

    use rustscript_vm::{
        CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
        compile_source_at_path_with_flavor_and_options,
    };

    use crate::{
        CancellationReason, RunCancellation,
        auth::{host::AuthHost, oauth::OAuthHost},
    };

    use super::*;

    struct FixtureHome(PathBuf);

    impl FixtureHome {
        fn new() -> Self {
            let base =
                PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned temp"));
            let path = base.join(format!(
                "oauth-callback-policy-revalidation-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).expect("create private fixture home");
            let fixture =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
            fs::copy(fixture.join("config.yaml"), path.join("config.yaml"))
                .expect("copy fixture config");
            let auth = fs::read_to_string(fixture.join("auth.yaml"))
                .expect("read fixture auth")
                .replace("1788440000000", "1900000000000");
            fs::write(path.join("auth.yaml"), auth).expect("write private fixture auth");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("restrict fixture home");
                for name in ["config.yaml", "auth.yaml"] {
                    fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o600))
                        .expect("restrict fixture file");
                }
            }
            Self(path)
        }
    }

    impl AsRef<Path> for FixtureHome {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for FixtureHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct NativeHarness {
        _home: FixtureHome,
        cancellation: RunCancellation,
        auth: AuthHost,
        oauth: Arc<OAuthHost>,
        transport: Arc<crate::auth::oauth::ScriptedHttpsTransport>,
        clock: Arc<crate::auth::oauth::ScriptedClock>,
        vm: Vm,
        owner: Arc<Owner>,
        policy: crate::auth::oauth::TrustedTransportPolicy,
        policy_value: Value,
        credential_id: String,
    }

    impl NativeHarness {
        fn new() -> Self {
            Self::from_home(FixtureHome::new(), "fixture-codex")
        }

        fn first_login() -> Self {
            let home = FixtureHome::new();
            let auth_path = home.0.join("auth.yaml");
            let auth = fs::read_to_string(&auth_path)
                .expect("read assigned credential fixture")
                .replace("  fixture-codex:", "  fixture-first-login:")
                .replace("    generation: 4\n", "");
            fs::write(auth_path, auth).expect("write generation-zero fixture");
            let config_path = home.0.join("config.yaml");
            let config = fs::read_to_string(&config_path)
                .expect("read assigned config fixture")
                .replace("auth: fixture-codex", "auth: fixture-first-login");
            fs::write(config_path, config).expect("select generation-zero credential");
            Self::from_home(home, "fixture-first-login")
        }

        fn from_home(home: FixtureHome, credential_id: &str) -> Self {
            use crate::auth::oauth::{
                ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
                ScriptedHttpsTransport,
            };

            let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
            let transport = Arc::new(ScriptedHttpsTransport::new());
            let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
            let oauth = Arc::new(OAuthHost::new(
                Arc::clone(&transport) as Arc<_>,
                Arc::new(ScriptedCallback::new()),
                Arc::new(ScriptedBrowser::new()),
                Arc::clone(&clock) as Arc<_>,
                Arc::new(ScriptedCancel::new()),
            ));
            let auth = AuthHost::new(home.0.clone(), cancellation.clone())
                .expect("scripted AuthHost")
                .with_oauth_host(oauth.clone());
            let rss_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("rss/auth/code_exchange_contract.rss");
            let mut source =
                fs::read_to_string(rss_path).expect("read existing typed code-exchange RSS");
            source.push_str(
                r#"

pub fn capacity_access(policy: resource<auth.policy>) -> resource<auth.access> {
    auth::access_handle("fixture-codex", 4, &policy).handle
}
"#,
            );
            fs::write(home.0.join("native-pair-transport.rss"), &source)
                .expect("write temporary RSS helper in assigned fixture home");
            let compiled = compile_source_at_path_with_flavor_and_options(
                home.0.join("config.yaml"),
                &source,
                SourceFlavor::RustScript,
                CompileSourceFileOptions::default()
                    .with_host_api_catalog(crate::auth::host::auth_host_catalog()),
            )
            .expect("compile against exact auth catalog");
            let mut vm = Vm::new_shared(Arc::new(compiled.program));
            let mut registry = HostFunctionRegistry::restricted();
            auth.register(
                &mut registry,
                crate::auth::host::auth_host_catalog().as_ref(),
            )
            .expect("register exact auth catalog");
            registry
                .bind_vm_cached(&mut vm)
                .expect("bind restricted exact catalog");
            assert!(matches!(vm.run().expect("run RSS root"), VmStatus::Halted));

            let host_home = auth.bind_vm(&mut vm).expect("bind host owner");
            let snapshot_export = vm
                .resolve_exported_callable("snapshot")
                .expect("existing policy snapshot export");
            let snapshot = vm
                .invoke_callable(snapshot_export, &[field(&host_home, "host_home")])
                .expect("load bound policy resource");
            let policy_value = field(&snapshot, "policy_handle");
            let owner = vm
                .host_context()
                .scope_state::<Bound>()
                .map(|bound| Arc::clone(&bound.0))
                .expect("bound Owner");
            assert!(
                !owner.oauth_callback_fixture,
                "native publication needs no callback fixture permission"
            );
            let policy = transport_policy(&owner, credential_id).expect("frozen owner policy");
            assert_eq!(
                policy.generation, owner.snapshot.generation,
                "native policy generation must match the bound owner snapshot"
            );

            Self {
                _home: home,
                cancellation,
                auth,
                oauth,
                transport,
                clock,
                vm,
                owner,
                policy,
                policy_value,
                credential_id: credential_id.to_string(),
            }
        }

        fn allowed_path(&self, suffix: &str) -> String {
            let prefix = &self
                .policy
                .endpoints
                .first()
                .expect("actual trusted endpoint")
                .path_prefix;
            format!("{}/{}", prefix.trim_end_matches('/'), suffix)
        }

        fn request_value(&self, body: &str) -> Value {
            Value::map(vec![
                (Value::string("policy_handle"), self.policy_value.clone()),
                (
                    Value::string("credential_id"),
                    Value::string(&self.credential_id),
                ),
                (Value::string("method"), Value::string("POST")),
                (
                    Value::string("path"),
                    Value::string(self.allowed_path("token")),
                ),
                (Value::string("public_headers"), Value::array(Vec::new())),
                (Value::string("public_body"), Value::string(body)),
            ])
        }

        fn capture_pair(&self, label: &str) -> OpaqueExchangePair {
            use std::collections::BTreeMap;

            use crate::auth::oauth::{
                CredentialUse, ExchangeCodeField, OpaqueExchangeResponseIntent, ProviderRequest,
            };

            self.transport.push_json(
                200,
                serde_json::json!({
                    "device_code": format!("native-device-{label}"),
                    "user_code": "FLOW-USER-0001",
                    "verification_uri": "https://auth.openai.com/device",
                    "expires_in": 900,
                    "interval": 5
                }),
            );
            let device = self
                .oauth
                .transport(
                    &self.policy,
                    ProviderRequest {
                        method: "POST".to_string(),
                        path: self.allowed_path("device-start"),
                        public_headers: BTreeMap::new(),
                        public_body: "client_id=public-client-id".to_string(),
                        credential_id: self.credential_id.clone(),
                    },
                    CredentialUse::None,
                )
                .expect("actual scripted native device start")
                .device_handle
                .expect("native device session handle");
            self.transport.push_json(
                200,
                serde_json::json!({
                    "authorization_code": format!("native-authorization-code-{label}"),
                    "code_verifier": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
                }),
            );
            self.oauth
                .transport_exchange_pair(
                    &self.policy,
                    ProviderRequest {
                        method: "POST".to_string(),
                        path: self.allowed_path("device-capture"),
                        public_headers: BTreeMap::new(),
                        public_body: "grant_type=device_code".to_string(),
                        credential_id: self.credential_id.clone(),
                    },
                    device,
                    OpaqueExchangeResponseIntent {
                        code_field: ExchangeCodeField::AuthorizationCode,
                        redirect_uri: "https://auth.openai.com/deviceauth/callback".to_string(),
                    },
                )
                .expect("actual scripted native exchange capture")
                .pair
                .expect("native promoted code/verifier pair")
        }

        fn publish(&mut self, pair: OpaqueExchangePair) -> VmResult<PublishedExchangePair> {
            let generation = self
                .owner
                .snapshot
                .credential_generations
                .get(&self.credential_id)
                .copied()
                .unwrap_or(0);
            publish_exchange_pair(
                &mut self.vm,
                &self.owner,
                &self.credential_id,
                generation,
                pair,
            )
        }

        fn submit(&mut self, code: &Value, verifier: &Value, body: &str) -> VmResult<Value> {
            let exchange = self
                .vm
                .resolve_exported_callable("exchange")
                .expect("existing typed code-exchange caller");
            self.vm.invoke_callable(
                exchange,
                &[self.request_value(body), code.clone(), verifier.clone()],
            )
        }

        fn close_code(&mut self, code: &Value) -> VmResult<Value> {
            let close = self
                .vm
                .resolve_exported_callable("close_code")
                .expect("existing typed code close");
            self.vm.invoke_callable(close, std::slice::from_ref(code))
        }

        fn close_verifier(&mut self, verifier: &Value) -> VmResult<Value> {
            let close = self
                .vm
                .resolve_exported_callable("close_verifier")
                .expect("existing typed verifier close");
            self.vm
                .invoke_callable(close, std::slice::from_ref(verifier))
        }

        fn issue_capacity_resource(&mut self) {
            let issue = self
                .vm
                .resolve_exported_callable("capacity_access")
                .expect("existing typed access resource constructor");
            self.vm
                .invoke_callable(issue, std::slice::from_ref(&self.policy_value))
                .expect("issue actual AuthHost access resource");
        }

        fn generation(&self) -> u64 {
            self.owner
                .snapshot
                .credential_generations
                .get(&self.credential_id)
                .copied()
                .unwrap_or(0)
        }

        fn native_count(&self) -> usize {
            self.auth
                .fixture_live_oauth_flow_count()
                .expect("native flow count")
        }

        fn pair_live(&self, pair: &OpaqueExchangePair) -> bool {
            self.oauth.exchange_pair_live(
                &pair.code_handle,
                &pair.verifier_handle,
                self.policy.generation,
                &self.owner.identity,
                &self.credential_id,
            )
        }

        fn resource_count(&mut self) -> usize {
            self.vm.host_context().resource_count()
        }
    }

    fn capture_native_pair(
        oauth: &OAuthHost,
        transport: &crate::auth::oauth::ScriptedHttpsTransport,
        policy: &crate::auth::oauth::TrustedTransportPolicy,
        credential_id: &str,
        label: &str,
    ) -> OpaqueExchangePair {
        use std::collections::BTreeMap;

        use crate::auth::oauth::{
            CredentialUse, ExchangeCodeField, OpaqueExchangeResponseIntent, ProviderRequest,
        };

        let path = |suffix: &str| {
            let prefix = &policy
                .endpoints
                .first()
                .expect("actual trusted endpoint")
                .path_prefix;
            format!("{}/{}", prefix.trim_end_matches('/'), suffix)
        };
        transport.push_json(
            200,
            serde_json::json!({
                "device_code": format!("native-device-{label}"),
                "user_code": "FLOW-USER-0001",
                "verification_uri": "https://auth.openai.com/device",
                "expires_in": 900,
                "interval": 5
            }),
        );
        let device = oauth
            .transport(
                policy,
                ProviderRequest {
                    method: "POST".to_string(),
                    path: path("device-start"),
                    public_headers: BTreeMap::new(),
                    public_body: "client_id=public-client-id".to_string(),
                    credential_id: credential_id.to_string(),
                },
                CredentialUse::None,
            )
            .expect("actual scripted native device start")
            .device_handle
            .expect("native device session handle");
        transport.push_json(
            200,
            serde_json::json!({
                "authorization_code": format!("native-authorization-code-{label}"),
                "code_verifier": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            }),
        );
        oauth
            .transport_exchange_pair(
                policy,
                ProviderRequest {
                    method: "POST".to_string(),
                    path: path("device-capture"),
                    public_headers: BTreeMap::new(),
                    public_body: "grant_type=device_code".to_string(),
                    credential_id: credential_id.to_string(),
                },
                device,
                OpaqueExchangeResponseIntent {
                    code_field: ExchangeCodeField::AuthorizationCode,
                    redirect_uri: "https://auth.openai.com/deviceauth/callback".to_string(),
                },
            )
            .expect("actual scripted native exchange capture")
            .pair
            .expect("native promoted code/verifier pair")
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

    fn fixture_intent() -> Value {
        Value::map(vec![
            (
                Value::string("credential_id"),
                Value::string("fixture-codex"),
            ),
            (Value::string("path"), Value::string("/codex/device")),
            (
                Value::string("flow"),
                Value::string("authorization_code_pkce"),
            ),
            (Value::string("callback_mode"), Value::string("manual")),
            (
                Value::string("scopes"),
                Value::array(vec![Value::string("scope.synthetic")]),
            ),
            (
                Value::string("public_query"),
                Value::array(vec![
                    Value::map(vec![
                        (Value::string("name"), Value::string("client_id")),
                        (Value::string("value"), Value::string("public-client-id")),
                    ]),
                    Value::map(vec![
                        (Value::string("name"), Value::string("response_type")),
                        (Value::string("value"), Value::string("code")),
                    ]),
                ]),
            ),
        ])
    }

    #[test]
    fn native_pair_survives_rss_local_rejection_and_retries_with_same_resources() {
        use std::collections::BTreeMap;

        use crate::auth::oauth::{
            CredentialUse, ExchangeCodeField, OpaqueExchangeResponseIntent, ProviderRequest,
            ScriptedBrowser, ScriptedCancel, ScriptedClock, ScriptedHttpsTransport,
        };

        let home = FixtureHome::new();
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let transport = Arc::new(ScriptedHttpsTransport::new());
        let oauth = Arc::new(OAuthHost::new(
            Arc::clone(&transport) as Arc<_>,
            Arc::new(crate::auth::oauth::ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(1_900_000_000_000)),
            Arc::new(ScriptedCancel::new()),
        ));
        let auth = AuthHost::new(home.0.clone(), cancellation)
            .expect("scripted AuthHost")
            .with_oauth_host(oauth.clone());

        let rss_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/code_exchange_contract.rss");
        let source = fs::read_to_string(&rss_path).expect("read existing typed code-exchange RSS");
        let compiled = compile_source_at_path_with_flavor_and_options(
            home.0.join("config.yaml"),
            &source,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::default()
                .with_host_api_catalog(crate::auth::host::auth_host_catalog()),
        )
        .expect("compile against exact auth catalog");
        let mut vm = Vm::new_shared(Arc::new(compiled.program));
        let mut registry = HostFunctionRegistry::restricted();
        auth.register(
            &mut registry,
            crate::auth::host::auth_host_catalog().as_ref(),
        )
        .expect("register exact auth catalog");
        registry
            .bind_vm_cached(&mut vm)
            .expect("bind restricted exact catalog");
        assert!(matches!(vm.run().expect("run RSS root"), VmStatus::Halted));

        let host_home = auth.bind_vm(&mut vm).expect("bind host owner");
        let snapshot_callable = vm
            .resolve_exported_callable("snapshot")
            .expect("existing policy snapshot export");
        let snapshot = vm
            .invoke_callable(snapshot_callable, &[field(&host_home, "host_home")])
            .expect("load bound policy resource");
        let policy_value = field(&snapshot, "policy_handle");
        let owner = vm
            .host_context()
            .scope_state::<Bound>()
            .map(|bound| Arc::clone(&bound.0))
            .expect("bound Owner");
        assert!(
            !owner.oauth_callback_fixture,
            "native publication needs no callback fixture permission"
        );
        let policy = transport_policy(&owner, "fixture-codex").expect("frozen owner policy");
        let path_prefix = policy
            .endpoints
            .first()
            .expect("actual trusted endpoint")
            .path_prefix
            .clone();
        let allowed_path =
            |suffix: &str| format!("{}/{}", path_prefix.trim_end_matches('/'), suffix);
        let request_value = |policy_handle: Value, path: &str, body: &str| {
            Value::map(vec![
                (Value::string("policy_handle"), policy_handle),
                (
                    Value::string("credential_id"),
                    Value::string("fixture-codex"),
                ),
                (Value::string("method"), Value::string("POST")),
                (Value::string("path"), Value::string(path)),
                (Value::string("public_headers"), Value::array(Vec::new())),
                (Value::string("public_body"), Value::string(body)),
            ])
        };

        transport.push_json(
            200,
            serde_json::json!({
                "device_code": "native-device-session-marker",
                "user_code": "FLOW-USER-0001",
                "verification_uri": "https://auth.openai.com/device",
                "expires_in": 900,
                "interval": 5
            }),
        );
        let device = oauth
            .transport(
                &policy,
                ProviderRequest {
                    method: "POST".to_string(),
                    path: allowed_path("device-start"),
                    public_headers: BTreeMap::new(),
                    public_body: "client_id=public-client-id".to_string(),
                    credential_id: "fixture-codex".to_string(),
                },
                CredentialUse::None,
            )
            .expect("actual scripted native device start")
            .device_handle
            .expect("native device session handle");
        transport.push_json(
            200,
            serde_json::json!({
                "authorization_code": "native-authorization-code-marker",
                "code_verifier": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            }),
        );
        let pair = oauth
            .transport_exchange_pair(
                &policy,
                ProviderRequest {
                    method: "POST".to_string(),
                    path: allowed_path("device-capture"),
                    public_headers: BTreeMap::new(),
                    public_body: "grant_type=device_code".to_string(),
                    credential_id: "fixture-codex".to_string(),
                },
                device,
                OpaqueExchangeResponseIntent {
                    code_field: ExchangeCodeField::AuthorizationCode,
                    redirect_uri: "https://auth.openai.com/deviceauth/callback".to_string(),
                },
            )
            .expect("actual scripted native exchange capture")
            .pair
            .expect("native promoted code/verifier pair");
        let native_code = pair.code_handle.clone();
        let native_verifier = pair.verifier_handle.clone();
        let credential_generation = owner
            .snapshot
            .credential_generations
            .get("fixture-codex")
            .copied()
            .unwrap_or(0);
        let published = publish_exchange_pair(
            &mut vm,
            &owner,
            "fixture-codex",
            credential_generation,
            pair,
        )
        .expect("publish actual native pair to VM resources");
        assert!(published.flow.callback.is_none());
        let baseline = vm.host_context().resource_count() - 2;
        assert_eq!(
            auth.fixture_live_oauth_flow_count()
                .expect("native flow count"),
            1
        );
        transport.take_sent();

        let submit = vm
            .resolve_exported_callable("exchange")
            .expect("existing typed code-exchange caller");
        let rejected = vm.invoke_callable(
            submit.clone(),
            &[
                request_value(
                    policy_value.clone(),
                    &allowed_path("token"),
                    "grant_type=authorization_code&code_verifier=caller-controlled",
                ),
                published.code_handle.clone(),
                published.verifier_handle.clone(),
            ],
        );
        let rejected_debug = format!("{rejected:?}");
        assert!(!rejected_debug.contains("native-authorization-code-marker"));
        assert!(
            !rejected_debug
                .contains("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
        );
        let rejected_sent = transport.take_sent();
        assert!(
            rejected_sent.is_empty(),
            "reserved public form data must be rejected before send; result={rejected:?}"
        );
        assert!(oauth.exchange_pair_live(
            &native_code,
            &native_verifier,
            policy.generation,
            &owner.identity,
            "fixture-codex",
        ));
        assert_eq!(
            auth.fixture_live_oauth_flow_count()
                .expect("retryable native flow"),
            1
        );
        assert_eq!(vm.host_context().resource_count(), baseline + 2);

        transport.push_json(200, serde_json::json!({}));
        let response = vm
            .invoke_callable(
                submit,
                &[
                    request_value(
                        policy_value,
                        &allowed_path("token"),
                        "grant_type=authorization_code",
                    ),
                    published.code_handle.clone(),
                    published.verifier_handle.clone(),
                ],
            )
            .expect("same native pair retries through actual RSS transport");
        let response_debug = format!("{response:?}");
        assert!(!response_debug.contains("native-authorization-code-marker"));
        assert!(
            !response_debug
                .contains("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
        );
        let safe_json = serde_json::to_string(&serde_json::json!({
            "result": &response_debug,
            "error": &rejected_debug,
        }))
        .expect("serialize redacted RSS result and error to JSON");
        assert!(!safe_json.contains("native-authorization-code-marker"));
        assert!(
            !safe_json.contains("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
        );
        let sent = transport.take_sent();
        assert_eq!(sent.len(), 1, "one actual request after local rejection");
        assert!(sent[0].body.contains("grant_type=authorization_code"));
        assert!(sent[0].body.contains("code="));
        assert!(sent[0].body.contains("code_verifier="));
        assert_eq!(
            auth.fixture_live_oauth_flow_count()
                .expect("consumed native flow"),
            0
        );
        assert_eq!(vm.host_context().resource_count(), baseline);
    }

    #[test]
    fn active_snapshot_generation_mismatch_does_not_consume_native_pair() {
        let mut harness = NativeHarness::new();
        let pair = harness.capture_pair("generation-mismatch");
        let live_pair = OpaqueExchangePair {
            code_handle: pair.code_handle.clone(),
            verifier_handle: pair.verifier_handle.clone(),
        };
        let base_resources = harness.resource_count();
        let wrong_generation = harness.generation() + 1;
        let failure = publish_exchange_pair(
            &mut harness.vm,
            &harness.owner,
            &harness.credential_id,
            wrong_generation,
            pair,
        );

        assert!(
            failure.is_err(),
            "active generation mismatch must be rejected"
        );
        let (failure_debug, failure_display) = match &failure {
            Err(failure) => (format!("{failure:?}"), failure.to_string()),
            Ok(_) => (String::new(), String::new()),
        };
        assert!(!failure_debug.contains("native-authorization-code-generation-mismatch"));
        assert!(
            !failure_debug
                .contains("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
        );
        assert!(!failure_display.contains("native-authorization-code-generation-mismatch"));
        assert!(
            !failure_display
                .contains("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
        );
        assert!(
            harness.pair_live(&live_pair),
            "rejected admission remains retryable"
        );
        assert_eq!(
            harness.native_count(),
            1,
            "unadmitted flow remains registered"
        );
        assert_eq!(
            harness.resource_count(),
            base_resources,
            "no VM resources were allocated"
        );
    }

    #[test]
    fn generation_zero_pair_publishes_and_outer_rollback_is_idempotent() {
        let mut harness = NativeHarness::first_login();
        assert_eq!(
            harness.generation(),
            0,
            "missing snapshot generation means first login"
        );
        let pair = harness.capture_pair("generation-zero");
        let live_pair = OpaqueExchangePair {
            code_handle: pair.code_handle.clone(),
            verifier_handle: pair.verifier_handle.clone(),
        };
        let baseline = harness.resource_count();
        let published = harness.publish(pair).expect("publish generation-zero pair");

        assert_eq!(published.flow.credential_generation, 0);
        assert!(harness.pair_live(&live_pair));
        assert_eq!(harness.resource_count(), baseline + 2);
        published.rollback(&mut harness.vm);
        assert!(!harness.pair_live(&live_pair));
        assert_eq!(harness.native_count(), 0);
        assert_eq!(harness.resource_count(), baseline);
        published.rollback(&mut harness.vm);
        assert_eq!(harness.resource_count(), baseline, "rollback is idempotent");
    }

    #[test]
    fn proven_inactive_pair_cleanup_preserves_native_sibling() {
        let mut harness = NativeHarness::new();
        let first = harness.capture_pair("inactive-first");
        let second = harness.capture_pair("inactive-second");
        let first_alias = OpaqueExchangePair {
            code_handle: first.code_handle.clone(),
            verifier_handle: first.verifier_handle.clone(),
        };
        let second_alias = OpaqueExchangePair {
            code_handle: second.code_handle.clone(),
            verifier_handle: second.verifier_handle.clone(),
        };
        let baseline = harness.resource_count();
        harness.cancellation.request(CancellationReason::Requested);
        let generation = harness.generation();
        let failure = match publish_exchange_pair(
            &mut harness.vm,
            &harness.owner,
            &harness.credential_id,
            generation,
            first,
        ) {
            Err(failure) => failure,
            Ok(published) => {
                published.rollback(&mut harness.vm);
                panic!("inactive verified owner admitted a native pair");
            }
        };

        assert_eq!(failure.to_string(), error("policy_inactive").to_string());
        assert!(!harness.pair_live(&first_alias));
        assert!(
            harness.pair_live(&second_alias),
            "cleanup must not revoke a sibling"
        );
        assert_eq!(harness.native_count(), 1);
        assert_eq!(
            harness.resource_count(),
            baseline,
            "inactive publication allocated nothing"
        );
    }

    #[test]
    fn expired_proven_pair_is_reclaimed_before_publication() {
        let mut harness = NativeHarness::new();
        let pair = harness.capture_pair("expired");
        let alias = OpaqueExchangePair {
            code_handle: pair.code_handle.clone(),
            verifier_handle: pair.verifier_handle.clone(),
        };
        let baseline = harness.resource_count();
        harness.clock.expire();
        assert!(!harness.pair_live(&alias));

        let failure = match harness.publish(pair) {
            Err(failure) => failure,
            Ok(published) => {
                published.rollback(&mut harness.vm);
                panic!("expired native pair was published");
            }
        };
        assert_eq!(failure.to_string(), error("resource_invalid").to_string());
        assert_eq!(harness.native_count(), 0);
        assert_eq!(harness.resource_count(), baseline);
    }

    #[test]
    fn mismatched_native_pair_is_rejected_without_reclaiming_either_flow() {
        let mut harness = NativeHarness::new();
        let first = harness.capture_pair("mixed-first");
        let second = harness.capture_pair("mixed-second");
        let first_alias = OpaqueExchangePair {
            code_handle: first.code_handle.clone(),
            verifier_handle: first.verifier_handle.clone(),
        };
        let second_alias = OpaqueExchangePair {
            code_handle: second.code_handle.clone(),
            verifier_handle: second.verifier_handle.clone(),
        };
        let mixed = OpaqueExchangePair {
            code_handle: first.code_handle,
            verifier_handle: second.verifier_handle,
        };
        let baseline = harness.resource_count();
        let failure = match harness.publish(mixed) {
            Err(failure) => failure,
            Ok(published) => {
                published.rollback(&mut harness.vm);
                panic!("mixed native pair was published");
            }
        };

        assert_eq!(failure.to_string(), error("handle_provenance").to_string());
        assert!(harness.pair_live(&first_alias));
        assert!(harness.pair_live(&second_alias));
        assert_eq!(harness.native_count(), 2);
        assert_eq!(harness.resource_count(), baseline);
    }

    #[test]
    fn swapped_vm_resources_are_rejected_and_both_pairs_remain_retryable() {
        let mut harness = NativeHarness::new();
        let first = harness.capture_pair("swapped-resource-first");
        let second = harness.capture_pair("swapped-resource-second");
        let first_alias = OpaqueExchangePair {
            code_handle: first.code_handle.clone(),
            verifier_handle: first.verifier_handle.clone(),
        };
        let second_alias = OpaqueExchangePair {
            code_handle: second.code_handle.clone(),
            verifier_handle: second.verifier_handle.clone(),
        };
        let baseline = harness.resource_count();
        let first_vm = harness.publish(first).expect("publish first pair");
        let second_vm = harness.publish(second).expect("publish second pair");
        harness.transport.take_sent();

        let rejected = harness.submit(
            &first_vm.code_handle,
            &second_vm.verifier_handle,
            "grant_type=authorization_code",
        );
        assert!(
            rejected.is_err(),
            "cross-family VM resources must be rejected"
        );
        assert!(harness.transport.take_sent().is_empty());
        assert!(harness.pair_live(&first_alias));
        assert!(harness.pair_live(&second_alias));
        assert_eq!(harness.native_count(), 2);
        assert_eq!(harness.resource_count(), baseline + 4);

        harness.transport.push_json(200, serde_json::json!({}));
        harness
            .submit(
                &first_vm.code_handle,
                &first_vm.verifier_handle,
                "grant_type=authorization_code",
            )
            .expect("same VM family remains usable after swapped-resource rejection");
        assert_eq!(harness.transport.take_sent().len(), 1);
        assert!(!harness.pair_live(&first_alias));
        assert!(harness.pair_live(&second_alias));
        assert_eq!(harness.native_count(), 1);
        assert_eq!(harness.resource_count(), baseline + 2);

        harness.transport.push_json(200, serde_json::json!({}));
        harness
            .submit(
                &second_vm.code_handle,
                &second_vm.verifier_handle,
                "grant_type=authorization_code",
            )
            .expect("sibling VM family remains independently usable");
        assert_eq!(harness.transport.take_sent().len(), 1);
        assert_eq!(harness.native_count(), 0);
        assert_eq!(harness.resource_count(), baseline);
    }

    #[test]
    fn unknown_credential_pair_is_rejected_without_native_reclamation() {
        let mut harness = NativeHarness::new();
        let unknown_id = "unlisted-credential";
        let pair = capture_native_pair(
            &harness.oauth,
            &harness.transport,
            &harness.policy,
            unknown_id,
            "unknown-credential",
        );
        let code = pair.code_handle.clone();
        let verifier = pair.verifier_handle.clone();
        let baseline = harness.resource_count();
        let failure =
            match publish_exchange_pair(&mut harness.vm, &harness.owner, unknown_id, 0, pair) {
                Err(failure) => failure,
                Ok(published) => {
                    published.rollback(&mut harness.vm);
                    panic!("unknown credential pair was admitted");
                }
            };

        assert_eq!(
            failure.to_string(),
            error("credential_not_admitted").to_string()
        );
        assert!(harness.oauth.exchange_pair_live(
            &code,
            &verifier,
            harness.policy.generation,
            &harness.owner.identity,
            unknown_id,
        ));
        assert_eq!(harness.native_count(), 1);
        assert_eq!(harness.resource_count(), baseline);
    }

    #[test]
    fn mismatched_policy_generation_pair_is_denied_and_remains_native_live() {
        let mut harness = NativeHarness::new();
        let mut mismatched_policy = harness.policy.clone();
        mismatched_policy.generation = mismatched_policy.generation.saturating_add(1);
        let pair = capture_native_pair(
            &harness.oauth,
            &harness.transport,
            &mismatched_policy,
            &harness.credential_id,
            "mismatched-policy",
        );
        let code = pair.code_handle.clone();
        let verifier = pair.verifier_handle.clone();
        let baseline = harness.resource_count();
        let failure = match harness.publish(pair) {
            Err(failure) => failure,
            Ok(published) => {
                published.rollback(&mut harness.vm);
                panic!("mismatched policy generation was admitted");
            }
        };

        assert_eq!(failure.to_string(), error("handle_provenance").to_string());
        assert!(harness.oauth.exchange_pair_live(
            &code,
            &verifier,
            mismatched_policy.generation,
            &harness.owner.identity,
            &harness.credential_id,
        ));
        assert_eq!(harness.native_count(), 1);
        assert_eq!(harness.resource_count(), baseline);
    }

    #[test]
    fn cross_vm_owner_and_cross_host_pair_denials_do_not_revoke_foreign_flows() {
        use crate::auth::oauth::{
            ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
            ScriptedHttpsTransport,
        };

        let mut first_vm = NativeHarness::new();
        let mut second_vm = NativeHarness::new();
        let pair = first_vm.capture_pair("cross-vm");
        let alias = OpaqueExchangePair {
            code_handle: pair.code_handle.clone(),
            verifier_handle: pair.verifier_handle.clone(),
        };
        let second_baseline = second_vm.resource_count();
        let generation = first_vm.generation();
        let failure = match publish_exchange_pair(
            &mut second_vm.vm,
            &first_vm.owner,
            &first_vm.credential_id,
            generation,
            pair,
        ) {
            Err(failure) => failure,
            Ok(published) => {
                published.rollback(&mut second_vm.vm);
                panic!("foreign VM owner was accepted");
            }
        };
        assert_eq!(failure.to_string(), error("owner_mismatch").to_string());
        assert!(first_vm.pair_live(&alias));
        assert_eq!(first_vm.native_count(), 1);
        assert_eq!(second_vm.resource_count(), second_baseline);

        let foreign_transport = Arc::new(ScriptedHttpsTransport::new());
        let foreign_oauth = OAuthHost::new(
            Arc::clone(&foreign_transport) as Arc<_>,
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(1_900_000_000_000)),
            Arc::new(ScriptedCancel::new()),
        );
        let foreign_pair = capture_native_pair(
            &foreign_oauth,
            &foreign_transport,
            &first_vm.policy,
            &first_vm.credential_id,
            "cross-host",
        );
        let foreign_code = foreign_pair.code_handle.clone();
        let foreign_verifier = foreign_pair.verifier_handle.clone();
        let first_baseline = first_vm.resource_count();
        let failure = match first_vm.publish(foreign_pair) {
            Err(failure) => failure,
            Ok(published) => {
                published.rollback(&mut first_vm.vm);
                panic!("foreign OAuth host pair was accepted");
            }
        };
        assert_eq!(failure.to_string(), error("handle_provenance").to_string());
        assert!(foreign_oauth.exchange_pair_live(
            &foreign_code,
            &foreign_verifier,
            first_vm.policy.generation,
            &first_vm.owner.identity,
            &first_vm.credential_id,
        ));
        assert_eq!(
            first_vm.native_count(),
            1,
            "only the original VM-owned flow remains"
        );
        assert_eq!(first_vm.resource_count(), first_baseline);
    }

    #[test]
    fn native_close_removes_only_requested_vm_resource_and_closes_pair_family() {
        let mut harness = NativeHarness::new();
        let pair = harness.capture_pair("close-family");
        let alias = OpaqueExchangePair {
            code_handle: pair.code_handle.clone(),
            verifier_handle: pair.verifier_handle.clone(),
        };
        let baseline = harness.resource_count();
        let published = harness.publish(pair).expect("publish close test pair");
        assert_eq!(harness.resource_count(), baseline + 2);

        harness
            .close_code(&published.code_handle)
            .expect("close native code resource through existing RSS");
        assert_eq!(
            harness.native_count(),
            0,
            "closing either component revokes native pair"
        );
        assert!(!harness.pair_live(&alias));
        assert_eq!(harness.resource_count(), baseline + 1);
        harness
            .close_verifier(&published.verifier_handle)
            .expect("close remaining verifier resource through existing RSS");
        assert_eq!(harness.resource_count(), baseline);
        assert_eq!(harness.native_count(), 0);
    }

    #[test]
    fn native_pair_resource_ceiling_uses_real_access_resources_and_reclaims_admitted_pair() {
        let mut harness = NativeHarness::new();
        let pair = harness.capture_pair("capacity");
        let alias = OpaqueExchangePair {
            code_handle: pair.code_handle.clone(),
            verifier_handle: pair.verifier_handle.clone(),
        };
        while harness.resource_count() < LIMIT - 1 {
            harness.issue_capacity_resource();
        }
        let at_ceiling = harness.resource_count();
        assert_eq!(
            at_ceiling,
            LIMIT - 1,
            "real AuthHost resources fill the VM arena"
        );

        let failure = match harness.publish(pair) {
            Err(failure) => failure,
            Ok(published) => {
                published.rollback(&mut harness.vm);
                panic!("pair publication exceeded the Core resource limit");
            }
        };
        assert_eq!(failure.to_string(), error("resource_limit").to_string());
        assert_eq!(
            harness.resource_count(),
            at_ceiling,
            "no partial pair resources charged"
        );
        assert!(
            !harness.pair_live(&alias),
            "verified native family is reclaimed on capacity refusal"
        );
        assert_eq!(harness.native_count(), 0);
    }

    #[test]
    fn native_pair_exchange_is_one_use_and_rss_results_do_not_disclose_secret_bytes() {
        let mut harness = NativeHarness::new();
        let pair = harness.capture_pair("one-use-proof");
        let code = pair.code_handle.clone();
        let verifier = pair.verifier_handle.clone();
        let baseline = harness.resource_count();
        let published = harness.publish(pair).expect("publish one-use pair");
        harness.transport.take_sent();
        harness.transport.push_json(200, serde_json::json!({}));

        let response = harness
            .submit(
                &published.code_handle,
                &published.verifier_handle,
                "grant_type=authorization_code",
            )
            .expect("real RSS code exchange");
        let sent = harness.transport.take_sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].body.contains("code="));
        assert!(sent[0].body.contains("code_verifier="));
        let request_debug = format!("{sent:?}");
        let response_debug = format!("{response:?}");
        for secret in [
            "native-authorization-code-one-use-proof",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
        ] {
            assert!(!request_debug.contains(secret));
            assert!(!response_debug.contains(secret));
        }
        assert!(!harness.pair_live(&OpaqueExchangePair {
            code_handle: code.clone(),
            verifier_handle: verifier.clone(),
        }));
        assert_eq!(harness.native_count(), 0);
        assert_eq!(harness.resource_count(), baseline);

        let replay = harness.submit(
            &published.code_handle,
            &published.verifier_handle,
            "grant_type=authorization_code",
        );
        assert!(
            replay.is_err(),
            "a consumed native code pair cannot be replayed"
        );
        assert!(
            harness.transport.take_sent().is_empty(),
            "replay performs no HTTPS send"
        );
        assert_eq!(harness.resource_count(), baseline);
    }

    #[test]
    fn sixty_five_native_publish_rollback_cycles_do_not_grow_vm_or_native_counts() {
        let mut harness = NativeHarness::new();
        let baseline = harness.resource_count();

        for cycle in 0..65 {
            let pair = harness.capture_pair(&format!("cycle-{cycle}"));
            let alias = OpaqueExchangePair {
                code_handle: pair.code_handle.clone(),
                verifier_handle: pair.verifier_handle.clone(),
            };
            let published = harness.publish(pair).expect("publish cycle pair");
            assert_eq!(harness.resource_count(), baseline + 2);
            published.rollback(&mut harness.vm);
            assert!(!harness.pair_live(&alias));
            assert_eq!(harness.native_count(), 0);
            assert_eq!(harness.resource_count(), baseline);
        }
    }

    #[test]
    fn policy_revalidation_cancellation_reclaims_callback_resources() {
        let home = FixtureHome::new();
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let oauth = Arc::new(OAuthHost::new(
            Arc::new(crate::auth::oauth::ScriptedHttpsTransport::new()),
            Arc::new(crate::auth::oauth::ScriptedCallback::new()),
            Arc::new(crate::auth::oauth::ScriptedBrowser::new()),
            Arc::new(crate::auth::oauth::ScriptedClock::new(1_900_000_000_000)),
            Arc::new(crate::auth::oauth::ScriptedCancel::new()),
        ));
        let auth = AuthHost::new(home.0.clone(), cancellation.clone())
            .expect("synthetic auth host")
            .with_oauth_host(oauth)
            .with_oauth_callback_fixture();

        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        let rss_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/callback_contract.rss");
        let source = fs::read_to_string(&rss_path).expect("read production callback contract");
        let compiled = compile_source_at_path_with_flavor_and_options(
            fixture.join("config.yaml"),
            &source,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::default()
                .with_host_api_catalog(crate::auth::host::auth_host_catalog()),
        )
        .expect("compile against exact auth catalog");
        let mut vm = Vm::new_shared(Arc::new(compiled.program));
        let mut registry = HostFunctionRegistry::restricted();
        auth.register(
            &mut registry,
            crate::auth::host::auth_host_catalog().as_ref(),
        )
        .expect("register exact catalog");
        registry
            .bind_vm_cached(&mut vm)
            .expect("bind restricted exact catalog");
        assert!(matches!(vm.run().expect("run RSS root"), VmStatus::Halted));

        let host_home = auth.bind_vm(&mut vm).expect("bind host owner");
        let begin = vm.resolve_exported_callable("begin").expect("RSS begin");
        let begun = vm
            .invoke_callable(begin, &[field(&host_home, "host_home"), fixture_intent()])
            .expect("invoke real RSS begin");
        let callback = field(&begun, "callback_handle");
        let verifier = field(&begun, "verifier_handle");
        let flow = flow_for_callback(&mut vm, &callback).expect("borrow callback flow");
        let previous_count = vm.host_context().resource_count();
        assert_eq!(previous_count, 4, "home, policy, callback, and verifier");
        assert!(callback_owner_check(&flow.owner, &flow.credential_id).is_ok());
        assert_eq!(
            auth.fixture_live_oauth_flow_count().expect("native flow"),
            1
        );

        cancellation.request(CancellationReason::Requested);
        let failure = revalidate_callback_policy(&mut vm, &flow)
            .expect_err("revalidation must reject the requested cancellation");
        assert_eq!(
            failure.to_string(),
            error("policy_inactive").to_string(),
            "preserve Owner::check's existing typed error"
        );
        assert_eq!(
            auth.fixture_live_oauth_flow_count().expect("revoked flow"),
            0
        );
        assert_eq!(vm.host_context().resource_count(), previous_count - 2);
        assert_eq!(
            vm.host_context().resource_count(),
            2,
            "retain home and policy"
        );

        assert!(flow_for_callback(&mut vm, &callback).is_err());
        let verifier_handle = handle(&verifier).expect("verifier handle");
        {
            let context = vm.host_context();
            let verifier_borrow = context.borrow_resource_with_key::<VerifierResource>(
                verifier_handle,
                &ResourceTypeKey::new(VERIFIER_KEY).expect("verifier key"),
            );
            assert!(verifier_borrow.is_err(), "verifier alias must be reclaimed");
        }

        let home_handle = handle(&field(&host_home, "host_home")).expect("home handle");
        let policy_handle = flow
            .owner
            .policy
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .expect("RSS policy resource remains");
        let context = vm.host_context();
        assert!(
            context
                .borrow_resource_with_key::<super::super::HostHome>(
                    home_handle,
                    &ResourceTypeKey::new("auth.host_home").expect("home key"),
                )
                .is_ok()
        );
        assert!(
            context
                .borrow_resource_with_key::<super::super::Policy>(
                    policy_handle,
                    &ResourceTypeKey::new("auth.policy").expect("policy key"),
                )
                .is_ok()
        );
    }
}
