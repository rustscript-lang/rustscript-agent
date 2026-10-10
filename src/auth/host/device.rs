use std::sync::Arc;

use rustscript_vm::resource::{
    CloseProgress, HostResource, ResourceCloseReason, ResourceHandle, ResourceResult,
};
use rustscript_vm::{
    CallOutcome, HostFunctionDescriptor, HostParamPassing, HostParamSchema, HostResourceType,
    HostResourceTypeMeta, HostTypeSchema, ResourceTypeKey, Value, Vm, VmResult,
};

use crate::auth::oauth::OpaqueDeviceSessionHandle;

use super::{
    Bound, LIMIT, Owner, OwnerResource, desc, error, field, handle, key, optional_field, result,
    string, validate_transport_use_keys,
};

pub(super) const DEVICE_KEY: &str = "oauth.device_session";

struct DeviceResource {
    owner: Arc<Owner>,
    credential_id: String,
    policy_generation: u64,
    credential_generation: u64,
    native: OpaqueDeviceSessionHandle,
}

impl HostResource for DeviceResource {
    fn resource_type_key() -> Option<ResourceTypeKey> {
        Some(ResourceTypeKey::new(DEVICE_KEY).expect("static device key"))
    }

    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        if let Some(oauth) = &self.owner.oauth
            && oauth.device_session_matches_binding(
                &self.native,
                self.policy_generation,
                &self.owner.identity,
                &self.credential_id,
            )
        {
            let _ = oauth.terminal(&self.native);
        }
        Ok(CloseProgress::Ready)
    }
}

impl HostResourceType for DeviceResource {
    const KEY: &'static str = DEVICE_KEY;
    const DESCRIPTION: &'static str = "Owner-bound generic OAuth device session";
}

impl OwnerResource for DeviceResource {
    fn owner(&self) -> Arc<Owner> {
        self.owner.clone()
    }
}

pub(super) struct TransportDevice {
    resource: ResourceHandle,
    credential_generation: u64,
    native: OpaqueDeviceSessionHandle,
    owner: Arc<Owner>,
    credential_id: String,
    policy_generation: u64,
}

impl TransportDevice {
    pub(super) fn generation(&self) -> u64 {
        self.credential_generation
    }

    pub(super) fn for_send(&self) -> crate::auth::oauth::CredentialUse {
        crate::auth::oauth::CredentialUse::Device(self.native.clone())
    }

    pub(super) fn close_if_terminal(&self, vm: &mut Vm) -> VmResult<()> {
        let live = self.owner.oauth.as_ref().is_some_and(|oauth| {
            oauth.device_session_live(
                &self.native,
                self.policy_generation,
                &self.owner.identity,
                &self.credential_id,
            )
        });
        if self.owner.check().is_err() || !live {
            close_resource(vm, self.resource)?;
        }
        Ok(())
    }

    pub(super) fn terminate(&self, vm: &mut Vm) -> VmResult<()> {
        if let Some(oauth) = &self.owner.oauth
            && oauth.device_session_matches_binding(
                &self.native,
                self.policy_generation,
                &self.owner.identity,
                &self.credential_id,
            )
        {
            let _ = oauth.terminal(&self.native);
        }
        let _ = close_resource(vm, self.resource);
        Ok(())
    }
}

pub(super) fn meta() -> HostResourceTypeMeta {
    HostResourceTypeMeta::of::<DeviceResource>()
}

pub(super) fn close_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::close_device",
        vec![HostParamSchema::with_passing(
            "handle",
            key(DEVICE_KEY),
            HostParamPassing::TakeOwned,
        )],
        HostTypeSchema::Null,
        close_call,
    )
}

pub(super) fn issue(
    vm: &mut Vm,
    owner: &Arc<Owner>,
    credential_id: &str,
    native: OpaqueDeviceSessionHandle,
) -> VmResult<Value> {
    owner.authorize(credential_id)?;
    let credential_generation = owner
        .snapshot
        .credential_generations
        .get(credential_id)
        .copied()
        .ok_or_else(|| error("credential_unavailable"))?;
    let policy_generation = owner.snapshot.generation;
    let oauth = owner
        .oauth
        .as_ref()
        .ok_or_else(|| error("transport_unavailable"))?;
    if !oauth.device_session_live(&native, policy_generation, &owner.identity, credential_id) {
        return Err(error("device_session_invalid"));
    }
    if vm.host_context().resource_count() >= LIMIT {
        return Err(error("resource_limit"));
    }
    let value = super::issue(
        vm,
        DeviceResource {
            owner: owner.clone(),
            credential_id: credential_id.to_owned(),
            policy_generation,
            credential_generation,
            native,
        },
    )?;
    if let Err(failure) = owner.check() {
        let _ = close_resource(vm, handle(&value)?);
        return Err(failure);
    }
    Ok(value)
}

pub(super) fn transport(
    vm: &mut Vm,
    value: &Value,
    owner: &Arc<Owner>,
    credential_id: &str,
) -> VmResult<TransportDevice> {
    let resource = handle(value)?;
    let (resource_owner, bound_credential, policy_generation, credential_generation, native) = {
        let context = vm.host_context();
        let device = context
            .borrow_resource_with_key::<DeviceResource>(
                resource,
                &ResourceTypeKey::new(DEVICE_KEY).expect("static device key"),
            )
            .map_err(|_| error("resource_invalid"))?;
        (
            device.owner.clone(),
            device.credential_id.clone(),
            device.policy_generation,
            device.credential_generation,
            device.native.clone(),
        )
    };
    let bound_owner = vm
        .host_context()
        .scope_state::<Bound>()
        .map(|bound| Arc::clone(&bound.0))
        .ok_or_else(|| error("host_unbound"))?;
    if !Arc::ptr_eq(owner, &bound_owner) || !Arc::ptr_eq(owner, &resource_owner) {
        return Err(error("owner_mismatch"));
    }
    if bound_credential != credential_id || policy_generation != owner.snapshot.generation {
        return Err(error("handle_provenance"));
    }
    let expected_generation = owner
        .snapshot
        .credential_generations
        .get(credential_id)
        .copied()
        .ok_or_else(|| error("credential_unavailable"))?;
    if credential_generation != expected_generation {
        return Err(error("handle_provenance"));
    }
    let oauth = owner
        .oauth
        .as_ref()
        .ok_or_else(|| error("transport_unavailable"))?;
    if !oauth.device_session_matches_binding(
        &native,
        policy_generation,
        &owner.identity,
        credential_id,
    ) {
        return Err(error("handle_provenance"));
    }
    if !oauth.device_session_live(&native, policy_generation, &owner.identity, credential_id) {
        close_resource(vm, resource)?;
        return Err(error("resource_invalid"));
    }
    Ok(TransportDevice {
        resource,
        credential_generation,
        native,
        owner: owner.clone(),
        credential_id: credential_id.to_owned(),
        policy_generation,
    })
}

pub(super) fn cleanup_inactive(vm: &mut Vm, request: &Value, usage: &Value, credential_id: &str) {
    if validate_transport_use_keys(usage).is_err()
        || string(field(usage, "kind").unwrap_or(&Value::Null)).ok() != Some("device_session")
    {
        return;
    }
    let (Ok(None), Ok(None), Ok(None), Ok(Some(device))) = (
        optional_field(usage, "access_handle"),
        optional_field(usage, "refresh_handle"),
        optional_field(usage, "code_handle"),
        optional_field(usage, "device_handle"),
    ) else {
        return;
    };
    if optional_field(usage, "verifier_handle")
        .ok()
        .flatten()
        .is_some()
    {
        return;
    }
    let Ok(policy_value) = field(request, "policy_handle") else {
        return;
    };
    let Ok(owner) = super::policy_owner_for_cleanup(vm, policy_value) else {
        return;
    };
    if owner.check().is_ok() {
        return;
    }
    reclaim_inactive(vm, device, &owner, credential_id);
}

fn reclaim_inactive(vm: &mut Vm, value: &Value, owner: &Arc<Owner>, credential_id: &str) {
    let Ok(resource) = handle(value) else {
        return;
    };
    let (resource_owner, id, policy_generation, credential_generation, native) = {
        let context = vm.host_context();
        let Ok(device) = context.borrow_resource_with_key::<DeviceResource>(
            resource,
            &ResourceTypeKey::new(DEVICE_KEY).expect("static device key"),
        ) else {
            return;
        };
        (
            device.owner.clone(),
            device.credential_id.clone(),
            device.policy_generation,
            device.credential_generation,
            device.native.clone(),
        )
    };
    let bound_owner = vm
        .host_context()
        .scope_state::<Bound>()
        .map(|bound| Arc::clone(&bound.0));
    if !bound_owner.is_some_and(|bound| Arc::ptr_eq(&bound, owner))
        || !Arc::ptr_eq(owner, &resource_owner)
        || id != credential_id
        || policy_generation != owner.snapshot.generation
        || owner
            .snapshot
            .credential_generations
            .get(credential_id)
            .copied()
            != Some(credential_generation)
    {
        return;
    }
    let Some(oauth) = &owner.oauth else {
        return;
    };
    if oauth.device_session_matches_binding(
        &native,
        policy_generation,
        &owner.identity,
        credential_id,
    ) {
        let _ = close_resource(vm, resource);
    }
}

pub(super) fn close_issued(vm: &mut Vm, value: &Value) {
    if let Ok(resource) = handle(value) {
        let _ = close_resource(vm, resource);
    }
}

fn close_resource(vm: &mut Vm, resource: ResourceHandle) -> VmResult<()> {
    vm.host_context()
        .close_resource::<DeviceResource>(resource, ResourceCloseReason::Requested)
        .map(|_| ())
        .map_err(|_| error("resource_invalid"))
}

fn close_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let value = args.first().ok_or_else(|| error("invalid_request"))?;
    let resource = handle(value)?;
    let owner = {
        let context = vm.host_context();
        context
            .borrow_resource_with_key::<DeviceResource>(
                resource,
                &ResourceTypeKey::new(DEVICE_KEY).expect("static device key"),
            )
            .map_err(|_| error("resource_invalid"))?
            .owner
            .clone()
    };
    let bound_owner = vm
        .host_context()
        .scope_state::<Bound>()
        .map(|bound| Arc::clone(&bound.0))
        .ok_or_else(|| error("host_unbound"))?;
    if !Arc::ptr_eq(&owner, &bound_owner) {
        return Err(error("owner_mismatch"));
    }
    close_resource(vm, resource)?;
    owner.check()?;
    result(Value::Null)
}
