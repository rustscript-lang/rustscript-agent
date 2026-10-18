use std::sync::{Arc, Weak};

use rustscript_vm::resource::{
    CloseProgress, HostResource, ResourceCloseReason, ResourceErrorCode, ResourceHandle,
};
use rustscript_vm::vm::HostContextErrorKind;
use rustscript_vm::{
    CallOutcome, HostFunctionDescriptor, HostResourceType, HostTypeSchema, ResourceTypeKey, Value,
    Vm, VmResult,
};

use super::{
    Access, Owner, OwnerResource, Policy, Refresh, SecretSlot, borrow, desc, error, key,
    policy_owner_for_cleanup, result,
};

const TRANSIENT_KEYS: [&str; 7] = [
    Access::KEY,
    Refresh::KEY,
    SecretSlot::KEY,
    "oauth.device_session",
    "oauth.callback",
    "oauth.verifier",
    "oauth.authorization_code",
];

type ProbeFn = fn(&mut Vm, ResourceHandle, &'static str) -> Probe;
type CloseFn = fn(&mut Vm, ResourceHandle, &'static str) -> Result<CloseProgress, ()>;

#[derive(Clone)]
struct Entry {
    handle: ResourceHandle,
    type_key: &'static str,
    owner: Weak<Owner>,
    probe: ProbeFn,
    close: CloseFn,
}

#[derive(Default)]
struct TransientIndex {
    entries: Vec<Entry>,
}

enum Probe {
    Live(Arc<Owner>),
    Retired,
    Failed,
}

pub(super) fn tracks(type_key: &str) -> bool {
    TRANSIENT_KEYS.contains(&type_key)
}

pub(super) fn prepare(vm: &mut Vm) -> VmResult<()> {
    let snapshot = vm
        .host_context()
        .scope_state::<TransientIndex>()
        .map(|index| index.entries.clone())
        .unwrap_or_default();
    let mut retired = Vec::new();
    let mut failed = false;
    for entry in snapshot {
        match inspect(vm, &entry) {
            Probe::Retired => retired.push(entry.handle),
            Probe::Live(_) => {}
            Probe::Failed => failed = true,
        }
    }
    remove_entries(vm, &retired)?;
    if failed {
        return Err(error("resource_unavailable"));
    }
    let count = vm
        .host_context()
        .scope_state::<TransientIndex>()
        .map_or(0, |index| index.entries.len());
    if count >= super::LIMIT {
        return Err(error("resource_limit"));
    }
    Ok(())
}

pub(super) fn register<T>(vm: &mut Vm, handle: ResourceHandle, owner: Weak<Owner>) -> VmResult<()>
where
    T: HostResource + HostResourceType + OwnerResource,
{
    if !tracks(T::KEY) {
        return Ok(());
    }
    let mut context = vm.host_context();
    let index = context
        .scope_state_or_insert_with(TransientIndex::default)
        .map_err(|_| error("resource_unavailable"))?;
    if index.entries.len() >= super::LIMIT {
        return Err(error("resource_limit"));
    }
    index
        .entries
        .try_reserve(1)
        .map_err(|_| error("resource_unavailable"))?;
    index.entries.push(Entry {
        handle,
        type_key: T::KEY,
        owner,
        probe: probe::<T>,
        close: close::<T>,
    });
    Ok(())
}

fn probe<T>(vm: &mut Vm, handle: ResourceHandle, type_key: &'static str) -> Probe
where
    T: HostResource + HostResourceType + OwnerResource,
{
    if type_key != T::KEY {
        return Probe::Failed;
    }
    let Ok(expected) = ResourceTypeKey::new(type_key) else {
        return Probe::Failed;
    };
    let validation = vm
        .host_context()
        .execution_scope()
        .resources()
        .validate_resource_type_key(handle, &expected);
    if let Err(failure) = validation {
        return classify_resource_error(failure.code());
    }
    let borrowed = {
        let context = vm.host_context();
        context
            .borrow_resource_with_key::<T>(handle, &expected)
            .map(|resource| resource.owner())
    };
    match borrowed {
        Ok(owner) => Probe::Live(owner),
        Err(failure) => match failure.kind() {
            HostContextErrorKind::Resource(resource) => classify_resource_error(resource.code()),
            _ => Probe::Failed,
        },
    }
}

fn classify_resource_error(code: ResourceErrorCode) -> Probe {
    match code {
        ResourceErrorCode::ResourceStale | ResourceErrorCode::ResourceAlreadyClosed => {
            Probe::Retired
        }
        _ => Probe::Failed,
    }
}

fn close<T>(
    vm: &mut Vm,
    handle: ResourceHandle,
    type_key: &'static str,
) -> Result<CloseProgress, ()>
where
    T: HostResource + HostResourceType + OwnerResource,
{
    if type_key != T::KEY {
        return Err(());
    }
    vm.host_context()
        .close_resource::<T>(handle, ResourceCloseReason::Requested)
        .map_err(|_| ())
}

fn inspect(vm: &mut Vm, entry: &Entry) -> Probe {
    match (entry.probe)(vm, entry.handle, entry.type_key) {
        Probe::Live(live_owner) => {
            let Some(indexed_owner) = entry.owner.upgrade() else {
                return Probe::Failed;
            };
            if Arc::ptr_eq(&indexed_owner, &live_owner) {
                Probe::Live(live_owner)
            } else {
                Probe::Failed
            }
        }
        Probe::Retired => Probe::Retired,
        Probe::Failed => Probe::Failed,
    }
}

fn remove_entries(vm: &mut Vm, handles: &[ResourceHandle]) -> VmResult<()> {
    if handles.is_empty() {
        return Ok(());
    }
    let mut context = vm.host_context();
    let index = context
        .scope_state_mut::<TransientIndex>()
        .ok_or_else(|| error("resource_unavailable"))?;
    index
        .entries
        .retain(|entry| !handles.contains(&entry.handle));
    Ok(())
}

pub(super) fn cleanup_desc() -> HostFunctionDescriptor {
    desc(
        "auth::cleanup_transients",
        vec![borrow("policy_handle", key(Policy::KEY))],
        HostTypeSchema::Null,
        cleanup_call,
    )
}

fn cleanup_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let policy = args.first().ok_or_else(|| error("invalid_request"))?;
    let owner = policy_owner_for_cleanup(vm, policy)?;
    cleanup_owner(vm, &owner)?;
    result(Value::Null)
}

fn cleanup_owner(vm: &mut Vm, owner: &Arc<Owner>) -> VmResult<()> {
    let snapshot = vm
        .host_context()
        .scope_state::<TransientIndex>()
        .map(|index| index.entries.clone())
        .unwrap_or_default();
    let mut retired = Vec::new();
    let mut failed = false;
    for entry in snapshot {
        match inspect(vm, &entry) {
            Probe::Retired => retired.push(entry.handle),
            Probe::Failed => failed = true,
            Probe::Live(live_owner) if Arc::ptr_eq(&live_owner, owner) => {
                match (entry.close)(vm, entry.handle, entry.type_key) {
                    Ok(CloseProgress::Ready) => retired.push(entry.handle),
                    Ok(CloseProgress::Pending) => failed = true,
                    Err(()) => match inspect(vm, &entry) {
                        Probe::Retired => retired.push(entry.handle),
                        Probe::Live(_) | Probe::Failed => failed = true,
                    },
                }
            }
            Probe::Live(_) => {}
        }
    }
    remove_entries(vm, &retired)?;
    if failed {
        return Err(error("resource_unavailable"));
    }
    Ok(())
}
