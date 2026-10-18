use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

use rustscript_vm::resource::{
    CloseProgress, HostResource, ResourceCloseReason, ResourceHandle, ResourceResult,
};
use rustscript_vm::{
    CallOutcome, HostApiCatalog, HostFunctionRegistry, HostModuleDescriptor, HostParamPassing,
    HostParamSchema, HostResourceType, HostResourceTypeMeta, ResourceTypeKey, Value, Vm, VmResult,
};

use crate::config_file::AgentPaths;
use crate::runtime::rss_runner::RunCancellation;

use super::{Bound, LIMIT, desc, error, key, object, result};

pub(crate) const PATH_IMPORT_NAME: &str = "config::resolved_path_result";
const MAX_CONFIG_PATH_BYTES: usize = 2048;
const RESOURCE_KEY: &str = "config.path_home";

struct ConfigPathHome {
    owner: Arc<PathOwner>,
}

impl HostResource for ConfigPathHome {
    fn resource_type_key() -> Option<ResourceTypeKey> {
        Some(ResourceTypeKey::new(RESOURCE_KEY).expect("static resource key"))
    }

    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        self.owner.revoked.store(true, Ordering::Release);
        Ok(CloseProgress::Ready)
    }
}

impl HostResourceType for ConfigPathHome {
    const KEY: &'static str = RESOURCE_KEY;
    const DESCRIPTION: &'static str = "Trusted config-path home for this run";
}

struct PathOwner {
    config_path: PathBuf,
    cancellation: RunCancellation,
    deadline: Instant,
    revoked: AtomicBool,
}

#[derive(Clone, Copy, Default)]
struct OwnerFlags {
    cancelled: bool,
    deadline_exceeded: bool,
    revoked: bool,
}

impl PathOwner {
    fn flags(&self) -> OwnerFlags {
        OwnerFlags {
            cancelled: self.cancellation.token().is_cancelled()
                || self.cancellation.requested().is_some(),
            deadline_exceeded: Instant::now() >= self.deadline,
            revoked: self.revoked.load(Ordering::Acquire),
        }
    }
}

pub(super) struct BoundPaths(Arc<PathOwner>);

/// No-store access to the one host-derived structural config path.
pub struct ConfigPathHost {
    config_path: PathBuf,
    cancellation: RunCancellation,
    owners: Mutex<Vec<std::sync::Weak<PathOwner>>>,
}

impl ConfigPathHost {
    pub fn new(home: impl Into<PathBuf>, cancellation: RunCancellation) -> Result<Self, String> {
        let deadline = finite_active_deadline(&cancellation)?;
        let paths = AgentPaths::from_home(home.into()).map_err(|_| "invalid_host_home")?;
        if Instant::now() >= deadline {
            return Err("finite_deadline_required".into());
        }
        Ok(Self {
            config_path: paths.config,
            cancellation,
            owners: Mutex::new(Vec::new()),
        })
    }

    /// Revokes every owner issued by this host.
    pub fn revoke(&self) {
        let mut owners = self
            .owners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        owners.retain(|weak| {
            if let Some(owner) = weak.upgrade() {
                owner.revoked.store(true, Ordering::Release);
                true
            } else {
                false
            }
        });
    }

    /// Installs only the config-path function against the compile catalog.
    pub fn register(
        &self,
        registry: &mut HostFunctionRegistry,
        catalog: &HostApiCatalog,
    ) -> VmResult<()> {
        path_host_module()
            .install_from_catalog(registry, catalog)
            .map(|_| ())
    }

    /// Publishes one current-VM resource and the matching private scope owner.
    pub fn bind_vm(&self, vm: &mut Vm) -> VmResult<Value> {
        let deadline = finite_active_deadline(&self.cancellation).map_err(error)?;
        let mut context = vm.host_context();
        if context.scope_state::<Bound>().is_some() || context.scope_state::<BoundPaths>().is_some()
        {
            return Err(error("already_bound"));
        }
        if context.resource_count() >= LIMIT {
            return Err(error("resource_limit"));
        }
        let owner = Arc::new(PathOwner {
            config_path: self.config_path.clone(),
            cancellation: self.cancellation.clone(),
            deadline,
            revoked: AtomicBool::new(false),
        });
        let resource = context
            .push_resource(ConfigPathHome {
                owner: Arc::clone(&owner),
            })
            .map_err(|_| error("resource_unavailable"))?;
        let handle = resource.handle();
        if context
            .scope_state_or_insert_with(|| BoundPaths(Arc::clone(&owner)))
            .is_err()
        {
            let _ =
                context.close_resource::<ConfigPathHome>(handle, ResourceCloseReason::Requested);
            return Err(error("resource_unavailable"));
        }
        self.owners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Arc::downgrade(&owner));
        Ok(object(vec![("host_home", Value::Int(handle.raw() as i64))]))
    }
}

fn finite_active_deadline(cancellation: &RunCancellation) -> Result<Instant, &'static str> {
    if cancellation.has_deadline_overflow() {
        return Err("finite_deadline_required");
    }
    let deadline = cancellation
        .deadline_instant()
        .filter(|deadline| *deadline > Instant::now())
        .ok_or("finite_deadline_required")?;
    if cancellation.requested().is_some() || cancellation.token().is_cancelled() {
        return Err("cancelled");
    }
    Ok(deadline)
}

pub(super) fn home_meta() -> HostResourceTypeMeta {
    HostResourceTypeMeta::of::<ConfigPathHome>()
}

pub(super) fn resolved_path_result_desc() -> rustscript_vm::HostFunctionDescriptor {
    desc(
        PATH_IMPORT_NAME,
        vec![HostParamSchema::with_passing(
            "home",
            key(RESOURCE_KEY),
            HostParamPassing::Borrow,
        )],
        super::fallible::result_type(
            "ConfigPathResultEnvelope",
            rustscript_vm::HostTypeSchema::String,
        ),
        resolved_path_result_call,
    )
}

fn path_host_module() -> HostModuleDescriptor {
    HostModuleDescriptor {
        name: "config-path",
        functions: &[resolved_path_result_desc],
        resources: &[home_meta],
    }
}

fn resolved_path_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let bound_owner = vm
        .host_context()
        .scope_state::<BoundPaths>()
        .map(|bound| Arc::clone(&bound.0));
    let Some(owner) = bound_owner else {
        return failure("host_unbound", OwnerFlags::default());
    };
    let flags = owner.flags();
    if flags.cancelled || flags.deadline_exceeded || flags.revoked {
        return failure("policy_inactive", flags);
    }
    let Some(value) = args.first() else {
        return failure("resource_invalid", flags);
    };
    let handle = match resource_handle(value) {
        Ok(handle) => handle,
        Err(()) => return failure("resource_invalid", flags),
    };
    let resource_owner = {
        let context = vm.host_context();
        match context.borrow_resource_with_key::<ConfigPathHome>(
            handle,
            &ResourceTypeKey::new(RESOURCE_KEY).expect("static resource key"),
        ) {
            Ok(resource) => Arc::clone(&resource.owner),
            Err(_) => return failure("resource_invalid", owner.flags()),
        }
    };
    if !Arc::ptr_eq(&owner, &resource_owner) {
        return failure("owner_mismatch", owner.flags());
    }
    let Some(path) = owner.config_path.to_str() else {
        return failure("invalid_path", owner.flags());
    };
    if path.is_empty() || path.len() > MAX_CONFIG_PATH_BYTES || path.chars().any(char::is_control) {
        return failure("invalid_path", owner.flags());
    }
    let flags = owner.flags();
    if flags.cancelled || flags.deadline_exceeded || flags.revoked {
        return failure("policy_inactive", flags);
    }
    result(object(vec![
        ("ok", Value::Bool(true)),
        ("error", Value::Null),
        ("value", Value::string(path)),
    ]))
}

fn resource_handle(value: &Value) -> Result<ResourceHandle, ()> {
    let Value::Int(raw) = value else {
        return Err(());
    };
    ResourceHandle::from_raw((*raw).try_into().map_err(|_| ())?).map_err(|_| ())
}

fn failure(code: &str, flags: OwnerFlags) -> VmResult<CallOutcome> {
    result(object(vec![
        ("ok", Value::Bool(false)),
        (
            "error",
            object(vec![
                ("code", Value::string(code)),
                ("cancelled", Value::Bool(flags.cancelled)),
                ("deadline_exceeded", Value::Bool(flags.deadline_exceeded)),
                ("revoked", Value::Bool(flags.revoked)),
            ]),
        ),
        ("value", Value::Null),
    ]))
}
