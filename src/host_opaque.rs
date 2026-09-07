//! Smallest host-native opaque values the current VM can carry.
//!
//! pd-vm `Value` has no `opaque_nonserializable` variant. Callables are the
//! only heap values that `json::encode` rejects and that RSS cannot rebuild
//! from a map or string. Copy clones the `Arc` and therefore aliases the same
//! host object. Each mint uses `env: None` and a process-unique reserved
//! invalid `prototype_id` so RSS cannot dispatch or compare across handles.

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, OnceLock, Weak};

use parking_lot::Mutex;
use rustscript_vm::{CallableKind, CallableValue, Value};

/// pd-vm looks up prototypes with `Vec::get(prototype_id as usize)`. Reserved
/// ids stay in the upper half of `u32` so a live program cannot index them.
pub(crate) const OPAQUE_ID_FLOOR: u32 = 1 << 31;
/// Plan-aligned live-handle ceiling (`max_turns: 64`).
pub(crate) const MAX_LIVE_OPAQUE_HANDLES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpaqueError {
    LiveHandleLimit,
    PrototypeIdSpaceExhausted,
}

struct IdPool {
    next: u32,
}

fn id_pool() -> &'static Mutex<IdPool> {
    static POOL: OnceLock<Mutex<IdPool>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(IdPool { next: u32::MAX }))
}

fn allocate_prototype_id() -> Result<u32, OpaqueError> {
    let mut pool = id_pool().lock();
    let id = pool.next;
    if id < OPAQUE_ID_FLOOR {
        return Err(OpaqueError::PrototypeIdSpaceExhausted);
    }
    pool.next = id.saturating_sub(1);
    Ok(id)
}

struct Registered {
    class: &'static str,
    payload: Arc<dyn Any + Send + Sync>,
    generation: u64,
}

struct RegistryInner {
    by_id: HashMap<u32, Registered>,
    generation: u64,
}

/// Owner-scoped opaque registry. Payloads die with the last owner `Arc`.
pub(crate) struct OpaqueRegistry {
    inner: Mutex<RegistryInner>,
}

impl OpaqueRegistry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(RegistryInner {
                by_id: HashMap::new(),
                generation: 0,
            }),
        })
    }

    #[cfg(test)]
    pub(crate) fn live_len(&self) -> usize {
        self.inner.lock().by_id.len()
    }

    pub(crate) fn clear(&self) {
        self.inner.lock().by_id.clear();
    }

    pub(crate) fn mint<T: Send + Sync + 'static>(
        self: &Arc<Self>,
        class: &'static str,
        payload: T,
    ) -> Result<OpaqueHostValue, OpaqueError> {
        let mut inner = self.inner.lock();
        if inner.by_id.len() >= MAX_LIVE_OPAQUE_HANDLES {
            return Err(OpaqueError::LiveHandleLimit);
        }
        let prototype_id = allocate_prototype_id()?;
        inner.generation = inner.generation.saturating_add(1);
        let generation = inner.generation;
        let payload = Arc::new(payload) as Arc<dyn Any + Send + Sync>;
        inner.by_id.insert(
            prototype_id,
            Registered {
                class,
                payload: Arc::clone(&payload),
                generation,
            },
        );
        Ok(OpaqueHostValue {
            callable: Arc::new(CallableValue {
                prototype_id,
                kind: CallableKind::HostFunction,
                env: None,
            }),
            class,
            payload: Arc::downgrade(&payload),
            registry: Arc::downgrade(self),
            generation,
            prototype_id,
        })
    }

    pub(crate) fn from_vm_value(self: &Arc<Self>, value: &Value) -> Option<OpaqueHostValue> {
        let Value::Callable(callable) = value else {
            return None;
        };
        if callable.kind != CallableKind::HostFunction || callable.env.is_some() {
            return None;
        }
        let inner = self.inner.lock();
        let registered = inner.by_id.get(&callable.prototype_id)?;
        Some(OpaqueHostValue {
            callable: Arc::clone(callable),
            class: registered.class,
            payload: Arc::downgrade(&registered.payload),
            registry: Arc::downgrade(self),
            generation: registered.generation,
            prototype_id: callable.prototype_id,
        })
    }

    fn contains(&self, prototype_id: u32, generation: u64, class: &'static str) -> bool {
        self.inner
            .lock()
            .by_id
            .get(&prototype_id)
            .is_some_and(|entry| entry.generation == generation && entry.class == class)
    }

    pub(crate) fn revoke(&self, prototype_id: u32) {
        self.inner.lock().by_id.remove(&prototype_id);
    }
}

impl Drop for OpaqueRegistry {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Host-minted opaque value. RSS may copy it; it cannot construct, parse, or
/// serialize a matching object.
#[derive(Clone)]
pub(crate) struct OpaqueHostValue {
    callable: Arc<CallableValue>,
    class: &'static str,
    payload: Weak<dyn Any + Send + Sync>,
    registry: Weak<OpaqueRegistry>,
    generation: u64,
    prototype_id: u32,
}

impl fmt::Debug for OpaqueHostValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueHostValue")
            .field("class", &self.class)
            .field("prototype_id", &self.prototype_id)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl OpaqueHostValue {
    pub(crate) fn to_vm_value(&self) -> Value {
        Value::Callable(Arc::clone(&self.callable))
    }

    pub(crate) fn class(&self) -> &'static str {
        self.class
    }

    pub(crate) fn prototype_id(&self) -> u32 {
        self.callable.prototype_id
    }

    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        self.prototype_id == other.prototype_id && Weak::ptr_eq(&self.registry, &other.registry)
    }

    pub(crate) fn downcast_arc<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        let registry = self.registry.upgrade()?;
        if !registry.contains(self.prototype_id, self.generation, self.class) {
            return None;
        }
        let payload = self.payload.upgrade()?;
        payload.downcast::<T>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};

    use rustscript_vm::{
        CallOutcome, CallReturn, CompileSourceFileOptions, HostApiBuilder, HostApiCatalog,
        HostFunctionRegistry, HostFunctionSchema, HostTypeSchema, SourceFlavor, Vm, VmError,
        VmStatus, compile_source_with_flavor_and_options, format_value,
    };

    struct ProbeFlag {
        fired: Arc<AtomicBool>,
    }

    fn drive_root_frame(vm: &mut Vm) {
        loop {
            match vm.run() {
                Ok(VmStatus::Halted) => return,
                Ok(VmStatus::Waiting(_)) => {
                    vm.wait_for_host_op_blocking_with_cancel(|| false)
                        .unwrap_or_else(|error| panic!("root wait failed: {error}"));
                }
                Ok(status) => panic!("unexpected root status: {status:?}"),
                Err(error) => panic!("root frame failed: {error}"),
            }
        }
    }

    fn probe_catalog() -> Arc<HostApiCatalog> {
        let mut builder = HostApiBuilder::new();
        builder.function(HostFunctionSchema::with_return(
            "probe::touch",
            vec![],
            HostTypeSchema::Int,
        ));
        Arc::new(builder.build().expect("probe catalog must build"))
    }

    fn touch_adapter(vm: &mut Vm, _args: &[Value]) -> rustscript_vm::VmResult<CallOutcome> {
        let fired = {
            let context = vm.host_context();
            context
                .module_state::<ProbeFlag>()
                .map(|flag| Arc::clone(&flag.fired))
        };
        if let Some(fired) = fired {
            fired.store(true, Ordering::SeqCst);
        }
        Ok(CallOutcome::Return(CallReturn::One(Value::Int(1))))
    }

    fn compile_probe_program() -> rustscript_vm::Program {
        let options = CompileSourceFileOptions::default().with_host_api_catalog(probe_catalog());
        compile_source_with_flavor_and_options(
            r#"
use probe;

pub fn run(handle: fn() -> int) -> int {
    let _ = handle();
    0
}

pub fn touch() -> int {
    probe::touch()
}
"#,
            SourceFlavor::RustScript,
            options,
        )
        .unwrap_or_else(|error| panic!("probe program must compile: {error}"))
        .program
    }

    fn bind_probe_vm(flag: Arc<AtomicBool>) -> Vm {
        let program = compile_probe_program();
        let catalog = probe_catalog();
        let mut registry = HostFunctionRegistry::restricted();
        for schema in rustscript_vm::catalog_import_schemas(catalog.as_ref(), "probe::touch") {
            registry
                .register_exact_static("probe::touch", 0, schema, touch_adapter)
                .expect("register exact probe::touch");
        }
        registry.register_static("probe::touch", 0, touch_adapter);
        registry
            .allow_builtin("probe::touch")
            .expect("allow probe::touch");
        let mut vm = Vm::try_new_shared(Arc::new(program)).expect("probe vm");
        registry
            .bind_vm_cached(&mut vm)
            .expect("bind probe registry");
        vm.host_context()
            .set_module_state(ProbeFlag { fired: flag });
        drive_root_frame(&mut vm);
        vm
    }

    fn rss_call_handle(vm: &mut Vm, handle: Value) -> Result<Value, VmError> {
        let run = vm
            .resolve_exported_callable("run")
            .expect("probe exports run");
        vm.invoke_callable(run, &[handle])
    }

    fn rss_touch(vm: &mut Vm) -> Result<Value, VmError> {
        let touch = vm
            .resolve_exported_callable("touch")
            .expect("probe exports touch");
        vm.invoke_callable(touch, &[])
    }

    #[test]
    fn opaque_host_home_is_not_equal_to_policy_handle() {
        let registry = OpaqueRegistry::new();
        let home = registry.mint("HostHome", ()).expect("home");
        let policy = registry.mint("OpaquePolicyHandle", ()).expect("policy");
        assert_ne!(home.to_vm_value(), policy.to_vm_value());
        assert_ne!(home.prototype_id(), policy.prototype_id());
        assert!(home.prototype_id() >= OPAQUE_ID_FLOOR);
        assert!(policy.prototype_id() >= OPAQUE_ID_FLOOR);
        assert_eq!(home.class(), "HostHome");
        assert_eq!(policy.class(), "OpaquePolicyHandle");
        match home.to_vm_value() {
            Value::Callable(callable) => assert!(callable.env.is_none()),
            other => panic!("expected callable, got {other:?}"),
        }
    }

    #[test]
    fn opaque_separate_mints_are_not_equal() {
        let registry = OpaqueRegistry::new();
        let first = registry.mint("HostHome", 1u8).expect("first");
        let second = registry.mint("HostHome", 2u8).expect("second");
        assert_ne!(first.to_vm_value(), second.to_vm_value());
        assert_ne!(first.prototype_id(), second.prototype_id());
    }

    #[test]
    fn opaque_copied_alias_equals_source_and_keeps_id() {
        let registry = OpaqueRegistry::new();
        let minted = registry.mint("HostHome", ()).expect("mint");
        let value = minted.to_vm_value();
        let alias = value.clone();
        assert_eq!(value, alias);
        match (&value, &alias) {
            (Value::Callable(left), Value::Callable(right)) => {
                assert_eq!(left.prototype_id, right.prototype_id);
                assert_eq!(left.prototype_id, minted.prototype_id());
                assert!(left.env.is_none());
            }
            _ => panic!("expected callable alias"),
        }
        let recovered = registry.from_vm_value(&alias).expect("alias lookup");
        assert!(minted.ptr_eq(&recovered));
    }

    #[test]
    fn opaque_ids_cannot_index_current_program() {
        let registry = OpaqueRegistry::new();
        let minted = registry.mint("HostHome", ()).expect("mint");
        let program = compile_probe_program();
        assert!(
            (minted.prototype_id() as usize) >= program.callable_prototypes.len(),
            "reserved id {} indexes program of len {}",
            minted.prototype_id(),
            program.callable_prototypes.len()
        );
        assert!(minted.prototype_id() >= OPAQUE_ID_FLOOR);
    }

    #[test]
    fn opaque_registry_is_bounded_and_fail_closed() {
        let registry = OpaqueRegistry::new();
        for index in 0..MAX_LIVE_OPAQUE_HANDLES {
            registry
                .mint("HostHome", index as u16)
                .unwrap_or_else(|error| panic!("mint {index} within bound: {error:?}"));
        }
        assert_eq!(registry.live_len(), MAX_LIVE_OPAQUE_HANDLES);
        assert_eq!(
            registry.mint("HostHome", 0u16).expect_err("65th mint"),
            OpaqueError::LiveHandleLimit
        );
        registry.clear();
        registry.mint("HostHome", 0u16).expect("mint after clear");
        assert_eq!(registry.live_len(), 1);
        let extra = registry.mint("HostHome", 1u16).expect("second after clear");
        registry.revoke(extra.prototype_id());
        assert_eq!(registry.live_len(), 1);
    }

    #[test]
    fn escaped_callable_fails_after_registry_drop() {
        let minted;
        let value;
        {
            let registry = OpaqueRegistry::new();
            minted = registry
                .mint("HostHome", PathBuf::from("/tmp/secret-home"))
                .expect("mint");
            value = minted.to_vm_value();
            assert!(registry.from_vm_value(&value).is_some());
            assert!(minted.downcast_arc::<PathBuf>().is_some());
        }
        assert!(minted.downcast_arc::<PathBuf>().is_none());
        let other = OpaqueRegistry::new();
        assert!(other.from_vm_value(&value).is_none());
    }

    #[test]
    fn opaque_call_value_returns_invalid_callable_prototype_without_host_effect() {
        let host_effect = Arc::new(AtomicBool::new(false));
        let mut vm = bind_probe_vm(Arc::clone(&host_effect));
        rss_touch(&mut vm).expect("real host callback must run");
        assert!(
            host_effect.load(Ordering::SeqCst),
            "probe::touch must fire the registered host callback"
        );
        host_effect.store(false, Ordering::SeqCst);

        let registry = OpaqueRegistry::new();
        let minted = registry.mint("HostHome", ()).expect("home");
        let error =
            rss_call_handle(&mut vm, minted.to_vm_value()).expect_err("opaque must not dispatch");
        assert!(
            matches!(
                error,
                VmError::InvalidCallablePrototype(id) if id == minted.prototype_id()
            ),
            "expected InvalidCallablePrototype({}), got {error:?}",
            minted.prototype_id()
        );
        assert!(
            !host_effect.load(Ordering::SeqCst),
            "calling an opaque host value must not run the registered host callback"
        );

        let policy = registry.mint("OpaquePolicyHandle", ()).expect("policy");
        let error =
            rss_call_handle(&mut vm, policy.to_vm_value()).expect_err("policy must not dispatch");
        assert!(
            matches!(
                error,
                VmError::InvalidCallablePrototype(id) if id == policy.prototype_id()
            ),
            "expected InvalidCallablePrototype({}), got {error:?}",
            policy.prototype_id()
        );
        assert!(!host_effect.load(Ordering::SeqCst));
    }

    #[test]
    fn opaque_value_denies_map_string_reconstruction_and_stringify_leak() {
        let registry = OpaqueRegistry::new();
        let minted = registry
            .mint("HostHome", PathBuf::from("/tmp/secret-home"))
            .expect("mint");
        let vm = minted.to_vm_value();
        assert!(matches!(vm, Value::Callable(_)));
        assert!(
            registry
                .from_vm_value(&Value::string("/tmp/secret-home"))
                .is_none()
        );
        assert!(
            registry
                .from_vm_value(&Value::map(vec![
                    (Value::string("class"), Value::string("HostHome")),
                    (Value::string("id"), Value::string("1")),
                ]))
                .is_none()
        );
        let copy = vm.clone();
        let recovered = registry.from_vm_value(&copy).expect("copy aliases");
        assert!(minted.ptr_eq(&recovered));
        let rendered = format_value(&vm);
        assert!(
            !rendered.contains("/tmp/secret-home"),
            "stringify must not leak the payload: {rendered}"
        );
        assert!(
            !rendered.contains("HostHome"),
            "stringify must not leak a reconstructible class token: {rendered}"
        );
        assert!(
            !rendered.contains('{'),
            "stringify must not be JSON: {rendered}"
        );
    }
}
