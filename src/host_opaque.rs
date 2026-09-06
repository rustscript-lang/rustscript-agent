//! Smallest host-native opaque values the current VM can carry.
//!
//! pd-vm `Value` has no `opaque_nonserializable` variant. Callables are the
//! only heap values that `json::encode` rejects and that RSS cannot rebuild
//! from a map or string. Copy clones the `Arc` and therefore aliases the same
//! host object. Each mint uses an invalid prototype id and a unique
//! environment so RSS cannot dispatch or compare across handles.

use std::any::Any;
use std::collections::HashMap;
use std::mem::{align_of, size_of};
use std::sync::{Arc, Mutex, OnceLock};

use rustscript_vm::{CallableEnvironment, CallableKind, CallableValue, Value};

/// pd-vm looks up prototypes with `Vec::get(prototype_id as usize)`. `u32::MAX`
/// is in range for `usize` on this target and the lookup returns `None`, so
/// `CallValue` fails closed as `InvalidCallablePrototype(u32::MAX)` instead of
/// dispatching a registered or program callable.
const OPAQUE_PROTOTYPE_ID: u32 = u32::MAX;

fn unique_opaque_env() -> Arc<CallableEnvironment> {
    #[allow(dead_code)]
    struct MintEnv {
        cells: Mutex<Vec<Arc<Mutex<Value>>>>,
    }
    const _: () = {
        assert!(size_of::<MintEnv>() == size_of::<CallableEnvironment>());
        assert!(align_of::<MintEnv>() == align_of::<CallableEnvironment>());
    };
    let env = Arc::new(MintEnv {
        cells: Mutex::new(Vec::new()),
    });
    // SAFETY: `MintEnv` is a single-field twin of `CallableEnvironment`.
    // pd-vm keeps `cells` crate-private, so this host crate cannot name the
    // constructor; the compile-time size/align check rejects a layout drift.
    unsafe { Arc::from_raw(Arc::into_raw(env).cast::<CallableEnvironment>()) }
}

struct Registry {
    by_ptr: HashMap<usize, Registered>,
}

struct Registered {
    callable: Arc<CallableValue>,
    class: &'static str,
    payload: Arc<dyn Any + Send + Sync>,
}

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| {
        Mutex::new(Registry {
            by_ptr: HashMap::new(),
        })
    })
}

fn lock_registry() -> std::sync::MutexGuard<'static, Registry> {
    registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Host-minted opaque value. RSS may copy it; it cannot construct, parse, or
/// serialize a matching object.
#[derive(Clone)]
pub struct OpaqueHostValue {
    callable: Arc<CallableValue>,
    class: &'static str,
    payload: Arc<dyn Any + Send + Sync>,
}

impl OpaqueHostValue {
    pub fn mint<T: Send + Sync + 'static>(class: &'static str, payload: T) -> Self {
        let callable = Arc::new(CallableValue {
            prototype_id: OPAQUE_PROTOTYPE_ID,
            kind: CallableKind::HostFunction,
            env: Some(unique_opaque_env()),
        });
        let payload = Arc::new(payload) as Arc<dyn Any + Send + Sync>;
        let value = Self {
            callable: Arc::clone(&callable),
            class,
            payload: Arc::clone(&payload),
        };
        let ptr = Arc::as_ptr(&callable) as usize;
        lock_registry().by_ptr.insert(
            ptr,
            Registered {
                callable,
                class,
                payload,
            },
        );
        value
    }

    pub fn from_vm_value(value: &Value) -> Option<Self> {
        let Value::Callable(callable) = value else {
            return None;
        };
        let registered = lock_registry()
            .by_ptr
            .get(&(Arc::as_ptr(callable) as usize))
            .cloned()?;
        Some(Self {
            callable: registered.callable,
            class: registered.class,
            payload: registered.payload,
        })
    }

    pub fn to_vm_value(&self) -> Value {
        Value::Callable(Arc::clone(&self.callable))
    }

    pub fn class(&self) -> &'static str {
        self.class
    }

    pub fn ptr(&self) -> usize {
        Arc::as_ptr(&self.callable) as usize
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.callable, &other.callable)
    }

    pub fn downcast_ref<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.payload.as_ref().downcast_ref::<T>()
    }
}

impl Registered {
    fn cloned(&self) -> Self {
        Self {
            callable: Arc::clone(&self.callable),
            class: self.class,
            payload: Arc::clone(&self.payload),
        }
    }
}

impl Clone for Registered {
    fn clone(&self) -> Self {
        self.cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    use rustscript_vm::{
        SourceFlavor, Vm, VmError, VmStatus, compile_source_with_flavor, format_value,
    };

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

    fn rss_call_handle(handle: Value) -> Result<Value, VmError> {
        let compiled = compile_source_with_flavor(
            r#"
pub fn run(handle: fn() -> int) -> int {
    let _ = handle();
    0
}
"#,
            SourceFlavor::RustScript,
        )
        .unwrap_or_else(|error| panic!("call probe must compile: {error}"));
        let mut vm = Vm::try_new_shared(Arc::new(compiled.program)).expect("call probe vm");
        drive_root_frame(&mut vm);
        let run = vm
            .resolve_exported_callable("run")
            .expect("call probe exports run");
        vm.invoke_callable(run, &[handle])
    }

    #[test]
    fn opaque_host_home_is_not_equal_to_policy_handle() {
        let home = OpaqueHostValue::mint("HostHome", ());
        let policy = OpaqueHostValue::mint("OpaquePolicyHandle", ());
        assert_ne!(home.to_vm_value(), policy.to_vm_value());
    }

    #[test]
    fn opaque_separate_mints_are_not_equal() {
        let first = OpaqueHostValue::mint("HostHome", 1u8);
        let second = OpaqueHostValue::mint("HostHome", 2u8);
        assert_ne!(first.to_vm_value(), second.to_vm_value());
    }

    #[test]
    fn opaque_copied_alias_equals_source() {
        let minted = OpaqueHostValue::mint("HostHome", ());
        let value = minted.to_vm_value();
        assert_eq!(value, value.clone());
    }

    #[test]
    fn opaque_call_value_returns_invalid_callable_prototype_without_host_effect() {
        let host_effect = Arc::new(AtomicBool::new(false));
        let minted = OpaqueHostValue::mint("HostHome", Arc::clone(&host_effect));
        let error = rss_call_handle(minted.to_vm_value()).expect_err("opaque must not dispatch");
        assert!(
            matches!(error, VmError::InvalidCallablePrototype(u32::MAX)),
            "expected InvalidCallablePrototype(u32::MAX), got {error:?}"
        );
        assert!(
            !host_effect.load(Ordering::SeqCst),
            "calling an opaque host value must not run host payload"
        );
        let policy = OpaqueHostValue::mint("OpaquePolicyHandle", Arc::clone(&host_effect));
        let error = rss_call_handle(policy.to_vm_value()).expect_err("policy must not dispatch");
        assert!(
            matches!(error, VmError::InvalidCallablePrototype(u32::MAX)),
            "expected InvalidCallablePrototype(u32::MAX), got {error:?}"
        );
        assert!(!host_effect.load(Ordering::SeqCst));
    }

    #[test]
    fn opaque_value_denies_map_string_reconstruction_and_stringify_leak() {
        let minted =
            OpaqueHostValue::mint("HostHome", std::path::PathBuf::from("/tmp/secret-home"));
        let vm = minted.to_vm_value();
        assert!(matches!(vm, Value::Callable(_)));
        assert!(OpaqueHostValue::from_vm_value(&Value::string("/tmp/secret-home")).is_none());
        assert!(
            OpaqueHostValue::from_vm_value(&Value::map(vec![
                (Value::string("class"), Value::string("HostHome")),
                (Value::string("id"), Value::string("1")),
            ]))
            .is_none()
        );
        let copy = vm.clone();
        let recovered = OpaqueHostValue::from_vm_value(&copy).expect("copy aliases");
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
