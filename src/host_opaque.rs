//! Smallest host-native opaque values the current VM can carry.
//!
//! pd-vm `Value` has no `opaque_nonserializable` variant. Callables are the
//! only heap values that `json::encode` rejects and that RSS cannot rebuild
//! from a map or string. Copy clones the `Arc` and therefore aliases the same
//! host object. Identity is the callable pointer, never an ID, JSON field, or
//! textual bearer token.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use rustscript_vm::{CallableKind, CallableValue, Value};

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
            prototype_id: 0,
            kind: CallableKind::HostFunction,
            env: None,
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
    use rustscript_vm::format_value;

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
