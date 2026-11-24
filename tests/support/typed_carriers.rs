//! Strict projections at the Rust side of the RSS boundary.
use rustscript_vm::{Value, option};

/// Project a required logical Option field after the caller selects its schema.
/// Null is only a test-side sentinel for None; it is never sent into the VM.
pub fn nullable(carrier: &Value) -> &Value {
    match option::payload(carrier).expect("logical Option carrier") {
        (false, None) => &Value::Null,
        (true, Some(value)) if !matches!(value, Value::Null) => value,
        _ => panic!("noncanonical Option carrier"),
    }
}
