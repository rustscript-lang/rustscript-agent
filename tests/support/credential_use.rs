//! Shared `TransportCredentialUse` fixture for integration tests.
//!
//! The published contract declares `kind` plus five handle slots, each a logical
//! `Option<resource<…>>`. A hand-built map that omits a slot, or that puts a
//! physical null in one, is rejected by the callable's argument schema before
//! the adapter ever runs — so tests build the carrier here instead of restating
//! the field list, and adding a slot to the host contract cannot silently
//! desynchronise the fixtures again.
//!
//! `None` is the canonical `{tag: false}` carrier, never a null; a selected slot
//! is `{tag: true, payload: <live handle>}`.

use rustscript_vm::{Value, option};

/// Every handle slot the published `TransportCredentialUse` declares.
pub const HANDLE_SLOTS: [&str; 5] = [
    "access_handle",
    "refresh_handle",
    "code_handle",
    "verifier_handle",
    "device_handle",
];

/// A usage map with every handle slot absent.
pub fn none(kind: &str) -> Value {
    with_handles(kind, &[])
}

/// A usage map whose named slots carry live handles; every other slot is `None`.
pub fn with_handles(kind: &str, handles: &[(&str, Value)]) -> Value {
    let mut fields = vec![(Value::string("kind"), Value::string(kind))];
    for slot in HANDLE_SLOTS {
        let selected = handles
            .iter()
            .find(|(name, _)| *name == slot)
            .map(|(_, handle)| handle.clone());
        let carrier = match selected {
            Some(handle) => option::some_carrier(handle),
            None => option::none_carrier(),
        };
        fields.push((Value::string(slot), carrier));
    }
    Value::map(fields)
}
