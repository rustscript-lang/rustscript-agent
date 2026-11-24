//! Declared-shape carriers at the host→guest return boundary.
//!
//! Two distinct nullabilities exist in the pinned core and they are *not*
//! interchangeable:
//!
//! * `HostTypeSchema::Optional(T)` is the legacy nullable slot. Its physical
//!   carrier is the internal `Null` value.
//! * `HostTypeSchema::Option(T)` is the guest `Option<T>`. Its physical carrier
//!   is the canonical map `{tag: Bool, payload?}` (`tag: false` = `None`,
//!   `tag: true` + `payload` = `Some`). `Some(())` is `{tag: true, payload:
//!   null}`, so a physical null payload never selects the variant — only the
//!   Boolean tag does.
//!
//! Because a physical null can be `None`, `Some(())`, or `Some(None)`, this
//! module never *infers* an `Option` from a null. An adapter that owns a
//! confirmed legacy nullable leaf constructs its carrier explicitly through
//! [`logical_option`], and a value that already carries a canonical carrier is
//! rejected instead of being wrapped twice. Anything the adapter cannot decide
//! is a hard error, never a guess.
//!
//! Shape checking itself is delegated to the VM's own native validator
//! (`Vm::validate_guest_result_value`): it walks `Result`, `Map`, `Optional`,
//! `Option`, `Named` and `Array` over native [`Value`]s, keeps a resource field
//! as its original `Value::Int` handle and checks that handle against the live
//! resource table, and never converts `Bytes` through JSON. Calling it from
//! inside the adapter — instead of leaving the check to the post-return pass —
//! is what lets an adapter that has already issued resources observe the
//! failure inside its own rollback scope.

use std::fmt;

use rustscript_vm::{
    CallOutcome, CallReturn, HostTypeSchema, Value, Vm, VmError, VmResult, option,
};

/// Why a declared return slot could not be shaped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ShapeError {
    slot: String,
    detail: String,
}

impl ShapeError {
    fn new(slot: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            slot: slot.into(),
            detail: detail.into(),
        }
    }

    /// Stable host error code used when the failure crosses the boundary.
    pub(crate) fn code(&self) -> &'static str {
        "host_return_shape_invalid"
    }
}

impl fmt::Display for ShapeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.slot, self.detail)
    }
}

impl std::error::Error for ShapeError {}

impl From<ShapeError> for VmError {
    fn from(error: ShapeError) -> Self {
        VmError::HostError(format!("{} ({})", error, error.code()))
    }
}

/// Builds the canonical carrier for one confirmed nullable leaf slot.
///
/// `legacy` is what the adapter itself observed for that field: `None` when the
/// field was absent or physically null on the old wire, `Some(value)` when the
/// adapter put a value there. It must never be handed a value it re-read from an
/// already-shaped result. The declared `inner` type then decides the rest:
///
/// * a nested `Option`/`Result` slot must already carry a canonical carrier,
///   so `Some(None)` and `Some(Some(v))` stay distinguishable;
/// * a `Unit` slot accepts the physical null payload that means `Some(())`;
/// * any other slot must not hand in a null (that would be indistinguishable
///   from `None`) and must not hand in an already-shaped carrier (that would be
///   wrapped a second time).
pub(crate) fn logical_option(
    inner: &HostTypeSchema,
    legacy: Option<&Value>,
) -> Result<Value, ShapeError> {
    let Some(value) = legacy else {
        return Ok(option::none_carrier());
    };
    let nested = matches!(
        inner,
        HostTypeSchema::Option(_) | HostTypeSchema::Result { .. }
    );
    if nested {
        if ensure_carrier(value).is_err() {
            return Err(ShapeError::new(
                "Option",
                "nested Option/Result payload must already be one canonical {tag, payload} carrier",
            ));
        }
        return Ok(option::some_carrier(value.clone()));
    }
    if matches!(value, Value::Null) && !matches!(inner, HostTypeSchema::Unit) {
        return Err(ShapeError::new(
            "Option",
            "a physical null payload cannot decide this Option; pass no value or an explicit nested carrier",
        ));
    }
    if ensure_carrier(value).is_ok() {
        return Err(ShapeError::new(
            "Option",
            "value already carries a canonical {tag, payload} carrier; refusing to wrap it twice",
        ));
    }
    Ok(option::some_carrier(value.clone()))
}

/// Checks the canonical carrier shape strictly: only `tag` (Boolean, required)
/// and `payload` may appear, and `tag: false` must not carry a payload.
fn ensure_carrier(value: &Value) -> Result<(), ShapeError> {
    let Value::Map(entries) = value else {
        return Err(ShapeError::new("carrier", "not a map"));
    };
    if entries.len() > 2 {
        return Err(ShapeError::new(
            "carrier",
            "more than the two canonical fields",
        ));
    }
    for (key, _) in entries.iter() {
        match key {
            Value::String(name) if name.as_str() == "tag" || name.as_str() == "payload" => {}
            _ => {
                return Err(ShapeError::new(
                    "carrier",
                    "non-canonical field in a {tag, payload} carrier",
                ));
            }
        }
    }
    let Some(Value::Bool(tag)) = entries.get(&Value::string("tag")) else {
        return Err(ShapeError::new("carrier", "missing Boolean tag"));
    };
    let payload = entries.get(&Value::string("payload"));
    if !*tag && payload.is_some() {
        return Err(ShapeError::new("carrier", "None must not carry a payload"));
    }
    Ok(())
}

/// Whether `value` is already one canonical `Option`/`Result` carrier.
#[cfg(test)]
fn is_carrier(value: &Value) -> bool {
    ensure_carrier(value).is_ok()
}

/// Converts a value that the adapter built on the **old** nullable wire into the
/// declared shape, constructing one canonical carrier for every declared
/// `Option` slot.
///
/// Only the declared schema decides *where* a carrier belongs, so this is not a
/// guess from the data: a declared `Option` field that is absent from a named
/// map or physically null is `None`, an already-canonical carrier is left
/// alone instead of being wrapped twice, and any other declared shape recurses.
/// A legacy `Optional` slot in the target schema, an undecidable null in a
/// non-`Option` slot, and an unsupported schema all fail closed.
pub(crate) fn logical_from_legacy(
    schema: &HostTypeSchema,
    value: &Value,
) -> Result<Value, ShapeError> {
    match schema {
        HostTypeSchema::Option(inner) => {
            if ensure_carrier(value).is_ok() {
                return Ok(value.clone());
            }
            if matches!(value, Value::Null) {
                return logical_option(inner, None);
            }
            // The payload of a `Some` keeps its own declared shape: a named or
            // array payload still has to have every nested nullable leaf
            // converted before it is wrapped, otherwise the inner Option slots
            // would still be physical nulls under the carrier.
            if matches!(
                inner.as_ref(),
                HostTypeSchema::Named { .. } | HostTypeSchema::Array(_)
            ) {
                let converted = logical_from_legacy(inner, value)?;
                return logical_option(inner, Some(&converted));
            }
            logical_option(inner, Some(value))
        }
        HostTypeSchema::Named { fields, .. } => {
            let Value::Map(entries) = value else {
                return Err(ShapeError::new("Named", "not a map"));
            };
            let mut shaped = Vec::with_capacity(fields.len());
            for field in fields {
                let entry = entries.get(&Value::string(&field.name));
                let converted = match (entry, &field.ty) {
                    (Some(entry), ty) => logical_from_legacy(ty, entry)?,
                    (None, HostTypeSchema::Option(inner)) => logical_option(inner, None)?,
                    (None, HostTypeSchema::Optional(_)) => continue,
                    (None, _) => {
                        return Err(ShapeError::new(
                            &field.name,
                            "required field is missing from the old wire shape",
                        ));
                    }
                };
                shaped.push((Value::string(&field.name), converted));
            }
            Ok(Value::map(shaped))
        }
        HostTypeSchema::Array(inner) => {
            let Value::Array(items) = value else {
                return Err(ShapeError::new("Array", "not an array"));
            };
            let mut shaped = Vec::with_capacity(items.len());
            for item in items.iter() {
                shaped.push(logical_from_legacy(inner, item)?);
            }
            Ok(Value::Array(shaped.into()))
        }
        HostTypeSchema::Null => Err(ShapeError::new(
            "Null",
            "a declared physical Null is not an Option and cannot be converted",
        )),
        HostTypeSchema::Optional(_) => Err(ShapeError::new(
            "Optional",
            "the converted shape must not keep a legacy nullable slot",
        )),
        HostTypeSchema::Unknown | HostTypeSchema::Map(_) | HostTypeSchema::Callable { .. } => Err(
            ShapeError::new("schema", "an open slot cannot be converted field by field"),
        ),
        HostTypeSchema::Result { .. } => Err(ShapeError::new(
            "Result",
            "a Result carrier is built by its owner, not converted from null",
        )),
        HostTypeSchema::Unit
        | HostTypeSchema::Int
        | HostTypeSchema::Float
        | HostTypeSchema::Number
        | HostTypeSchema::Bool
        | HostTypeSchema::String
        | HostTypeSchema::Bytes
        | HostTypeSchema::Resource(_) => {
            if matches!(value, Value::Null) {
                return Err(ShapeError::new(
                    "leaf",
                    "a physical null cannot stand in for a non-Option leaf",
                ));
            }
            Ok(value.clone())
        }
    }
}

/// The inverse of [`logical_from_legacy`] for a converted **parameter**.
///
/// A guest now sends the declared shape (with `Option` carriers), while the
/// durable record still has the old nullable JSON shape: `Some(payload)` becomes
/// the payload and `None` becomes a physical null, which is exactly how the
/// serde structs still model an absent field. Only the declared schema decides
/// where a carrier is read; an undeclared shape fails closed.
pub(crate) fn legacy_from_logical(
    schema: &HostTypeSchema,
    value: &Value,
) -> Result<Value, ShapeError> {
    match schema {
        HostTypeSchema::Option(inner) => match option_payload(inner, value)? {
            None => Ok(Value::Null),
            Some(payload) => legacy_from_logical(inner, payload),
        },
        HostTypeSchema::Named { fields, .. } => {
            let Value::Map(entries) = value else {
                return Err(ShapeError::new("Named", "not a map"));
            };
            let mut legacy = Vec::with_capacity(fields.len());
            for field in fields {
                match entries.get(&Value::string(&field.name)) {
                    Some(entry) => {
                        legacy.push((
                            Value::string(&field.name),
                            legacy_from_logical(&field.ty, entry)?,
                        ));
                    }
                    None if matches!(field.ty, HostTypeSchema::Option(_)) => {
                        legacy.push((Value::string(&field.name), Value::Null));
                    }
                    None => {
                        return Err(ShapeError::new(
                            &field.name,
                            "required field is missing from the declared shape",
                        ));
                    }
                }
            }
            Ok(Value::map(legacy))
        }
        HostTypeSchema::Array(inner) => {
            let Value::Array(items) = value else {
                return Err(ShapeError::new("Array", "not an array"));
            };
            let mut legacy = Vec::with_capacity(items.len());
            for item in items.iter() {
                legacy.push(legacy_from_logical(inner, item)?);
            }
            Ok(Value::Array(legacy.into()))
        }
        HostTypeSchema::Unknown
        | HostTypeSchema::Null
        | HostTypeSchema::Optional(_)
        | HostTypeSchema::Map(_)
        | HostTypeSchema::Callable { .. }
        | HostTypeSchema::Result { .. } => Err(ShapeError::new(
            "schema",
            "this slot has no declared concrete shape to read back",
        )),
        HostTypeSchema::Unit
        | HostTypeSchema::Int
        | HostTypeSchema::Float
        | HostTypeSchema::Number
        | HostTypeSchema::Bool
        | HostTypeSchema::String
        | HostTypeSchema::Bytes
        | HostTypeSchema::Resource(_) => Ok(value.clone()),
    }
}

/// Reads one logical `Option` carrier out of a guest-supplied parameter.
///
/// `Ok(None)` is a `None` carrier. `Ok(Some(payload))` is a live payload: a
/// resource payload stays its `Value::Int` handle. A `Some` without a payload is
/// only legal for a logical Unit, so a resource payload that is missing fails
/// closed instead of being treated as absent.
pub(crate) fn option_payload<'a>(
    inner: &HostTypeSchema,
    value: &'a Value,
) -> Result<Option<&'a Value>, ShapeError> {
    let (some, payload) = rustscript_vm::option::payload(value).map_err(|_| {
        ShapeError::new(
            "Option",
            "parameter is not one canonical {tag, payload} carrier",
        )
    })?;
    if !some {
        return Ok(None);
    }
    match payload {
        Some(payload) => Ok(Some(payload)),
        None if matches!(inner, HostTypeSchema::Unit) => Ok(Some(&Value::Null)),
        None => Err(ShapeError::new(
            "Option",
            "a Some carrier for this payload type must carry its payload",
        )),
    }
}

/// Validates a finished native value against the declared return schema inside
/// the calling adapter, then returns it.
///
/// Resource slots keep the `Value::Int` handle the adapter issued and are
/// checked against the live resource table; `Bytes` never leaves the VM.
pub(crate) fn shaped(vm: &mut Vm, schema: &HostTypeSchema, value: Value) -> VmResult<CallOutcome> {
    ensure_shaped(vm, schema, &value)?;
    Ok(CallOutcome::Return(CallReturn::One(value)))
}

/// The same check without consuming the value, for an adapter that still has to
/// fill a resource handle into the checked shape or embed it in a larger
/// envelope.
pub(crate) fn ensure_shaped(vm: &Vm, schema: &HostTypeSchema, value: &Value) -> VmResult<()> {
    vm.validate_guest_result_value(value, schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> Value {
        Value::string(value)
    }

    #[test]
    fn absent_legacy_nullable_becomes_none() {
        assert_eq!(
            logical_option(&HostTypeSchema::String, None).unwrap(),
            option::none_carrier()
        );
    }

    #[test]
    fn present_unit_payload_becomes_some_unit() {
        let carrier = logical_option(&HostTypeSchema::Unit, Some(&Value::Null)).unwrap();
        assert_eq!(carrier, option::some_carrier(Value::Null));
        assert!(is_carrier(&carrier), "Some(()) is a canonical carrier");
        assert_ne!(carrier, option::none_carrier(), "tag, not payload, selects");
    }

    #[test]
    fn nested_none_becomes_some_none() {
        let inner = HostTypeSchema::Option(Box::new(HostTypeSchema::String));
        let present = option::none_carrier();
        let carrier = logical_option(&inner, Some(&present)).unwrap();
        assert_eq!(carrier, option::some_carrier(option::none_carrier()));
        assert!(is_carrier(&carrier));
    }

    #[test]
    fn nested_some_becomes_some_some() {
        let inner = HostTypeSchema::Option(Box::new(HostTypeSchema::String));
        let present = option::some_carrier(text("alpha"));
        let carrier = logical_option(&inner, Some(&present)).unwrap();
        assert_eq!(carrier, option::some_carrier(present));
    }

    #[test]
    fn result_slot_payload_must_already_be_a_carrier() {
        let inner = HostTypeSchema::Result {
            ok: Box::new(HostTypeSchema::String),
            err: Box::new(HostTypeSchema::String),
        };
        let present = rustscript_vm::result::carrier(true, text("done"));
        let carrier = logical_option(&inner, Some(&present)).unwrap();
        assert_eq!(carrier, option::some_carrier(present));
        assert!(
            logical_option(&inner, Some(&Value::Null)).is_err(),
            "a physical null cannot stand in for a nested Result"
        );
    }

    #[test]
    fn a_second_conversion_is_refused() {
        let converted = option::some_carrier(text("alpha"));
        let error = logical_option(&HostTypeSchema::String, Some(&converted))
            .expect_err("an already-shaped value must not be wrapped twice");
        assert_eq!(error.code(), "host_return_shape_invalid");
        assert!(error.to_string().contains("twice"), "{error}");
    }

    #[test]
    fn a_physical_null_for_a_plain_leaf_is_undecidable() {
        let error = logical_option(&HostTypeSchema::String, Some(&Value::Null))
            .expect_err("null cannot decide Some(empty) versus None");
        assert!(error.to_string().contains("cannot decide"), "{error}");
    }

    #[test]
    fn canonical_carrier_reader_is_strict() {
        assert!(is_carrier(&option::none_carrier()));
        assert!(is_carrier(&option::some_carrier(Value::Null)));
        assert!(
            !is_carrier(&Value::map(vec![
                (Value::string("tag"), Value::Bool(false)),
                (Value::string("payload"), Value::Null),
            ])),
            "None with a payload is not canonical"
        );
        assert!(
            !is_carrier(&Value::map(vec![
                (Value::string("tag"), Value::Bool(true)),
                (Value::string("extra"), Value::Bool(true)),
            ])),
            "foreign fields are not canonical"
        );
        assert!(!is_carrier(&Value::Null));
    }
}
