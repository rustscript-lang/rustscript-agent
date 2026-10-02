use rustscript_vm::{HostTypeSchema, Value, VmResult};

use crate::auth::oauth::{
    DeviceIdField, ExchangeCodeField, NativeRequestBodyIntent, SecretBodyFieldSelection,
};
use crate::auth::request_body::RequestBodyEncoding;

use super::{error, named, opt};

pub(super) fn intent_type() -> HostTypeSchema {
    named(
        "TransportPayloadIntent",
        vec![
            ("encoding", HostTypeSchema::String),
            ("secret_fields", HostTypeSchema::String),
            ("device_field", opt(HostTypeSchema::String)),
            ("code_field", opt(HostTypeSchema::String)),
        ],
    )
}

const MAX_SELECTOR_BYTES: usize = 64;

fn invalid() -> rustscript_vm::VmError {
    error("payload_intent_invalid")
}

fn selector(value: Option<&Value>) -> VmResult<&str> {
    let Some(Value::String(value)) = value else {
        return Err(invalid());
    };
    if value.len() > MAX_SELECTOR_BYTES || value.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(value)
}

fn optional_selector(value: Option<&Value>) -> VmResult<Option<&str>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => selector(Some(value)).map(Some),
    }
}

/// Parse the public closed selector record into the native-only body intent.
/// No body values or secret material cross this boundary.
pub(super) fn parse(value: &Value) -> VmResult<NativeRequestBodyIntent> {
    let Value::Map(entries) = value else {
        return Err(invalid());
    };

    let mut seen = 0u8;
    let mut encoding = None;
    let mut secret_fields = None;
    let mut device_field = None;
    let mut code_field = None;

    for (key, value) in entries.iter() {
        let Value::String(key) = key else {
            return Err(invalid());
        };
        let (bit, target) = match key.as_str() {
            "encoding" => (1, &mut encoding),
            "secret_fields" => (2, &mut secret_fields),
            "device_field" => (4, &mut device_field),
            "code_field" => (8, &mut code_field),
            _ => return Err(invalid()),
        };
        if seen & bit != 0 {
            return Err(invalid());
        }
        seen |= bit;
        *target = Some(value);
    }

    let encoding = selector(encoding)?;
    let encoding = match encoding {
        "form" => RequestBodyEncoding::Form,
        "json_object" => RequestBodyEncoding::JsonObject,
        _ => return Err(invalid()),
    };
    let secret_fields = selector(secret_fields)?;
    let device_field = optional_selector(device_field)?;
    let code_field = optional_selector(code_field)?;

    let secret_fields = match (secret_fields, device_field, code_field) {
        ("none", None, None) => SecretBodyFieldSelection::None,
        ("device", Some("device_code"), None) => SecretBodyFieldSelection::Device {
            field: DeviceIdField::DeviceCode,
        },
        ("device", Some("device_auth_id"), None) => SecretBodyFieldSelection::Device {
            field: DeviceIdField::DeviceAuthId,
        },
        ("device", Some("device_id"), None) => SecretBodyFieldSelection::Device {
            field: DeviceIdField::DeviceId,
        },
        ("authorization_code", None, Some("code")) => SecretBodyFieldSelection::AuthorizationCode {
            code_field: ExchangeCodeField::Code,
        },
        ("authorization_code", None, Some("authorization_code")) => {
            SecretBodyFieldSelection::AuthorizationCode {
                code_field: ExchangeCodeField::AuthorizationCode,
            }
        }
        _ => return Err(invalid()),
    };

    Ok(NativeRequestBodyIntent {
        encoding,
        secret_fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(fields: Vec<(&str, Value)>) -> Value {
        Value::map(
            fields
                .into_iter()
                .map(|(name, value)| (Value::string(name), value))
                .collect(),
        )
    }

    fn valid_device(field: &str) -> Value {
        record(vec![
            ("encoding", Value::string("json_object")),
            ("secret_fields", Value::string("device")),
            ("device_field", Value::string(field)),
        ])
    }

    #[test]
    fn parser_maps_each_closed_device_alias_without_defaulting() {
        for (label, expected) in [
            ("device_code", DeviceIdField::DeviceCode),
            ("device_auth_id", DeviceIdField::DeviceAuthId),
            ("device_id", DeviceIdField::DeviceId),
        ] {
            let parsed = parse(&valid_device(label)).expect("supported device alias");
            assert!(matches!(
                parsed.secret_fields,
                SecretBodyFieldSelection::Device { field } if field == expected
            ));
        }
    }

    #[test]
    fn parser_returns_fixed_error_for_structural_invalid_records() {
        let wrong_type = record(vec![
            ("encoding", Value::string("json_object")),
            ("secret_fields", Value::string("device")),
            ("device_field", Value::Int(7)),
        ]);
        let non_string_key = Value::map(vec![
            (Value::Int(5), Value::string("private-marker")),
            (Value::string("encoding"), Value::string("json_object")),
            (Value::string("secret_fields"), Value::string("none")),
        ]);
        let extra = record(vec![
            ("encoding", Value::string("json_object")),
            ("secret_fields", Value::string("none")),
            ("extra", Value::string("private-marker")),
        ]);
        let cases = [Value::Int(7), wrong_type, non_string_key, extra];
        for value in cases {
            let failure = parse(&value).expect_err("invalid record rejected");
            assert!(failure.to_string().ends_with("payload_intent_invalid"));
            assert!(!failure.to_string().contains("private-marker"));
        }
    }
}
