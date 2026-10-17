use rustscript_vm::{HostTypeSchema, Value, VmResult};

use crate::auth::oauth::{ExchangeCodeField, OpaqueExchangePair, OpaqueExchangeResponseIntent};

use super::{TransportCredential, envelope, error, key, named, opt, transport_response_type};

const MAX_SELECTOR_BYTES: usize = 64;
const MAX_REDIRECT_URI_BYTES: usize = 2048;

pub(super) fn intent_type() -> HostTypeSchema {
    named(
        "TransportCaptureIntent",
        vec![
            ("code_field", HostTypeSchema::String),
            ("redirect_uri", HostTypeSchema::String),
        ],
    )
}

pub(super) fn envelope_type() -> HostTypeSchema {
    envelope(
        "TransportCaptureEnvelope",
        vec![
            ("response", transport_response_type()),
            ("code_handle", opt(key("oauth.authorization_code"))),
            ("verifier_handle", opt(key("oauth.verifier"))),
        ],
    )
}

fn invalid() -> rustscript_vm::VmError {
    error("capture_intent_invalid")
}

fn bounded_string(value: Option<&Value>, max_bytes: usize, nonempty: bool) -> VmResult<String> {
    let Some(Value::String(value)) = value else {
        return Err(invalid());
    };
    if value.len() > max_bytes
        || value.chars().any(char::is_control)
        || (nonempty && value.is_empty())
    {
        return Err(invalid());
    }
    Ok(value.to_string())
}

/// Parse the closed capture selector without carrying secret response values.
pub(super) fn parse(value: &Value) -> VmResult<OpaqueExchangeResponseIntent> {
    let Value::Map(entries) = value else {
        return Err(invalid());
    };

    let mut seen = 0u8;
    let mut code_field = None;
    let mut redirect_uri = None;
    for (key, value) in entries.iter() {
        let Value::String(key) = key else {
            return Err(invalid());
        };
        let (bit, target) = match key.as_str() {
            "code_field" => (1, &mut code_field),
            "redirect_uri" => (2, &mut redirect_uri),
            _ => return Err(invalid()),
        };
        if seen & bit != 0 {
            return Err(invalid());
        }
        seen |= bit;
        *target = Some(value);
    }

    let code_field = bounded_string(code_field, MAX_SELECTOR_BYTES, true)?;
    let code_field = match code_field.as_str() {
        "code" => ExchangeCodeField::Code,
        "authorization_code" => ExchangeCodeField::AuthorizationCode,
        _ => return Err(invalid()),
    };
    let redirect_uri = bounded_string(redirect_uri, MAX_REDIRECT_URI_BYTES, true)?;

    Ok(OpaqueExchangeResponseIntent {
        code_field,
        redirect_uri,
    })
}

/// Capture is deliberately limited to the proven device flow; native admission
/// remains responsible for complete redirect URL and request-body validation.
pub(super) fn compatible(
    credential: &TransportCredential,
    payload: Option<crate::auth::oauth::NativeRequestBodyIntent>,
) -> bool {
    matches!(credential, TransportCredential::Device(_))
        && matches!(
            payload,
            Some(crate::auth::oauth::NativeRequestBodyIntent {
                secret_fields: crate::auth::oauth::SecretBodyFieldSelection::Device { .. },
                ..
            })
        )
}

pub(super) fn revoke_native_pair(oauth: &crate::auth::oauth::OAuthHost, pair: OpaqueExchangePair) {
    let _ = oauth.close_code_resource(&pair.code_handle);
    let _ = oauth.close_verifier_resource(&pair.verifier_handle);
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

    #[test]
    fn parser_maps_only_the_two_supported_code_selectors() {
        for (selector, expected) in [
            ("code", ExchangeCodeField::Code),
            ("authorization_code", ExchangeCodeField::AuthorizationCode),
        ] {
            let parsed = parse(&record(vec![
                ("code_field", Value::string(selector)),
                (
                    "redirect_uri",
                    Value::string("https://auth.example.test/callback"),
                ),
            ]))
            .expect("supported selector");
            assert_eq!(parsed.code_field, expected);
        }
    }

    #[test]
    fn parser_rejects_open_wrong_carrier_missing_and_unbounded_values() {
        let marker = "CAPTURE_SELECTOR_PRIVATE_MARKER";
        let cases = [
            Value::Int(7),
            record(vec![("code_field", Value::string("code"))]),
            record(vec![
                ("code_field", Value::string("code")),
                (
                    "redirect_uri",
                    Value::string("https://auth.example.test/callback"),
                ),
                ("extra", Value::string(marker)),
            ]),
            Value::map(vec![
                (Value::Int(3), Value::string(marker)),
                (Value::string("code_field"), Value::string("code")),
                (
                    Value::string("redirect_uri"),
                    Value::string("https://auth.example.test/callback"),
                ),
            ]),
            record(vec![
                (
                    "code_field",
                    Value::string("x".repeat(MAX_SELECTOR_BYTES + 1)),
                ),
                (
                    "redirect_uri",
                    Value::string("https://auth.example.test/callback"),
                ),
            ]),
            record(vec![
                ("code_field", Value::string("code\n")),
                (
                    "redirect_uri",
                    Value::string("https://auth.example.test/callback"),
                ),
            ]),
            record(vec![
                ("code_field", Value::string("code")),
                (
                    "redirect_uri",
                    Value::string("x".repeat(MAX_REDIRECT_URI_BYTES + 1)),
                ),
            ]),
            record(vec![
                ("code_field", Value::string("code")),
                ("redirect_uri", Value::string("")),
            ]),
        ];
        for value in cases {
            let failure = parse(&value).expect_err("malformed intent rejected");
            assert!(failure.to_string().ends_with("capture_intent_invalid"));
            assert!(!failure.to_string().contains(marker));
        }
    }

    #[test]
    fn parser_preserves_redirect_uri_bytes_for_native_admission() {
        let value = record(vec![
            ("code_field", Value::string("code")),
            (
                "redirect_uri",
                Value::string("https://user@auth.example.test/callback"),
            ),
        ]);
        let parsed = parse(&value).expect("bounded URI syntax deferred to native admission");
        assert_eq!(
            parsed.redirect_uri,
            "https://user@auth.example.test/callback"
        );
    }
}
