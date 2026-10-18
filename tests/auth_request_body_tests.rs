use rustscript_agent::auth::request_body::{
    RequestBodyEncoding, RequestBodyError, SecretField, SecretRequestBody, encode_injected_body,
};

fn field(name: &str, value: &str) -> SecretField {
    SecretField::new(name, value).expect("valid secret field")
}

fn error(result: Result<SecretRequestBody, RequestBodyError>) -> RequestBodyError {
    result.expect_err("request body should be rejected")
}

#[test]
fn form_injection_percent_encodes_secret_and_preserves_public_pairs() {
    let fields = [field("custom_value", "a&b=# +%雪")];

    let body = encode_injected_body(
        "client_id=public+app&scope=read%3Athings",
        RequestBodyEncoding::Form,
        &fields,
    )
    .expect("valid form body");

    assert_eq!(
        body.as_str_for_transport(),
        "client_id=public%20app&scope=read%3Athings&custom_value=a%26b%3D%23%20%2B%25%E9%9B%AA"
    );
    assert_eq!(
        RequestBodyEncoding::Form.content_type(),
        "application/x-www-form-urlencoded"
    );
}

#[test]
fn form_empty_public_body_encodes_native_field() {
    let body = encode_injected_body(
        "",
        RequestBodyEncoding::Form,
        &[field("device_code", "synthetic-marker")],
    )
    .expect("empty public form is valid");

    assert_eq!(body.as_str_for_transport(), "device_code=synthetic-marker");
}

#[test]
fn form_rejects_malformed_percent_utf8_empty_and_duplicate_keys() {
    let fields = [field("private_value", "synthetic-secret")];
    for (public, expected) in [
        ("key=%", RequestBodyError::InvalidFormEncoding),
        ("key=%G0", RequestBodyError::InvalidFormEncoding),
        ("key=%FF", RequestBodyError::InvalidFormUtf8),
        ("=value", RequestBodyError::EmptyFormKey),
        ("key=one&%6Bey=two", RequestBodyError::DuplicatePublicKey),
    ] {
        assert_eq!(
            error(encode_injected_body(
                public,
                RequestBodyEncoding::Form,
                &fields
            )),
            expected,
            "unexpected rejection for {public:?}"
        );
    }
}

#[test]
fn form_rejects_encoded_case_insensitive_target_and_reserved_keys() {
    let fields = [field("private_value", "synthetic-secret")];
    for public in ["%70rivate%5Fvalue=caller", "%61ccess%5Ftoken=caller"] {
        assert_eq!(
            error(encode_injected_body(
                public,
                RequestBodyEncoding::Form,
                &fields
            )),
            RequestBodyError::ReservedPublicKey
        );
    }
}

#[test]
fn json_injection_adds_escaped_root_string_and_preserves_public_values() {
    let fields = [field("private_value", "quote \" slash \\\n雪")];

    let body = encode_injected_body(
        r#"{"client":{"scopes":["read","write"]},"enabled":true}"#,
        RequestBodyEncoding::JsonObject,
        &fields,
    )
    .expect("valid JSON object");
    let value: serde_json::Value =
        serde_json::from_str(body.as_str_for_transport()).expect("serialized JSON");

    assert_eq!(value["private_value"], "quote \" slash \\\n雪");
    assert_eq!(value["client"]["scopes"][0], "read");
    assert_eq!(value["client"]["scopes"][1], "write");
    assert_eq!(value["enabled"], true);
    assert_eq!(
        RequestBodyEncoding::JsonObject.content_type(),
        "application/json"
    );
}

#[test]
fn json_empty_public_body_encodes_an_object_with_native_fields() {
    let body = encode_injected_body(
        "",
        RequestBodyEncoding::JsonObject,
        &[field("private_value", "synthetic-marker")],
    )
    .expect("empty public JSON means an object");
    let value: serde_json::Value =
        serde_json::from_str(body.as_str_for_transport()).expect("serialized JSON");

    assert_eq!(
        value,
        serde_json::json!({"private_value": "synthetic-marker"})
    );
}

#[test]
fn json_duplicate_keys_are_rejected_at_root_and_nested_levels() {
    for public in [
        r#"{"name":1,"name":2}"#,
        r#"{"nested":{"name":1,"name":2}}"#,
        r#"{"name":1,"\u006eame":2}"#,
    ] {
        assert_eq!(
            error(encode_injected_body(
                public,
                RequestBodyEncoding::JsonObject,
                &[]
            )),
            RequestBodyError::DuplicateJsonKey,
            "unexpected duplicate-key result for {public}"
        );
    }
}

#[test]
fn json_rejects_non_object_malformed_and_trailing_input() {
    for public in ["[]", "null", "\"string\"", "{broken}", "{} trailing"] {
        let expected = if matches!(public, "[]" | "null" | "\"string\"") {
            RequestBodyError::JsonTopLevelNotObject
        } else {
            RequestBodyError::InvalidJson
        };
        assert_eq!(
            error(encode_injected_body(
                public,
                RequestBodyEncoding::JsonObject,
                &[]
            )),
            expected,
            "unexpected JSON result for {public}"
        );
    }
}

#[test]
fn json_rejects_reserved_and_target_keys_recursively_case_insensitively() {
    let fields = [field("private_value", "synthetic-secret")];
    for public in [
        r#"{"nested":[{"PRIVATE_VALUE":"caller"}]}"#,
        r#"{"nested":{"ACCESS_TOKEN":"caller"}}"#,
        r#"{"array":[{"cODe":"caller"}]}"#,
    ] {
        assert_eq!(
            error(encode_injected_body(
                public,
                RequestBodyEncoding::JsonObject,
                &fields
            )),
            RequestBodyError::ReservedPublicKey
        );
    }
}

#[test]
fn json_accepts_eight_structural_levels_and_rejects_nine() {
    let eight_levels = format!("{}0{}", "{\"x\":".repeat(8), "}".repeat(8));
    let nine_levels = format!("{}0{}", "{\"x\":".repeat(9), "}".repeat(9));

    assert!(encode_injected_body(&eight_levels, RequestBodyEncoding::JsonObject, &[]).is_ok());
    assert_eq!(
        error(encode_injected_body(
            &nine_levels,
            RequestBodyEncoding::JsonObject,
            &[]
        )),
        RequestBodyError::JsonDepthExceeded
    );
}

#[test]
fn secret_field_constructor_enforces_label_and_value_rules() {
    assert!(SecretField::new("a", "v").is_ok());
    assert!(SecretField::new("a".repeat(64), "v").is_ok());
    assert_eq!(
        SecretField::new("a".repeat(65), "v").err(),
        Some(RequestBodyError::InvalidFieldName)
    );
    for name in ["", "1name", "has space", "é"] {
        assert_eq!(
            SecretField::new(name, "v").err(),
            Some(RequestBodyError::InvalidFieldName)
        );
    }
    assert_eq!(
        SecretField::new("name", "").err(),
        Some(RequestBodyError::EmptySecret)
    );
    assert_eq!(
        SecretField::new("name", "contains\0nul").err(),
        Some(RequestBodyError::SecretContainsNul)
    );
    assert_eq!(
        SecretField::new("name", "x".repeat(64 * 1024 + 1)).err(),
        Some(RequestBodyError::SecretTooLarge)
    );
}

#[test]
fn encoding_enforces_injected_field_count_and_case_insensitive_uniqueness() {
    let eight = (0..8)
        .map(|index| field(&format!("field_{index}"), "synthetic"))
        .collect::<Vec<_>>();
    assert!(encode_injected_body("", RequestBodyEncoding::Form, &eight).is_ok());

    let nine = (0..9)
        .map(|index| field(&format!("field_{index}"), "synthetic"))
        .collect::<Vec<_>>();
    assert_eq!(
        error(encode_injected_body("", RequestBodyEncoding::Form, &nine)),
        RequestBodyError::TooManyFields
    );

    let duplicate = [field("Private_Value", "one"), field("private_value", "two")];
    assert_eq!(
        error(encode_injected_body(
            "",
            RequestBodyEncoding::JsonObject,
            &duplicate
        )),
        RequestBodyError::DuplicateInjectedField
    );
}

#[test]
fn all_known_secret_names_are_rejected_as_public_form_keys() {
    let reserved = [
        "access_token",
        "refresh_token",
        "id_token",
        "device_code",
        "device_auth_id",
        "device_id",
        "authorization_code",
        "code_verifier",
        "verifier",
        "client_secret",
        "password",
        "api_key",
        "authorization",
        "cookie",
        "code",
    ];
    for name in reserved {
        let public = format!("{}=synthetic-public-value", name.to_ascii_uppercase());
        assert_eq!(
            error(encode_injected_body(
                &public,
                RequestBodyEncoding::Form,
                &[]
            )),
            RequestBodyError::ReservedPublicKey,
            "reserved name {name} was accepted"
        );
    }
}

#[test]
fn public_input_and_encoded_output_limits_are_enforced() {
    let at_limit = format!("x={}", "a".repeat(64 * 1024 - 2));
    assert_eq!(at_limit.len(), 64 * 1024);
    let encoded = encode_injected_body(&at_limit, RequestBodyEncoding::Form, &[])
        .expect("input and output at the limit are accepted");
    assert_eq!(encoded.as_str_for_transport().len(), 64 * 1024);

    let over_limit = format!("x={}", "a".repeat(64 * 1024 - 1));
    assert_eq!(
        error(encode_injected_body(
            &over_limit,
            RequestBodyEncoding::Form,
            &[]
        )),
        RequestBodyError::InputTooLarge
    );

    assert_eq!(
        error(encode_injected_body(
            "",
            RequestBodyEncoding::Form,
            &[field("private_value", &"!".repeat(22_000))]
        )),
        RequestBodyError::OutputTooLarge
    );
    assert_eq!(
        error(encode_injected_body(
            "{}",
            RequestBodyEncoding::JsonObject,
            &[field("private_value", &"\u{1}".repeat(12_000))]
        )),
        RequestBodyError::OutputTooLarge
    );
}

#[test]
fn errors_and_debug_redact_secrets_and_borrowed_inputs_survive_failure() {
    let marker = "synthetic-secret-marker";
    let fields = [field("private_value", marker)];
    let caller_marker = "caller-marker";
    let public = String::from("PRIVATE_VALUE=caller-marker");
    let result = encode_injected_body(&public, RequestBodyEncoding::Form, &fields);
    let error = result.expect_err("target collision is rejected");

    assert!(!format!("{error:?}").contains(marker));
    assert!(!format!("{error:?}").contains(caller_marker));
    assert!(!error.to_string().contains(marker));
    assert!(!error.to_string().contains(caller_marker));
    assert!(!format!("{:?}", fields[0]).contains(marker));
    let body = encode_injected_body("", RequestBodyEncoding::JsonObject, &fields)
        .expect("valid secret JSON body");
    assert!(!format!("{body:?}").contains(marker));
    assert_eq!(public, "PRIVATE_VALUE=caller-marker");
    assert!(!body.as_str_for_transport().is_empty());
}

#[test]
fn parent_public_decimal_value_is_not_rounded_during_json_injection() {
    let fields = [field("private_value", "synthetic-secret")];
    let body = encode_injected_body(
        r#"{"public_decimal":9007199254740993.0}"#,
        RequestBodyEncoding::JsonObject,
        &fields,
    )
    .expect("valid JSON decimal");
    let output = body.as_str_for_transport();
    println!("native encoder output: {output}");
    assert!(
        output.contains("\"public_decimal\":9007199254740993.0"),
        "public decimal must remain exact; output was {output}"
    );
}

#[test]
fn json_preserves_public_number_lexemes_at_precision_and_exponent_boundaries() {
    let secret = "quote \" slash \\\n\u{1}";
    let fields = [field("private_value", secret)];
    let escaped_secret = serde_json::to_string(secret).expect("secret string serialization");
    for number in [
        "9007199254740993.0",
        "-9007199254740993.0",
        "0.123456789012345678901234567890123456789",
        "18446744073709551616",
        "-9223372036854775809",
        "1.2300e+0009",
        "1E+999999",
        "1e-999999",
        "-0.0",
    ] {
        let public = format!(r#"{{"number":{number}}}"#);
        let body = encode_injected_body(&public, RequestBodyEncoding::JsonObject, &fields)
            .expect("valid JSON number lexeme");
        let output = body.as_str_for_transport();
        assert!(
            output.contains(&format!("\"number\":{number}")),
            "number lexeme {number} was not preserved in {output}"
        );
        assert!(
            output.contains(&format!("\"private_value\":{escaped_secret}")),
            "native secret was not escaped and serialized as a JSON string: {output}"
        );
    }
}

#[test]
fn json_preserves_nested_public_number_lexemes_verbatim() {
    let public = r#"{"nested":[{"positive":9007199254740993,"wide":18446744073709551616},-0.0,1.2300e+0009,1e-999999]}"#;
    let body = encode_injected_body(
        public,
        RequestBodyEncoding::JsonObject,
        &[field("private_value", "synthetic-secret")],
    )
    .expect("valid nested JSON numbers");
    let output = body.as_str_for_transport();

    for fragment in [
        r#""positive":9007199254740993"#,
        r#""wide":18446744073709551616"#,
        "-0.0",
        "1.2300e+0009",
        "1e-999999",
    ] {
        assert!(
            output.contains(fragment),
            "nested number fragment {fragment} was not preserved in {output}"
        );
    }
    assert!(output.ends_with(",\"private_value\":\"synthetic-secret\"}"));
}

#[test]
fn json_rejects_invalid_number_grammar_and_trailing_tokens() {
    for number in [
        "01", "-01", "+1", "-", "1.", "1e", "1e+", "1e-", "1e++2", "1e2x", "1 2",
    ] {
        let public = format!(r#"{{"number":{number}}}"#);
        assert_eq!(
            error(encode_injected_body(
                &public,
                RequestBodyEncoding::JsonObject,
                &[]
            )),
            RequestBodyError::InvalidJson,
            "invalid JSON number {number} was accepted"
        );
    }
}
