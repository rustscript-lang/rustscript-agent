//! Native-only selected request-body transport behavior.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};

use rustscript_agent::auth::oauth::{
    CredentialUse, DeviceIdField, ExchangeCodeField, NativeRequestBodyIntent,
    NativeTransportIntents, OAuthHost, OpaqueDeviceSessionHandle, OpaqueExchangePair,
    OpaqueExchangeResponseIntent, ProviderRequest, ScriptedBrowser, ScriptedCallback,
    ScriptedCancel, ScriptedClock, ScriptedHttpsTransport, SecretBodyFieldSelection,
    TrustedEndpoint, TrustedTransportPolicy,
};
use rustscript_agent::auth::request_body::RequestBodyEncoding;

const DEVICE_ID: &str = "NATIVE_SELECTED_DEVICE +/雪";
const CODE: &str = "NATIVE_SELECTED_CODE +/雪&x=";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
const REDIRECT_URI: &str = "https://redirect.example.test/callback?state=public";

fn policy() -> TrustedTransportPolicy {
    TrustedTransportPolicy {
        generation: 23,
        run_id: "native-selected-payload-test".to_string(),
        deadline: Instant::now() + Duration::from_secs(120),
        endpoints: vec![TrustedEndpoint {
            authority: "auth.example.test".to_string(),
            path_prefix: "/oauth".to_string(),
        }],
        allowed_header_names: BTreeSet::from(["content-type".to_string()]),
    }
}

fn request(path: &str, body: &str) -> ProviderRequest {
    ProviderRequest {
        method: "POST".to_string(),
        path: path.to_string(),
        public_headers: BTreeMap::new(),
        public_body: body.to_string(),
        credential_id: "primary".to_string(),
    }
}

fn request_with_headers(
    path: &str,
    body: &str,
    headers: BTreeMap<String, String>,
) -> ProviderRequest {
    let mut request = request(path, body);
    request.public_headers = headers;
    request
}

fn selected_intents(
    encoding: RequestBodyEncoding,
    secret_fields: SecretBodyFieldSelection,
) -> NativeTransportIntents {
    NativeTransportIntents {
        request_body: Some(NativeRequestBodyIntent {
            encoding,
            secret_fields,
        }),
        exchange_response: None,
    }
}

fn host() -> (OAuthHost, Arc<ScriptedHttpsTransport>) {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let host = OAuthHost::new(
        Arc::clone(&transport) as Arc<_>,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    );
    (host, transport)
}

fn start_device(
    host: &OAuthHost,
    transport: &ScriptedHttpsTransport,
    policy: &TrustedTransportPolicy,
) -> OpaqueDeviceSessionHandle {
    start_device_with_id(host, transport, policy, DEVICE_ID)
}

fn start_device_with_id(
    host: &OAuthHost,
    transport: &ScriptedHttpsTransport,
    policy: &TrustedTransportPolicy,
    device_id: &str,
) -> OpaqueDeviceSessionHandle {
    transport.push_json(
        200,
        serde_json::json!({
            "device_code": device_id,
            "user_code": "SYNTHETIC-USER-CODE",
            "verification_uri": "https://auth.example.test/device",
            "expires_in": 900,
            "interval": 5
        }),
    );
    host.transport(
        policy,
        request("/oauth/device", "client_id=synthetic-client"),
        CredentialUse::None,
    )
    .expect("native device start")
    .device_handle
    .expect("native device handle")
}

fn capture_pair(
    host: &OAuthHost,
    transport: &ScriptedHttpsTransport,
    policy: &TrustedTransportPolicy,
    code_field: ExchangeCodeField,
) -> OpaqueExchangePair {
    let device = start_device(host, transport, policy);
    let response = match code_field {
        ExchangeCodeField::Code => {
            serde_json::json!({"code": CODE, "code_verifier": VERIFIER})
        }
        ExchangeCodeField::AuthorizationCode => {
            serde_json::json!({"authorization_code": CODE, "code_verifier": VERIFIER})
        }
    };
    transport.push_json(200, response);
    host.transport_exchange_pair(
        policy,
        request("/oauth/device/token", "grant_type=device_code"),
        device,
        OpaqueExchangeResponseIntent {
            code_field,
            redirect_uri: REDIRECT_URI.to_string(),
        },
    )
    .expect("native pair capture")
    .pair
    .expect("native exchange pair")
}

#[test]
fn selected_json_device_poll_sends_json_and_canonical_content_type() {
    let (host, transport) = host();
    let policy = policy();
    let device = start_device(&host, &transport, &policy);
    transport.push_json(200, serde_json::json!({"status": "waiting"}));

    host.transport_with_intents(
        &policy,
        request(
            "/oauth/device/token",
            r#"{"client_id":"synthetic-client","note":"literal &code=plain"}"#,
        ),
        CredentialUse::Device(device),
        NativeTransportIntents {
            request_body: Some(NativeRequestBodyIntent {
                encoding: RequestBodyEncoding::JsonObject,
                secret_fields: rustscript_agent::auth::oauth::SecretBodyFieldSelection::Device {
                    field: DeviceIdField::DeviceCode,
                },
            }),
            exchange_response: None,
        },
    )
    .expect("selected JSON poll");

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 2);
    let encoded: serde_json::Value =
        serde_json::from_str(&sent[1].body).expect("actual wire body is JSON");
    assert_eq!(encoded["client_id"], "synthetic-client");
    assert_eq!(encoded["note"], "literal &code=plain");
    assert_eq!(encoded["device_code"], DEVICE_ID);
    assert_eq!(
        sent[1].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
}

#[test]
fn selected_none_json_device_start_sends_canonical_json_and_mints_session() {
    let (host, transport) = host();
    let policy = policy();
    transport.push_json(
        200,
        serde_json::json!({
            "device_code": DEVICE_ID,
            "user_code": "SYNTHETIC-USER-CODE",
            "verification_uri": "https://auth.example.test/device",
            "expires_in": 900,
            "interval": 5
        }),
    );

    let result = host
        .transport_with_intents(
            &policy,
            request(
                "/oauth/device",
                r#"{"client_id":"synthetic-client","scope":"read"}"#,
            ),
            CredentialUse::None,
            selected_intents(
                RequestBodyEncoding::JsonObject,
                SecretBodyFieldSelection::None,
            ),
        )
        .expect("selected JSON device start");
    assert!(result.response.device_handle.is_some());
    assert!(
        !result
            .response
            .body_without_secret_fields
            .to_string()
            .contains(DEVICE_ID)
    );
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    let body: serde_json::Value = serde_json::from_str(&sent[0].body).expect("JSON start body");
    assert_eq!(body["client_id"], "synthetic-client");
    assert_eq!(body["scope"], "read");
    assert_eq!(
        sent[0].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
}

#[test]
fn selected_none_json_preserves_public_number_tokens_and_unicode() {
    let (host, transport) = host();
    let policy = policy();
    transport.push_json(200, serde_json::json!({"accepted": true}));
    let public_body = r#"{"wide":18446744073709551616,"decimal":1.2300,"exponent":2E+09,"negative_zero":-0,"text":"snow 雪 and \"quote\""}"#;

    host.transport_with_intents(
        &policy,
        request("/oauth/public", public_body),
        CredentialUse::None,
        selected_intents(
            RequestBodyEncoding::JsonObject,
            SecretBodyFieldSelection::None,
        ),
    )
    .expect("public selected JSON request");

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].body.contains("\"wide\":18446744073709551616"));
    assert!(sent[0].body.contains("\"decimal\":1.2300"));
    assert!(sent[0].body.contains("\"exponent\":2E+09"));
    assert!(sent[0].body.contains("\"negative_zero\":-0"));
    assert!(sent[0].body.contains("snow 雪"));
    assert_eq!(
        sent[0].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
}

#[test]
fn selected_device_aliases_encode_real_native_values_as_json_and_form() {
    let (host, transport) = host();
    let policy = policy();
    let device = start_device(&host, &transport, &policy);
    let _ = transport.take_sent();

    for (encoding, field, key) in [
        (
            RequestBodyEncoding::Form,
            DeviceIdField::DeviceAuthId,
            "device_auth_id",
        ),
        (
            RequestBodyEncoding::JsonObject,
            DeviceIdField::DeviceId,
            "device_id",
        ),
    ] {
        transport.push_json(200, serde_json::json!({"status": "waiting"}));
        let public_body = match encoding {
            RequestBodyEncoding::Form => "client_id=synthetic-client&note=literal+%26code%3Dplain",
            RequestBodyEncoding::JsonObject => {
                r#"{"client_id":"synthetic-client","note":"literal &code=plain"}"#
            }
        };
        host.transport_with_intents(
            &policy,
            request("/oauth/device/token", public_body),
            CredentialUse::Device(device.clone()),
            selected_intents(encoding, SecretBodyFieldSelection::Device { field }),
        )
        .expect("selected device alias poll");

        let sent = transport.take_sent();
        assert_eq!(sent.len(), 1);
        let content_type = match encoding {
            RequestBodyEncoding::Form => "application/x-www-form-urlencoded",
            RequestBodyEncoding::JsonObject => "application/json",
        };
        assert_eq!(
            sent[0].headers.get("content-type").map(String::as_str),
            Some(content_type)
        );
        match encoding {
            RequestBodyEncoding::Form => {
                assert!(sent[0].body.contains("note=literal%20%26code%3Dplain"));
                assert!(
                    sent[0]
                        .body
                        .contains("device_auth_id=NATIVE_SELECTED_DEVICE%20%2B%2F%E9%9B%AA")
                );
            }
            RequestBodyEncoding::JsonObject => {
                let body: serde_json::Value =
                    serde_json::from_str(&sent[0].body).expect("JSON wire body");
                assert_eq!(body["note"], "literal &code=plain");
                assert_eq!(body[key], DEVICE_ID);
            }
        }
        assert!(!sent[0].body.contains("device_code="));
    }
}

#[test]
fn selected_code_exchange_supports_both_native_aliases_and_encodings() {
    for code_field in [
        ExchangeCodeField::Code,
        ExchangeCodeField::AuthorizationCode,
    ] {
        for encoding in [RequestBodyEncoding::Form, RequestBodyEncoding::JsonObject] {
            let (host, transport) = host();
            let policy = policy();
            let pair = capture_pair(&host, &transport, &policy, code_field);
            let _ = transport.take_sent();
            transport.push_json(200, serde_json::json!({"public": "accepted"}));
            let public_body = match encoding {
                RequestBodyEncoding::Form => {
                    "grant_type=authorization_code&note=literal+%26code%3Dpublic"
                }
                RequestBodyEncoding::JsonObject => {
                    r#"{"grant_type":"authorization_code","note":"literal &code=public"}"#
                }
            };
            let result = host
                .transport_with_intents(
                    &policy,
                    request("/oauth/token", public_body),
                    CredentialUse::AuthorizationCode {
                        code: pair.code_handle.clone(),
                        verifier: pair.verifier_handle.clone(),
                    },
                    selected_intents(
                        encoding,
                        SecretBodyFieldSelection::AuthorizationCode { code_field },
                    ),
                )
                .expect("selected authorization-code exchange");
            assert_eq!(result.response.status, 200);
            assert!(!format!("{result:?}").contains(CODE));
            assert!(!format!("{result:?}").contains(VERIFIER));

            let sent = transport.take_sent();
            assert_eq!(sent.len(), 1);
            let code_key = match code_field {
                ExchangeCodeField::Code => "code",
                ExchangeCodeField::AuthorizationCode => "authorization_code",
            };
            let content_type = match encoding {
                RequestBodyEncoding::Form => "application/x-www-form-urlencoded",
                RequestBodyEncoding::JsonObject => "application/json",
            };
            assert_eq!(
                sent[0].headers.get("content-type").map(String::as_str),
                Some(content_type)
            );
            match encoding {
                RequestBodyEncoding::Form => {
                    assert!(sent[0].body.contains(&format!(
                        "{code_key}=NATIVE_SELECTED_CODE%20%2B%2F%E9%9B%AA%26x%3D"
                    )));
                    assert!(sent[0].body.contains(&format!("code_verifier={VERIFIER}")));
                    assert!(sent[0].body.contains(
                        "redirect_uri=https%3A%2F%2Fredirect.example.test%2Fcallback%3Fstate%3Dpublic"
                    ));
                    assert!(sent[0].body.contains("note=literal%20%26code%3Dpublic"));
                }
                RequestBodyEncoding::JsonObject => {
                    let body: serde_json::Value =
                        serde_json::from_str(&sent[0].body).expect("JSON wire body");
                    assert_eq!(body[code_key], CODE);
                    assert_eq!(body["code_verifier"], VERIFIER);
                    assert_eq!(body["redirect_uri"], REDIRECT_URI);
                    assert_eq!(body["note"], "literal &code=public");
                }
            }
            let replay = host
                .transport_with_intents(
                    &policy,
                    request("/oauth/token", public_body),
                    CredentialUse::AuthorizationCode {
                        code: pair.code_handle.clone(),
                        verifier: pair.verifier_handle.clone(),
                    },
                    selected_intents(
                        encoding,
                        SecretBodyFieldSelection::AuthorizationCode { code_field },
                    ),
                )
                .expect_err("one-use code pair replay rejected");
            assert_eq!(replay.code(), "handle_replayed");
            assert!(transport.take_sent().is_empty());
        }
    }
}

#[test]
fn rejected_device_bodies_are_retryable_and_errors_are_value_free() {
    let (host, transport) = host();
    let policy = policy();
    let device = start_device(&host, &transport, &policy);
    let _ = transport.take_sent();
    let mut nested = "0".to_string();
    for _ in 0..10 {
        nested = format!("{{\"next\":{nested}}}");
    }
    let cases = [
        (
            "{".to_string(),
            RequestBodyEncoding::JsonObject,
            "invalid_intent",
        ),
        (
            r#"{"duplicate":1,"duplicate":2}"#.to_string(),
            RequestBodyEncoding::JsonObject,
            "invalid_intent",
        ),
        (
            r#"{"device_code":"caller-value"}"#.to_string(),
            RequestBodyEncoding::JsonObject,
            "invalid_intent",
        ),
        (
            r#"{"meta":{"DEVICE_AUTH_ID":"caller-value"}}"#.to_string(),
            RequestBodyEncoding::JsonObject,
            "invalid_intent",
        ),
        (
            r#"{"refresh_token":"caller-value"}"#.to_string(),
            RequestBodyEncoding::JsonObject,
            "invalid_intent",
        ),
        (
            "[]".to_string(),
            RequestBodyEncoding::JsonObject,
            "invalid_intent",
        ),
        (
            format!("{{\"outer\":{nested}}}"),
            RequestBodyEncoding::JsonObject,
            "invalid_intent",
        ),
        (
            "bad=%Q0".to_string(),
            RequestBodyEncoding::Form,
            "invalid_intent",
        ),
        (
            "duplicate=one&duplicate=two".to_string(),
            RequestBodyEncoding::Form,
            "invalid_intent",
        ),
        (
            "client_id=one&%64evice_code=caller-value".to_string(),
            RequestBodyEncoding::Form,
            "invalid_intent",
        ),
        (
            "x".repeat(65_537),
            RequestBodyEncoding::JsonObject,
            "request_too_large",
        ),
    ];

    for (body, encoding, expected_code) in cases {
        let error = host
            .transport_with_intents(
                &policy,
                request("/oauth/device/token", &body),
                CredentialUse::Device(device.clone()),
                selected_intents(
                    encoding,
                    SecretBodyFieldSelection::Device {
                        field: DeviceIdField::DeviceCode,
                    },
                ),
            )
            .expect_err("invalid local body must fail before send");
        assert_eq!(error.code(), expected_code);
        let public_error = format!("{error:?} {error}");
        assert!(!public_error.contains(DEVICE_ID));
        assert!(transport.take_sent().is_empty());
    }

    transport.push_json(200, serde_json::json!({"status": "waiting"}));
    host.transport_with_intents(
        &policy,
        request("/oauth/device/token", r#"{"client_id":"corrected"}"#),
        CredentialUse::Device(device),
        selected_intents(
            RequestBodyEncoding::JsonObject,
            SecretBodyFieldSelection::Device {
                field: DeviceIdField::DeviceCode,
            },
        ),
    )
    .expect("same device session remains retryable");
    assert_eq!(transport.take_sent().len(), 1);
}

#[test]
fn encoded_output_limit_rejects_without_consuming_device_session() {
    let (host, transport) = host();
    let policy = policy();
    let large_device_id = "%".repeat(40_000);
    let device = start_device_with_id(&host, &transport, &policy, &large_device_id);
    let _ = transport.take_sent();
    let public_body = format!("{{\"public\":\"{}\"}}", "x".repeat(30_000));
    let error = host
        .transport_with_intents(
            &policy,
            request("/oauth/device/token", &public_body),
            CredentialUse::Device(device.clone()),
            selected_intents(
                RequestBodyEncoding::JsonObject,
                SecretBodyFieldSelection::Device {
                    field: DeviceIdField::DeviceCode,
                },
            ),
        )
        .expect_err("encoded payload exceeds native cap");
    assert_eq!(error.code(), "request_too_large");
    assert!(transport.take_sent().is_empty());

    transport.push_json(200, serde_json::json!({"status": "waiting"}));
    host.transport_with_intents(
        &policy,
        request("/oauth/device/token", r#"{"corrected":true}"#),
        CredentialUse::Device(device),
        selected_intents(
            RequestBodyEncoding::JsonObject,
            SecretBodyFieldSelection::Device {
                field: DeviceIdField::DeviceCode,
            },
        ),
    )
    .expect("same device session survives output limit");
    assert_eq!(transport.take_sent().len(), 1);
}

#[test]
fn encoded_code_exchange_output_limit_preserves_pair_for_retry() {
    let (host, transport) = host();
    let policy = policy();
    let pair = capture_pair(&host, &transport, &policy, ExchangeCodeField::Code);
    let _ = transport.take_sent();
    let oversized_encoded_body = format!("public={}", "x".repeat(65_400));
    assert!(oversized_encoded_body.len() < 65_536);
    let error = host
        .transport_with_intents(
            &policy,
            request("/oauth/token", &oversized_encoded_body),
            CredentialUse::AuthorizationCode {
                code: pair.code_handle.clone(),
                verifier: pair.verifier_handle.clone(),
            },
            selected_intents(
                RequestBodyEncoding::Form,
                SecretBodyFieldSelection::AuthorizationCode {
                    code_field: ExchangeCodeField::Code,
                },
            ),
        )
        .expect_err("injected controls push encoded output over limit");
    assert_eq!(error.code(), "request_too_large");
    assert!(transport.take_sent().is_empty());

    transport.push_json(200, serde_json::json!({"accepted": true}));
    host.transport_with_intents(
        &policy,
        request("/oauth/token", "grant_type=authorization_code"),
        CredentialUse::AuthorizationCode {
            code: pair.code_handle,
            verifier: pair.verifier_handle,
        },
        selected_intents(
            RequestBodyEncoding::Form,
            SecretBodyFieldSelection::AuthorizationCode {
                code_field: ExchangeCodeField::Code,
            },
        ),
    )
    .expect("same pair remains available after output-limit rejection");
    assert_eq!(transport.take_sent().len(), 1);
}

#[test]
fn selected_content_type_is_closed_canonical_and_header_denials_are_retryable() {
    let (host, transport) = host();
    let policy = policy();
    let device = start_device(&host, &transport, &policy);
    let _ = transport.take_sent();
    for headers in [
        BTreeMap::from([(
            "content-type".to_string(),
            "application/json; charset=utf-8".to_string(),
        )]),
        BTreeMap::from([(
            "authorization".to_string(),
            "Bearer NATIVE_HEADER_MARKER".to_string(),
        )]),
    ] {
        let error = host
            .transport_with_intents(
                &policy,
                request_with_headers("/oauth/device/token", r#"{"ok":true}"#, headers),
                CredentialUse::Device(device.clone()),
                selected_intents(
                    RequestBodyEncoding::JsonObject,
                    SecretBodyFieldSelection::Device {
                        field: DeviceIdField::DeviceCode,
                    },
                ),
            )
            .expect_err("noncanonical or forbidden header rejected");
        assert!(matches!(error.code(), "invalid_intent" | "header_denied"));
        assert!(!format!("{error:?} {error}").contains("NATIVE_HEADER_MARKER"));
        assert!(transport.take_sent().is_empty());
    }

    transport.push_json(200, serde_json::json!({"status": "waiting"}));
    host.transport_with_intents(
        &policy,
        request_with_headers(
            "/oauth/device/token",
            r#"{"ok":true}"#,
            BTreeMap::from([("Content-Type".to_string(), " APPLICATION/JSON ".to_string())]),
        ),
        CredentialUse::Device(device),
        selected_intents(
            RequestBodyEncoding::JsonObject,
            SecretBodyFieldSelection::Device {
                field: DeviceIdField::DeviceCode,
            },
        ),
    )
    .expect("trimmed case-insensitive canonical media type accepted");
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
}

#[test]
fn selected_kind_mismatch_leaves_code_pair_available_for_corrected_exchange() {
    let (host, transport) = host();
    let policy = policy();
    let pair = capture_pair(&host, &transport, &policy, ExchangeCodeField::Code);
    let _ = transport.take_sent();
    let mismatch = host
        .transport_with_intents(
            &policy,
            request("/oauth/token", r#"{"grant_type":"authorization_code"}"#),
            CredentialUse::AuthorizationCode {
                code: pair.code_handle.clone(),
                verifier: pair.verifier_handle.clone(),
            },
            selected_intents(
                RequestBodyEncoding::JsonObject,
                SecretBodyFieldSelection::Device {
                    field: DeviceIdField::DeviceCode,
                },
            ),
        )
        .expect_err("device field cannot be selected for a code pair");
    assert_eq!(mismatch.code(), "invalid_intent");
    assert!(transport.take_sent().is_empty());

    for (body, headers) in [
        ("{".to_string(), BTreeMap::new()),
        (r#"{"code":"caller-value"}"#.to_string(), BTreeMap::new()),
        (
            r#"{"grant_type":"authorization_code"}"#.to_string(),
            BTreeMap::from([("content-type".to_string(), "text/plain".to_string())]),
        ),
    ] {
        let error = host
            .transport_with_intents(
                &policy,
                request_with_headers("/oauth/token", &body, headers),
                CredentialUse::AuthorizationCode {
                    code: pair.code_handle.clone(),
                    verifier: pair.verifier_handle.clone(),
                },
                selected_intents(
                    RequestBodyEncoding::JsonObject,
                    SecretBodyFieldSelection::AuthorizationCode {
                        code_field: ExchangeCodeField::Code,
                    },
                ),
            )
            .expect_err("selected code body rejects locally before consumption");
        assert_eq!(error.code(), "invalid_intent");
        assert!(!format!("{error:?} {error}").contains(CODE));
        assert!(transport.take_sent().is_empty());
    }

    transport.push_json(200, serde_json::json!({"ok": true}));
    host.transport_with_intents(
        &policy,
        request("/oauth/token", r#"{"grant_type":"authorization_code"}"#),
        CredentialUse::AuthorizationCode {
            code: pair.code_handle,
            verifier: pair.verifier_handle,
        },
        selected_intents(
            RequestBodyEncoding::JsonObject,
            SecretBodyFieldSelection::AuthorizationCode {
                code_field: ExchangeCodeField::Code,
            },
        ),
    )
    .expect("corrected kind uses same code pair");
    assert_eq!(transport.take_sent().len(), 1);
}

#[test]
fn selected_device_body_can_capture_a_pair_in_the_same_transport_call() {
    let (host, transport) = host();
    let policy = policy();
    let device = start_device(&host, &transport, &policy);
    let _ = transport.take_sent();
    transport.push_json(
        200,
        serde_json::json!({"authorization_code": CODE, "code_verifier": VERIFIER}),
    );
    let intents = NativeTransportIntents {
        request_body: Some(NativeRequestBodyIntent {
            encoding: RequestBodyEncoding::JsonObject,
            secret_fields: SecretBodyFieldSelection::Device {
                field: DeviceIdField::DeviceId,
            },
        }),
        exchange_response: Some(OpaqueExchangeResponseIntent {
            code_field: ExchangeCodeField::AuthorizationCode,
            redirect_uri: REDIRECT_URI.to_string(),
        }),
    };
    let intent_debug = format!("{intents:?}");
    assert!(!intent_debug.contains(CODE));
    assert!(!intent_debug.contains(VERIFIER));
    let captured = host
        .transport_with_intents(
            &policy,
            request("/oauth/device/token", r#"{"grant_type":"device_code"}"#),
            CredentialUse::Device(device),
            intents,
        )
        .expect("selected device payload and capture compose");
    let captured_debug = format!("{captured:?}");
    let pair = captured.pair.expect("same-call captured pair");
    assert!(!captured_debug.contains(CODE));
    assert!(!captured_debug.contains(VERIFIER));
    let pair_debug = format!("{:?} {:?}", pair.code_handle, pair.verifier_handle);
    assert!(!pair_debug.contains(CODE));
    assert!(!pair_debug.contains(VERIFIER));
    assert!(
        !captured
            .response
            .body_without_secret_fields
            .to_string()
            .contains(CODE)
    );
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    let body: serde_json::Value = serde_json::from_str(&sent[0].body).expect("JSON device poll");
    assert_eq!(body["device_id"], DEVICE_ID);
    assert_eq!(
        sent[0].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
}
