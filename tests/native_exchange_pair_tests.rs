//! Native opaque capture of a device-poll authorization-code/verifier pair.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rustscript_agent::auth::oauth::{
    BoundedHttpsTransport, CredentialUse, ExchangeCodeField, MAX_LIVE_OAUTH_FLOWS, OAuthClock,
    OAuthError, OAuthHost, OAuthIoContext, OpaqueDeviceSessionHandle, OpaqueExchangeResponseIntent,
    PreparedHttpsRequest, ProviderRequest, RawHttpsResponse, ScriptedBrowser, ScriptedCallback,
    ScriptedCancel, ScriptedClock, ScriptedHttpsTransport, TrustedEndpoint, TrustedTransportPolicy,
};

const DEVICE_SECRET: &str = "DEVICE_EXCHANGE_PAIR_DEVICE_SECRET";
const AUTHORIZATION_CODE_SECRET: &str = "DEVICE_EXCHANGE_PAIR_AUTHORIZATION_CODE_SECRET";
const CODE_VERIFIER_SECRET: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
const ACCESS_SECRET: &str = "DEVICE_EXCHANGE_PAIR_ACCESS_SECRET";
const REFRESH_SECRET: &str = "DEVICE_EXCHANGE_PAIR_REFRESH_SECRET";

fn policy() -> TrustedTransportPolicy {
    TrustedTransportPolicy {
        generation: 7,
        transport_identity: None,
        run_id: "native-exchange-pair-test".to_string(),
        deadline: Instant::now() + Duration::from_secs(60),
        endpoints: vec![TrustedEndpoint {
            authority: "auth.example.test".to_string(),
            path_prefix: "/oauth".to_string(),
        }],
        allowed_header_names: BTreeSet::from(["content-type".to_string()]),
        transport_identity: None,
    }
}

fn request(path: &str, body: &str) -> ProviderRequest {
    ProviderRequest {
        method: "POST".to_string(),
        path: path.to_string(),
        public_headers: BTreeMap::from([(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )]),
        public_body: body.to_string(),
        credential_id: "primary".to_string(),
    }
}

fn default_host() -> (OAuthHost, Arc<ScriptedHttpsTransport>) {
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

fn start_device_session(
    host: &OAuthHost,
    transport: &ScriptedHttpsTransport,
    policy: &TrustedTransportPolicy,
) -> OpaqueDeviceSessionHandle {
    transport.push_json(
        200,
        serde_json::json!({
            "device_code": DEVICE_SECRET,
            "user_code": "SYNTHETIC-CODE",
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
    .expect("device session start")
    .device_handle
    .expect("native device handle")
}

fn capture_intent() -> OpaqueExchangeResponseIntent {
    OpaqueExchangeResponseIntent {
        code_field: ExchangeCodeField::AuthorizationCode,
        redirect_uri: "https://redirect.example.test/callback".to_string(),
    }
}

#[test]
fn device_poll_promotes_secret_pair_to_opaque_exchange_handles() {
    let (host, transport) = default_host();
    let policy = policy();
    transport.push_json(
        200,
        serde_json::json!({
            "device_code": DEVICE_SECRET,
            "user_code": "SYNTHETIC-CODE",
            "verification_uri": "https://auth.example.test/device",
            "expires_in": 900,
            "interval": 5
        }),
    );
    let device = host
        .transport(
            &policy,
            request("/oauth/device", "client_id=synthetic-client"),
            CredentialUse::None,
        )
        .expect("device session start")
        .device_handle
        .expect("native device handle");

    transport.push_json(
        200,
        serde_json::json!({
            "authorization_code": AUTHORIZATION_CODE_SECRET,
            "code_verifier": CODE_VERIFIER_SECRET,
            "status": "authorized"
        }),
    );
    let captured = host
        .transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            device.clone(),
            capture_intent(),
        )
        .expect("capture response pair");
    let pair = captured.pair.as_ref().expect("opaque exchange pair");
    let debug = format!(
        "{captured:?} {:?} {:?}",
        pair.code_handle, pair.verifier_handle
    );
    for secret in [
        DEVICE_SECRET,
        AUTHORIZATION_CODE_SECRET,
        CODE_VERIFIER_SECRET,
    ] {
        assert!(!debug.contains(secret), "secret leaked in Debug: {debug}");
        assert!(
            !captured
                .response
                .body_without_secret_fields
                .to_string()
                .contains(secret),
            "secret leaked in public response"
        );
    }
    assert!(
        captured
            .response
            .body_without_secret_fields
            .get("authorization_code")
            .is_none()
    );
    assert!(
        captured
            .response
            .body_without_secret_fields
            .get("code_verifier")
            .is_none()
    );
    assert!(captured.response.access_slot.is_none());
    assert!(captured.response.refresh_slot.is_none());
    assert!(captured.response.device_handle.is_none());

    // A stale alias may revoke only its old device flow, never the promoted pair.
    host.terminal(&device).expect("old device alias terminal");
    assert_eq!(
        host.transport(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            CredentialUse::Device(device.clone()),
        )
        .expect_err("old device alias is revoked")
        .code(),
        "handle_revoked"
    );
    transport.push_json(
        200,
        serde_json::json!({
            "token_type": "Bearer",
            "expires_in": 3600,
            "access_token": ACCESS_SECRET,
            "refresh_token": REFRESH_SECRET
        }),
    );
    let exchanged = host
        .transport(
            &policy,
            request("/oauth/token", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode {
                code: pair.code_handle.clone(),
                verifier: pair.verifier_handle.clone(),
            },
        )
        .expect("existing native code exchange");
    assert_eq!(exchanged.status, 200);
    assert!(exchanged.access_slot.is_some());
    assert!(exchanged.refresh_slot.is_some());

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 3);
    assert!(
        sent[1]
            .url
            .starts_with("https://auth.example.test/oauth/device/token")
    );
    assert!(
        sent[2]
            .url
            .starts_with("https://auth.example.test/oauth/token")
    );
    assert!(
        sent[1]
            .body
            .contains(&format!("device_code={DEVICE_SECRET}"))
    );
    assert!(
        sent[2]
            .body
            .contains(&format!("code={AUTHORIZATION_CODE_SECRET}"))
    );
    assert!(
        sent[2]
            .body
            .contains(&format!("code_verifier={CODE_VERIFIER_SECRET}"))
    );
    assert!(
        sent[2]
            .body
            .contains("redirect_uri=https%3A%2F%2Fredirect.example.test%2Fcallback")
    );
    for secret in [AUTHORIZATION_CODE_SECRET, CODE_VERIFIER_SECRET] {
        assert!(sent[2].body.contains(secret));
    }
    let replay = host
        .transport(
            &policy,
            request("/oauth/token", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode {
                code: pair.code_handle.clone(),
                verifier: pair.verifier_handle.clone(),
            },
        )
        .expect_err("pair exchange is one-shot");
    assert_eq!(replay.code(), "handle_replayed");
}

#[test]
fn legacy_transport_redacts_authorization_code_alias_without_opt_in() {
    let (host, transport) = default_host();
    let policy = policy();
    transport.push_json(
        200,
        serde_json::json!({
            "authorization_code": AUTHORIZATION_CODE_SECRET,
            "code_verifier": CODE_VERIFIER_SECRET,
            "ok": true
        }),
    );
    let response = host
        .transport(
            &policy,
            request("/oauth/token", "grant_type=refresh_token"),
            CredentialUse::None,
        )
        .expect("legacy transport response");
    assert!(
        response
            .body_without_secret_fields
            .get("authorization_code")
            .is_none()
    );
    assert!(
        response
            .body_without_secret_fields
            .get("code_verifier")
            .is_none()
    );
    let debug = format!("{response:?}");
    assert!(!debug.contains(AUTHORIZATION_CODE_SECRET));
    assert!(!debug.contains(CODE_VERIFIER_SECRET));
}

#[test]
fn pending_and_pairless_success_keep_device_session_retryable() {
    let (host, transport) = default_host();
    let policy = policy();
    transport.push_json(
        200,
        serde_json::json!({
            "device_code": DEVICE_SECRET,
            "user_code": "SYNTHETIC-CODE",
            "verification_uri": "https://auth.example.test/device",
            "expires_in": 900,
            "interval": 5
        }),
    );
    let device = host
        .transport(
            &policy,
            request("/oauth/device", "client_id=synthetic-client"),
            CredentialUse::None,
        )
        .expect("device session start")
        .device_handle
        .expect("native device handle");

    transport.push_json(400, serde_json::json!({"error": "authorization_pending"}));
    let pending = host
        .transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            device.clone(),
            capture_intent(),
        )
        .expect("pending response");
    assert_eq!(pending.response.status, 400);
    assert_eq!(
        pending.response.body_without_secret_fields["error"],
        "authorization_pending"
    );
    assert!(pending.pair.is_none());

    transport.push_json(
        200,
        serde_json::json!({
            "status": "waiting",
            "nested": {
                "authorization_code": AUTHORIZATION_CODE_SECRET,
                "code_verifier": CODE_VERIFIER_SECRET
            }
        }),
    );
    let pairless = host
        .transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            device.clone(),
            capture_intent(),
        )
        .expect("pairless success response");
    assert_eq!(pairless.response.status, 200);
    assert!(pairless.pair.is_none());
    assert_eq!(
        pairless.response.body_without_secret_fields["nested"],
        serde_json::json!({})
    );
    assert!(
        !pairless
            .response
            .body_without_secret_fields
            .to_string()
            .contains(AUTHORIZATION_CODE_SECRET)
    );
    assert!(
        !pairless
            .response
            .body_without_secret_fields
            .to_string()
            .contains(CODE_VERIFIER_SECRET)
    );

    transport.push_json(
        200,
        serde_json::json!({
            "authorization_code": AUTHORIZATION_CODE_SECRET,
            "code_verifier": CODE_VERIFIER_SECRET
        }),
    );
    let authorized = host
        .transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            device,
            capture_intent(),
        )
        .expect("retry returns pair");
    assert!(authorized.pair.is_some());
}

#[test]
fn malformed_or_ambiguous_pair_controls_fail_closed_and_revoke_only_the_device() {
    let valid_verifier = CODE_VERIFIER_SECRET;
    let cases = vec![
        ("code only", r#"{"authorization_code":"CODE"}"#.to_string()),
        (
            "verifier only",
            format!(r#"{{"code_verifier":"{valid_verifier}"}}"#),
        ),
        (
            "wrong code type",
            serde_json::json!({"authorization_code": 7, "code_verifier": valid_verifier})
                .to_string(),
        ),
        (
            "wrong verifier type",
            serde_json::json!({"authorization_code": "CODE", "code_verifier": false})
                .to_string(),
        ),
        (
            "empty code",
            serde_json::json!({"authorization_code": "", "code_verifier": valid_verifier})
                .to_string(),
        ),
        (
            "oversized code",
            serde_json::json!({
                "authorization_code": "C".repeat(4097),
                "code_verifier": valid_verifier
            })
            .to_string(),
        ),
        (
            "invalid verifier",
            serde_json::json!({"authorization_code": "CODE", "code_verifier": format!("{}+", "A".repeat(63))})
                .to_string(),
        ),
        (
            "two code candidates",
            serde_json::json!({
                "code": "CODE_A",
                "authorization_code": "CODE_B",
                "code_verifier": valid_verifier
            })
            .to_string(),
        ),
        (
            "case aliased code candidate",
            format!(
                r#"{{"authorization_code":"CODE_A","Authorization_Code":"CODE_B","code_verifier":"{valid_verifier}"}}"#
            ),
        ),
        (
            "case aliased verifier",
            format!(
                r#"{{"authorization_code":"CODE","code_verifier":"{valid_verifier}","Code_Verifier":"{valid_verifier}"}}"#
            ),
        ),
        (
            "duplicate selected key",
            format!(
                r#"{{"authorization_code":"CODE_A","authorization_code":"CODE_B","code_verifier":"{valid_verifier}"}}"#
            ),
        ),
        (
            "duplicate ordinary key",
            format!(
                r#"{{"status":"one","status":"two","authorization_code":"CODE","code_verifier":"{valid_verifier}"}}"#
            ),
        ),
    ];

    for (case, body) in cases {
        let (host, transport) = default_host();
        let policy = policy();
        let device = start_device_session(&host, &transport, &policy);
        transport.push_raw(200, &body);
        let error = host
            .transport_exchange_pair(
                &policy,
                request("/oauth/device/token", "grant_type=device_code"),
                device.clone(),
                capture_intent(),
            )
            .expect_err(case);
        assert_eq!(error.code(), "malformed_response", "{case}: {error}");
        assert_eq!(
            host.transport(
                &policy,
                request("/oauth/device/token", "grant_type=device_code"),
                CredentialUse::Device(device),
            )
            .expect_err("malformed pair revoked submitted device")
            .code(),
            "handle_revoked",
            "{case}"
        );
        assert_eq!(transport.take_sent().len(), 2, "{case}");
    }
}

#[test]
fn parent_empty_userinfo_is_rejected_before_send_and_preserves_retry() {
    let (host, transport) = default_host();
    let policy = policy();
    let device = start_device_session(&host, &transport, &policy);
    transport.push_json(
        200,
        serde_json::json!({
            "authorization_code": AUTHORIZATION_CODE_SECRET,
            "code_verifier": CODE_VERIFIER_SECRET
        }),
    );
    let error = host
        .transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            device.clone(),
            OpaqueExchangeResponseIntent {
                code_field: ExchangeCodeField::AuthorizationCode,
                redirect_uri: "https://@redirect.example.test/callback".to_string(),
            },
        )
        .expect_err("explicit empty userinfo must be rejected before I/O");
    assert_eq!(error.code(), "invalid_intent");
    assert_eq!(transport.take_sent().len(), 1, "only start sent");
    let retry = host
        .transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            device,
            capture_intent(),
        )
        .expect("submitted device remains retryable");
    assert!(retry.pair.is_some());
    assert_eq!(transport.take_sent().len(), 1, "only valid retry sent");
}

#[test]
fn path_and_query_at_signs_reach_the_existing_exchange_unchanged() {
    let cases = [
        (
            "https://redirect.example.test/callback/@path",
            "https%3A%2F%2Fredirect.example.test%2Fcallback%2F%40path",
        ),
        (
            "HTTPS://redirect.example.test/callback?return=@query",
            "HTTPS%3A%2F%2Fredirect.example.test%2Fcallback%3Freturn%3D%40query",
        ),
    ];

    for (redirect_uri, encoded_redirect_uri) in cases {
        let (host, transport) = default_host();
        let policy = policy();
        let device = start_device_session(&host, &transport, &policy);
        transport.push_json(
            200,
            serde_json::json!({
                "authorization_code": AUTHORIZATION_CODE_SECRET,
                "code_verifier": CODE_VERIFIER_SECRET
            }),
        );
        let captured = host
            .transport_exchange_pair(
                &policy,
                request("/oauth/device/token", "grant_type=device_code"),
                device,
                OpaqueExchangeResponseIntent {
                    code_field: ExchangeCodeField::AuthorizationCode,
                    redirect_uri: redirect_uri.to_string(),
                },
            )
            .expect("raw @ in path/query is not authority userinfo");
        let pair = captured.pair.expect("opaque pair");

        transport.push_json(200, serde_json::json!({"ok": true}));
        host.transport(
            &policy,
            request("/oauth/token", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode {
                code: pair.code_handle,
                verifier: pair.verifier_handle,
            },
        )
        .expect("existing exchange uses the admitted redirect URI");
        let sent = transport.take_sent();
        assert_eq!(sent.len(), 3);
        assert!(
            sent[2]
                .body
                .contains(&format!("redirect_uri={encoded_redirect_uri}"))
        );
    }
}

#[test]
fn invalid_redirect_intents_do_not_send_or_consume_device_session() {
    let (host, transport) = default_host();
    let policy = policy();
    let device = start_device_session(&host, &transport, &policy);
    let mut too_long = "https://auth.example.test/".to_string();
    too_long.push_str(&"x".repeat(2048));
    for redirect_uri in [
        String::new(),
        "http://attacker.example/callback".to_string(),
        "ftp://auth.example.test/callback".to_string(),
        "https://user:password@auth.example.test/callback".to_string(),
        "https://@redirect.example.test/callback".to_string(),
        "http://@127.0.0.1:43127/callback".to_string(),
        "HTTPS://@redirect.example.test/callback".to_string(),
        "https://redirect.example.test\\callback".to_string(),
        "https://auth.example.test/callback#fragment".to_string(),
        "https://auth.example.test/callback\n".to_string(),
        too_long,
    ] {
        let error = host
            .transport_exchange_pair(
                &policy,
                request("/oauth/device/token", "grant_type=device_code"),
                device.clone(),
                OpaqueExchangeResponseIntent {
                    code_field: ExchangeCodeField::AuthorizationCode,
                    redirect_uri,
                },
            )
            .expect_err("invalid redirect URI");
        assert_eq!(error.code(), "invalid_intent");
    }
    assert_eq!(transport.take_sent().len(), 1, "only device start sent");

    transport.push_json(
        200,
        serde_json::json!({
            "authorization_code": AUTHORIZATION_CODE_SECRET,
            "code_verifier": CODE_VERIFIER_SECRET
        }),
    );
    let retry = host
        .transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            device,
            capture_intent(),
        )
        .expect("active device session retries after local rejection");
    assert!(retry.pair.is_some());
    assert_eq!(transport.take_sent().len(), 1, "only valid poll sent");
}

#[test]
fn captured_pair_with_new_credentials_is_rejected_without_touching_sibling() {
    let (host, transport) = default_host();
    let policy = policy();
    let submitted = start_device_session(&host, &transport, &policy);
    let sibling = start_device_session(&host, &transport, &policy);
    let new_device = "UNEXPECTED_NEW_DEVICE_SECRET";
    transport.push_json(
        200,
        serde_json::json!({
            "authorization_code": AUTHORIZATION_CODE_SECRET,
            "code_verifier": CODE_VERIFIER_SECRET,
            "access_token": ACCESS_SECRET,
            "refresh_token": REFRESH_SECRET,
            "device_code": new_device
        }),
    );
    let error = host
        .transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            submitted.clone(),
            capture_intent(),
        )
        .expect_err("pair cannot combine with new credentials");
    assert_eq!(error.code(), "malformed_response");
    assert!(!format!("{error:?}").contains(ACCESS_SECRET));
    assert!(!format!("{error:?}").contains(REFRESH_SECRET));
    assert!(!format!("{error:?}").contains(new_device));
    assert_eq!(
        host.transport(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            CredentialUse::Device(submitted),
        )
        .expect_err("submitted session revoked on malformed controls")
        .code(),
        "handle_revoked"
    );

    transport.push_json(400, serde_json::json!({"error": "authorization_pending"}));
    let sibling_pending = host
        .transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            sibling.clone(),
            capture_intent(),
        )
        .expect("sibling remains active");
    assert!(sibling_pending.pair.is_none());
    transport.push_json(
        200,
        serde_json::json!({
            "authorization_code": AUTHORIZATION_CODE_SECRET,
            "code_verifier": CODE_VERIFIER_SECRET
        }),
    );
    let sibling_pair = host
        .transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            sibling,
            capture_intent(),
        )
        .expect("sibling can still be promoted");
    assert!(sibling_pair.pair.is_some());
}

#[test]
fn code_field_and_loopback_http_redirect_use_existing_exchange_path() {
    let (host, transport) = default_host();
    let policy = policy();
    let device = start_device_session(&host, &transport, &policy);
    let redirect_uri = "http://127.0.0.1:43127/callback";
    transport.push_json(
        200,
        serde_json::json!({
            "code": AUTHORIZATION_CODE_SECRET,
            "code_verifier": CODE_VERIFIER_SECRET
        }),
    );
    let captured = host
        .transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            device,
            OpaqueExchangeResponseIntent {
                code_field: ExchangeCodeField::Code,
                redirect_uri: redirect_uri.to_string(),
            },
        )
        .expect("capture `code` field");
    let pair = captured.pair.expect("opaque pair");
    assert!(
        captured
            .response
            .body_without_secret_fields
            .get("code")
            .is_none()
    );
    transport.push_json(200, serde_json::json!({"ok": true}));
    host.transport(
        &policy,
        request("/oauth/token", "grant_type=authorization_code"),
        CredentialUse::AuthorizationCode {
            code: pair.code_handle,
            verifier: pair.verifier_handle,
        },
    )
    .expect("native exchange consumes captured pair");
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 3);
    assert!(
        sent[2]
            .body
            .contains(&format!("code={AUTHORIZATION_CODE_SECRET}"))
    );
    assert!(
        sent[2]
            .body
            .contains(&format!("code_verifier={CODE_VERIFIER_SECRET}"))
    );
    assert!(
        sent[2]
            .body
            .contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A43127%2Fcallback")
    );
}

struct CancelAtClock {
    base: Instant,
    calls: AtomicUsize,
    cancel_at: AtomicUsize,
    cancel: Arc<ScriptedCancel>,
}

impl OAuthClock for CancelAtClock {
    fn now(&self) -> Instant {
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if call == self.cancel_at.load(Ordering::Acquire) {
            self.cancel.cancel();
        }
        self.base
    }

    fn unix_ms(&self) -> u64 {
        1_900_000_000_000
    }
}

#[test]
fn requested_cancellation_during_and_after_pair_publication_revokes_transients() {
    for cancel_at in [8, 9] {
        let transport = Arc::new(ScriptedHttpsTransport::new());
        let cancel = Arc::new(ScriptedCancel::new());
        let clock = Arc::new(CancelAtClock {
            base: Instant::now(),
            calls: AtomicUsize::new(0),
            cancel_at: AtomicUsize::new(usize::MAX),
            cancel: Arc::clone(&cancel),
        });
        let host = OAuthHost::new(
            Arc::clone(&transport) as Arc<_>,
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::clone(&clock) as Arc<_>,
            cancel,
        );
        let policy = policy();
        let device = start_device_session(&host, &transport, &policy);
        clock.calls.store(0, Ordering::Release);
        clock.cancel_at.store(cancel_at, Ordering::Release);
        transport.push_json(
            200,
            serde_json::json!({
                "authorization_code": AUTHORIZATION_CODE_SECRET,
                "code_verifier": CODE_VERIFIER_SECRET
            }),
        );
        let error = host
            .transport_exchange_pair(
                &policy,
                request("/oauth/device/token", "grant_type=device_code"),
                device.clone(),
                capture_intent(),
            )
            .expect_err("cancellation rejects response publication");
        assert_eq!(error.code(), "cancelled", "cancel checkpoint {cancel_at}");
        assert_eq!(
            host.transport(
                &policy,
                request("/oauth/device/token", "grant_type=device_code"),
                CredentialUse::Device(device),
            )
            .expect_err("submitted alias revoked")
            .code(),
            "handle_revoked",
            "cancel checkpoint {cancel_at}"
        );
        assert_eq!(
            transport.take_sent().len(),
            2,
            "cancel checkpoint {cancel_at}"
        );
    }
}

struct CancelDuringPollTransport {
    scripted: Arc<ScriptedHttpsTransport>,
    cancel: Arc<ScriptedCancel>,
}

impl BoundedHttpsTransport for CancelDuringPollTransport {
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        let response = self.scripted.send(request, context)?;
        if request.url.ends_with("/oauth/device/token") {
            self.cancel.cancel();
        }
        Ok(response)
    }
}

#[test]
fn cancellation_after_transport_io_revokes_submitted_device_session() {
    let scripted = Arc::new(ScriptedHttpsTransport::new());
    let cancel = Arc::new(ScriptedCancel::new());
    let host = OAuthHost::new(
        Arc::new(CancelDuringPollTransport {
            scripted: Arc::clone(&scripted),
            cancel: Arc::clone(&cancel),
        }),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        cancel,
    );
    let policy = policy();
    let device = start_device_session(&host, &scripted, &policy);
    scripted.push_json(
        200,
        serde_json::json!({
            "authorization_code": AUTHORIZATION_CODE_SECRET,
            "code_verifier": CODE_VERIFIER_SECRET
        }),
    );
    assert_eq!(
        host.transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            device.clone(),
            capture_intent(),
        )
        .expect_err("late cancellation")
        .code(),
        "cancelled"
    );
    assert_eq!(
        host.transport(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            CredentialUse::Device(device),
        )
        .expect_err("device revoked")
        .code(),
        "handle_revoked"
    );
    assert_eq!(scripted.take_sent().len(), 2);
}

#[test]
fn pair_promotion_replaces_device_in_place_at_live_flow_ceiling() {
    let (host, transport) = default_host();
    let mut policy = policy();
    policy.deadline = Instant::now() + Duration::from_secs(48 * 60 * 60);
    let mut devices = Vec::with_capacity(MAX_LIVE_OAUTH_FLOWS);
    for _ in 0..MAX_LIVE_OAUTH_FLOWS {
        devices.push(start_device_session(&host, &transport, &policy));
    }

    transport.push_json(
        200,
        serde_json::json!({
            "authorization_code": AUTHORIZATION_CODE_SECRET,
            "code_verifier": CODE_VERIFIER_SECRET
        }),
    );
    let captured = host
        .transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            devices[0].clone(),
            capture_intent(),
        )
        .expect("replacement fits at existing 64-flow ceiling");
    let pair = captured.pair.expect("promoted pair");

    transport.push_json(
        200,
        serde_json::json!({
            "device_code": "OVERFLOW_DEVICE_SECRET",
            "user_code": "OVERFLOW",
            "verification_uri": "https://auth.example.test/device",
            "expires_in": 900,
            "interval": 5
        }),
    );
    assert_eq!(
        host.transport(
            &policy,
            request("/oauth/device", "client_id=synthetic-client"),
            CredentialUse::None,
        )
        .expect_err("registry remains at its cap")
        .code(),
        "invalid_intent"
    );

    transport.push_json(200, serde_json::json!({"ok": true}));
    host.transport(
        &policy,
        request("/oauth/token", "grant_type=authorization_code"),
        CredentialUse::AuthorizationCode {
            code: pair.code_handle,
            verifier: pair.verifier_handle,
        },
    )
    .expect("promoted pair remains registered at ceiling");

    let resumed = start_device_session(&host, &transport, &policy);
    assert_eq!(resumed.class(), "OpaqueDeviceSessionHandle");
    assert_eq!(transport.take_sent().len(), MAX_LIVE_OAUTH_FLOWS + 4);
}

#[test]
fn foreign_host_run_and_credential_bindings_fail_without_consuming_device_session() {
    let (host, transport) = default_host();
    let policy = policy();
    let device = start_device_session(&host, &transport, &policy);

    let mut foreign_run = policy.clone();
    foreign_run.run_id = "foreign-native-run".to_string();
    assert_eq!(
        host.transport_exchange_pair(
            &foreign_run,
            request("/oauth/device/token", "grant_type=device_code"),
            device.clone(),
            capture_intent(),
        )
        .expect_err("foreign run rejected")
        .code(),
        "handle_provenance"
    );

    let mut foreign_credential_request = request("/oauth/device/token", "grant_type=device_code");
    foreign_credential_request.credential_id = "another-credential".to_string();
    assert_eq!(
        host.transport_exchange_pair(
            &policy,
            foreign_credential_request,
            device.clone(),
            capture_intent(),
        )
        .expect_err("foreign credential rejected")
        .code(),
        "handle_provenance"
    );

    let (foreign_host, foreign_transport) = default_host();
    assert_eq!(
        foreign_host
            .transport_exchange_pair(
                &policy,
                request("/oauth/device/token", "grant_type=device_code"),
                device.clone(),
                capture_intent(),
            )
            .expect_err("foreign host rejected")
            .code(),
        "handle_invalid"
    );
    assert!(foreign_transport.take_sent().is_empty());
    assert_eq!(transport.take_sent().len(), 1);

    transport.push_json(
        200,
        serde_json::json!({
            "authorization_code": AUTHORIZATION_CODE_SECRET,
            "code_verifier": CODE_VERIFIER_SECRET
        }),
    );
    let retry = host
        .transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            device,
            capture_intent(),
        )
        .expect("valid original binding can still poll");
    assert!(retry.pair.is_some());
}

struct ExpireDuringPollTransport {
    scripted: Arc<ScriptedHttpsTransport>,
    clock: Arc<ScriptedClock>,
}

impl BoundedHttpsTransport for ExpireDuringPollTransport {
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        let response = self.scripted.send(request, context)?;
        if request.url.ends_with("/oauth/device/token") {
            self.clock.expire();
        }
        Ok(response)
    }
}

#[test]
fn submitted_device_original_expiry_bounds_pair_capture_operation() {
    let scripted = Arc::new(ScriptedHttpsTransport::new());
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let host = OAuthHost::new(
        Arc::new(ExpireDuringPollTransport {
            scripted: Arc::clone(&scripted),
            clock: Arc::clone(&clock),
        }),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::clone(&clock) as Arc<_>,
        Arc::new(ScriptedCancel::new()),
    );
    let mut policy = policy();
    policy.deadline = Instant::now() + Duration::from_secs(48 * 60 * 60);
    let device = start_device_session(&host, &scripted, &policy);
    scripted.push_json(
        200,
        serde_json::json!({
            "authorization_code": AUTHORIZATION_CODE_SECRET,
            "code_verifier": CODE_VERIFIER_SECRET
        }),
    );
    assert_eq!(
        host.transport_exchange_pair(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            device.clone(),
            capture_intent(),
        )
        .expect_err("original device TTL expired in transport")
        .code(),
        "deadline_exceeded"
    );
    assert_eq!(
        host.transport(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            CredentialUse::Device(device),
        )
        .expect_err("expired device family revoked")
        .code(),
        "handle_revoked"
    );
    assert_eq!(scripted.take_sent().len(), 2);
}
