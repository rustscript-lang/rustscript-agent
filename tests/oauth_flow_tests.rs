//! Task 3 primitive tests: generic PKCE, callback, and bounded transport.
//!
//! These tests exercise host-side primitives through a fake transport and
//! callback. They do not invoke a live provider or the production host catalog.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustscript_agent::auth::oauth::{
    BoundedPublicOAuthIntent, CallbackMode, CredentialUse, OAuthClock, OAuthError, OAuthFlowKind,
    OAuthHost, OpaqueAuthorizationCodeHandle, OpaqueVerifierHandle, PreparedHttpsRequest,
    ProviderRequest, RawCallbackInput, RawHttpsResponse, ScriptedBrowser, ScriptedCallback,
    ScriptedCancel, ScriptedClock, ScriptedHttpsTransport, TrustedEndpoint, TrustedTransportPolicy,
};
use rustscript_agent::auth::pkce::{self, PKCE_CHALLENGE_METHOD};
use rustscript_agent::auth::store::AuthStore;
use rustscript_agent::config_file::AgentPaths;
use rustscript_agent::{
    CredentialConfig, CredentialId, RefreshSecretAction, SaveCredentialRequest, SaveOutcome,
};

const ACCESS: &str = "SYNTHETIC_ACCESS_TOKEN";
const REFRESH: &str = "SYNTHETIC_REFRESH_TOKEN";
const ROTATED_ACCESS: &str = "SYNTHETIC_ROTATED_ACCESS";
const ROTATED_REFRESH: &str = "SYNTHETIC_ROTATED_REFRESH";
const AUTH_CODE: &str = "SYNTHETIC_AUTH_CODE";
const VERIFIER_NEEDLE: &str = "code_verifier";
const DEVICE_ID: &str = "SYNTHETIC_DEVICE_ID";

fn policy() -> TrustedTransportPolicy {
    TrustedTransportPolicy {
        generation: 1,
        run_id: "oauth-primitive-run".to_string(),
        deadline: Instant::now() + Duration::from_secs(60),
        endpoints: vec![
            TrustedEndpoint {
                authority: "auth.example.test".to_string(),
                path_prefix: "/authorize".to_string(),
            },
            TrustedEndpoint {
                authority: "auth.example.test".to_string(),
                path_prefix: "/oauth/token".to_string(),
            },
            TrustedEndpoint {
                authority: "auth.example.test".to_string(),
                path_prefix: "/oauth/device".to_string(),
            },
            TrustedEndpoint {
                authority: "api.example.test".to_string(),
                path_prefix: "/v1".to_string(),
            },
        ],
        allowed_header_names: ["content-type", "accept"]
            .into_iter()
            .map(str::to_string)
            .collect(),
    }
}

fn intent(mode: CallbackMode) -> BoundedPublicOAuthIntent {
    let mut public_query = BTreeMap::new();
    public_query.insert("client_id".to_string(), "synthetic-client".to_string());
    public_query.insert("response_type".to_string(), "code".to_string());
    BoundedPublicOAuthIntent {
        flow: OAuthFlowKind::AuthorizationCodePkce,
        callback_mode: mode,
        path: "/authorize".to_string(),
        scopes: vec!["scope.synthetic".to_string()],
        public_query,
        credential_id: "primary".to_string(),
    }
}

fn host_with(
    transport: Arc<ScriptedHttpsTransport>,
    callback: Arc<ScriptedCallback>,
    browser: Arc<ScriptedBrowser>,
    clock: Arc<ScriptedClock>,
    cancel: Arc<ScriptedCancel>,
) -> OAuthHost {
    OAuthHost::new(transport, callback, browser, clock, cancel)
}

#[allow(clippy::type_complexity)]
fn default_host() -> (
    OAuthHost,
    Arc<ScriptedHttpsTransport>,
    Arc<ScriptedCallback>,
    Arc<ScriptedBrowser>,
    Arc<ScriptedClock>,
    Arc<ScriptedCancel>,
) {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let callback = Arc::new(ScriptedCallback::new());
    let browser = Arc::new(ScriptedBrowser::new());
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let cancel = Arc::new(ScriptedCancel::new());
    let host = host_with(
        Arc::clone(&transport),
        Arc::clone(&callback),
        Arc::clone(&browser),
        Arc::clone(&clock),
        Arc::clone(&cancel),
    );
    (host, transport, callback, browser, clock, cancel)
}

fn assert_no_secrets(value: &str) {
    assert!(!value.contains(ACCESS), "{value}");
    assert!(!value.contains(REFRESH), "{value}");
    assert!(!value.contains(ROTATED_ACCESS), "{value}");
    assert!(!value.contains(ROTATED_REFRESH), "{value}");
    assert!(!value.contains(AUTH_CODE), "{value}");
    assert!(!value.contains(DEVICE_ID), "{value}");
    assert!(!value.contains("dBjftJeZ4CVP"), "{value}");
}

fn provider_request(path: &str, body: &str) -> ProviderRequest {
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

fn device_start_json() -> serde_json::Value {
    serde_json::json!({
        "device_code": DEVICE_ID,
        "user_code": "WDJB-MJHT",
        "verification_uri": "https://auth.example.test/device",
        "expires_in": 900,
        "interval": 5
    })
}

fn token_success_json() -> serde_json::Value {
    serde_json::json!({
        "token_type": "Bearer",
        "expires_in": 3600,
        "access_token": ROTATED_ACCESS,
        "refresh_token": ROTATED_REFRESH,
        "scope": "scope.synthetic"
    })
}

fn begin_code_exchange(host: &OAuthHost) -> (OpaqueAuthorizationCodeHandle, OpaqueVerifierHandle) {
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("begin");
    host.inject_matching_callback(&begun.callback_handle, AUTH_CODE)
        .expect("inject");
    let waited = host
        .callback_wait(&begun.callback_handle)
        .expect("callback");
    (waited.code_handle.expect("code"), begun.verifier_handle)
}

#[test]
fn pkce_s256_matches_rfc7636_appendix_b_without_session_verifier() {
    let challenge = pkce::s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        .expect("RFC 7636 appendix B verifier");
    assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    assert_eq!(PKCE_CHALLENGE_METHOD, "S256");
}

#[test]
fn pkce_begin_builds_https_url_with_challenge_and_hides_verifier() {
    let (host, _, _, browser, _, _) = default_host();
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Browser))
        .expect("pkce_begin");
    assert!(
        begun
            .authorization_url
            .starts_with("https://auth.example.test/authorize?")
    );
    assert!(begun.authorization_url.contains("code_challenge="));
    assert!(
        begun
            .authorization_url
            .contains("code_challenge_method=S256")
    );
    assert!(begun.authorization_url.contains("state="));
    assert!(begun.authorization_url.contains("scope=scope.synthetic"));
    assert!(!begun.authorization_url.contains("code_verifier="));
    assert!(!begun.authorization_url.contains(VERIFIER_NEEDLE));
    assert_eq!(begun.code_challenge_method, "S256");
    assert_eq!(begun.code_challenge.len(), 43);
    assert!(begun.redirect_uri.starts_with("http://127.0.0.1:"));
    assert_eq!(browser.opened(), vec![begun.authorization_url.clone()]);
    assert_no_secrets(&begun.authorization_url);
    assert_no_secrets(&format!("{begun:?}"));
    assert_no_secrets(&begun.code_challenge);
}

#[test]
fn copied_callback_handle_aliases_one_wait_and_replay_fails() {
    let (host, _, _, _, _, _) = default_host();
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("begin");
    host.inject_matching_callback(&begun.callback_handle, AUTH_CODE)
        .expect("inject");
    let first = host
        .callback_wait(&begun.callback_handle)
        .expect("first wait");
    assert!(first.code_handle.is_some());
    let copy = begun.callback_handle.clone();
    let replay = host.callback_wait(&copy).expect_err("replay");
    assert_eq!(replay.code(), "handle_replayed");
}

#[test]
fn forged_serialized_stale_and_expired_handles_fail_closed() {
    let (host, _, _, _, clock, _) = default_host();
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("begin");
    let forged = host.forged_callback_handle();
    assert_eq!(
        host.callback_wait(&forged).expect_err("forged").code(),
        "handle_invalid"
    );
    let rendered = format!("{:?}", begun.callback_handle);
    assert!(rendered.contains("OpaqueCallbackHandle"));
    assert!(!rendered.contains(AUTH_CODE));
    assert!(!rendered.contains("code_verifier"));
    clock.expire();
    assert_eq!(
        host.callback_wait(&begun.callback_handle)
            .expect_err("expired")
            .code(),
        "handle_expired"
    );
}

#[test]
fn cross_run_and_restart_revoke_callback_handles() {
    let (host, _, _, _, _, _) = default_host();
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("begin");
    let handle = begun.callback_handle.clone();
    drop(host);
    let (restarted, _, _, _, _, _) = default_host();
    assert_eq!(
        restarted
            .callback_wait(&handle)
            .expect_err("restart")
            .code(),
        "handle_invalid"
    );
    let other = restarted
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("other run");
    assert_eq!(
        restarted
            .callback_wait(&begun.callback_handle)
            .expect_err("cross-run")
            .code(),
        "handle_invalid"
    );
    let _ = other;
}

#[test]
fn browser_and_manual_callback_happy_paths() {
    for mode in [CallbackMode::Browser, CallbackMode::Manual] {
        let (host, _, _, _, _, _) = default_host();
        let begun = host.pkce_begin(&policy(), intent(mode)).expect("begin");
        host.inject_matching_callback(&begun.callback_handle, AUTH_CODE)
            .expect("inject");
        let waited = host
            .callback_wait(&begun.callback_handle)
            .expect("callback");
        assert!(waited.code_handle.is_some());
        assert_no_secrets(&format!("{waited:?}"));
    }
}

#[test]
fn state_mismatch_duplicate_timeout_and_cancel_revoke_the_session() {
    let (host, _, _, _, _, cancel) = default_host();
    let mismatch = host
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("mismatch begin");
    host.inject_callback(
        &mismatch.callback_handle,
        RawCallbackInput::Query {
            state: "forged-state".to_string(),
            code: AUTH_CODE.to_string(),
        },
    )
    .expect("inject mismatch");
    assert_eq!(
        host.callback_wait(&mismatch.callback_handle)
            .expect_err("mismatch")
            .code(),
        "state_mismatch"
    );

    let duplicate = host
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("dup begin");
    host.inject_matching_callback(&duplicate.callback_handle, AUTH_CODE)
        .expect("first inject");
    host.callback_wait(&duplicate.callback_handle)
        .expect("first callback");
    host.inject_matching_callback(&duplicate.callback_handle, AUTH_CODE)
        .expect_err("second inject after close");

    let timed = host
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("timeout begin");
    host.inject_callback(&timed.callback_handle, RawCallbackInput::Timeout)
        .expect("timeout inject");
    assert_eq!(
        host.callback_wait(&timed.callback_handle)
            .expect_err("timeout")
            .code(),
        "callback_timeout"
    );

    let cancelled = host
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("cancel begin");
    cancel.cancel();
    host.inject_callback(&cancelled.callback_handle, RawCallbackInput::Cancelled)
        .expect("cancel inject");
    assert_eq!(
        host.callback_wait(&cancelled.callback_handle)
            .expect_err("cancel")
            .code(),
        "callback_cancelled"
    );
}

#[test]
fn transport_sanitizes_token_response_and_handoff_slots_save() {
    let (host, transport, _, _, _, _) = default_host();
    transport.push_json(
        200,
        serde_json::json!({
            "token_type": "Bearer",
            "expires_in": 3600,
            "access_token": ROTATED_ACCESS,
            "refresh_token": ROTATED_REFRESH,
            "scope": "scope.synthetic"
        }),
    );
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("begin");
    host.inject_matching_callback(&begun.callback_handle, AUTH_CODE)
        .expect("inject");
    let waited = host
        .callback_wait(&begun.callback_handle)
        .expect("callback");
    let response = host
        .transport(
            &policy(),
            ProviderRequest {
                method: "POST".to_string(),
                path: "/oauth/token".to_string(),
                public_headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                )]),
                public_body: "grant_type=authorization_code".to_string(),
                credential_id: "primary".to_string(),
            },
            CredentialUse::AuthorizationCode {
                code: waited.code_handle.expect("code"),
                verifier: begun.verifier_handle,
            },
        )
        .expect("transport");
    assert_eq!(response.status, 200);
    assert_eq!(response.body_without_secret_fields["token_type"], "Bearer");
    assert!(
        response
            .body_without_secret_fields
            .get("access_token")
            .is_none()
    );
    assert!(
        response
            .body_without_secret_fields
            .get("refresh_token")
            .is_none()
    );
    assert!(response.access_slot.is_some());
    assert!(response.refresh_slot.is_some());
    assert_no_secrets(&format!("{response:?}"));
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0]
            .url
            .starts_with("https://auth.example.test/oauth/token")
    );
    assert!(sent[0].body.contains("grant_type=authorization_code"));
    assert!(sent[0].body.contains("code="));
    assert!(sent[0].body.contains("code_verifier="));
    assert!(!format!("{response:?}").contains(&sent[0].body));
}

#[test]
fn transport_denies_authority_path_and_header_substitution() {
    let (host, transport, _, _, _, _) = default_host();
    transport.push_json(200, serde_json::json!({"ok": true}));
    let deny_url = host
        .transport(
            &policy(),
            ProviderRequest {
                method: "POST".to_string(),
                path: "https://evil.example/oauth/token".to_string(),
                public_headers: BTreeMap::new(),
                public_body: "grant_type=refresh_token".to_string(),
                credential_id: "primary".to_string(),
            },
            CredentialUse::None,
        )
        .expect_err("url path");
    assert_eq!(deny_url.code(), "path_denied");

    let deny_header = host
        .transport(
            &policy(),
            ProviderRequest {
                method: "POST".to_string(),
                path: "/oauth/token".to_string(),
                public_headers: BTreeMap::from([(
                    "authorization".to_string(),
                    format!("Bearer {ACCESS}"),
                )]),
                public_body: "grant_type=refresh_token".to_string(),
                credential_id: "primary".to_string(),
            },
            CredentialUse::None,
        )
        .expect_err("header");
    assert_eq!(deny_header.code(), "header_denied");

    let deny_host = host
        .transport(
            &policy(),
            ProviderRequest {
                method: "POST".to_string(),
                path: "/oauth/token".to_string(),
                public_headers: BTreeMap::from([("host".to_string(), "evil.example".to_string())]),
                public_body: "grant_type=refresh_token".to_string(),
                credential_id: "primary".to_string(),
            },
            CredentialUse::None,
        )
        .expect_err("host header");
    assert_eq!(deny_host.code(), "header_denied");
    assert!(transport.take_sent().is_empty());
}

#[test]
fn malformed_and_oversized_transport_responses_are_bounded() {
    let (host, transport, _, _, _, _) = default_host();
    transport.push_raw(200, "not-json{");
    let malformed = host
        .transport(
            &policy(),
            ProviderRequest {
                method: "POST".to_string(),
                path: "/oauth/token".to_string(),
                public_headers: BTreeMap::new(),
                public_body: "grant_type=refresh_token".to_string(),
                credential_id: "primary".to_string(),
            },
            CredentialUse::None,
        )
        .expect_err("malformed");
    assert_eq!(malformed.code(), "malformed_response");

    transport.push_raw(200, &"x".repeat(70 * 1024));
    let oversized = host
        .transport(
            &policy(),
            ProviderRequest {
                method: "POST".to_string(),
                path: "/oauth/token".to_string(),
                public_headers: BTreeMap::new(),
                public_body: "grant_type=refresh_token".to_string(),
                credential_id: "primary".to_string(),
            },
            CredentialUse::None,
        )
        .expect_err("oversized");
    assert_eq!(oversized.code(), "response_too_large");
}

#[test]
fn local_refresh_validation_does_not_consume_the_handle() {
    let root = tempfile_home("refresh-validate");
    let store = open_store(&root);
    seed_credential(&store);
    let handle = store
        .issue_refresh_handle("primary", 1, 1, "oauth-primitive-run")
        .expect("refresh handle");
    let (host, transport, _, _, _, _) = default_host();
    let denied = host
        .transport(
            &policy(),
            ProviderRequest {
                method: "POST".to_string(),
                path: "/not-admitted".to_string(),
                public_headers: BTreeMap::new(),
                public_body: "grant_type=refresh_token".to_string(),
                credential_id: "primary".to_string(),
            },
            CredentialUse::Refresh(handle.clone()),
        )
        .expect_err("path denied");
    assert_eq!(denied.code(), "path_denied");
    assert!(transport.take_sent().is_empty());
    handle.validate().expect("refresh still live");

    transport.push_json(
        200,
        serde_json::json!({
            "token_type": "Bearer",
            "expires_in": 3600,
            "access_token": ROTATED_ACCESS
        }),
    );
    let sent = host
        .transport(
            &policy(),
            ProviderRequest {
                method: "POST".to_string(),
                path: "/oauth/token".to_string(),
                public_headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                )]),
                public_body: "grant_type=refresh_token".to_string(),
                credential_id: "primary".to_string(),
            },
            CredentialUse::Refresh(handle.clone()),
        )
        .expect("refresh send");
    assert_eq!(sent.status, 200);
    assert_eq!(
        handle.consume().expect_err("consumed").code(),
        "handle_replayed"
    );
}

#[test]
fn pkce_begin_rejects_device_code_flow() {
    let (host, _, _, _, _, _) = default_host();
    let mut device_intent = intent(CallbackMode::None);
    device_intent.flow = OAuthFlowKind::DeviceCode;
    let error = host
        .pkce_begin(&policy(), device_intent)
        .expect_err("device pkce");
    assert_eq!(error.code(), "invalid_intent");
}

#[test]
fn device_start_mints_opaque_handle_and_strips_device_id() {
    let (host, transport, _, _, _, _) = default_host();
    transport.push_json(200, device_start_json());
    let started = host
        .transport(
            &policy(),
            provider_request("/oauth/device", "client_id=synthetic-client"),
            CredentialUse::None,
        )
        .expect("device start");
    assert_eq!(started.status, 200);
    assert_eq!(started.body_without_secret_fields["user_code"], "WDJB-MJHT");
    assert_eq!(started.body_without_secret_fields["interval"], 5);
    assert!(
        started
            .body_without_secret_fields
            .get("device_code")
            .is_none()
    );
    assert!(started.device_handle.is_some());
    assert_no_secrets(&format!("{started:?}"));
    assert_no_secrets(&started.body_without_secret_fields.to_string());
}

#[test]
fn device_poll_pending_then_success_injects_device_id_and_consumes_on_authorize() {
    let (host, transport, _, _, _, _) = default_host();
    transport.push_json(200, device_start_json());
    let started = host
        .transport(
            &policy(),
            provider_request("/oauth/device", "client_id=synthetic-client"),
            CredentialUse::None,
        )
        .expect("start");
    let handle = started.device_handle.expect("device handle");
    let copy = handle.clone();
    transport.push_json(400, serde_json::json!({"error": "authorization_pending"}));
    let pending = host
        .transport(
            &policy(),
            provider_request(
                "/oauth/device/token",
                "grant_type=urn:ietf:params:oauth:grant-type:device_code",
            ),
            CredentialUse::Device(copy),
        )
        .expect("pending");
    assert_eq!(pending.status, 400);
    assert_eq!(
        pending.body_without_secret_fields["error"],
        "authorization_pending"
    );
    assert!(pending.access_slot.is_none());

    transport.push_json(200, token_success_json());
    let authorized = host
        .transport(
            &policy(),
            provider_request(
                "/oauth/device/token",
                "grant_type=urn:ietf:params:oauth:grant-type:device_code",
            ),
            CredentialUse::Device(handle.clone()),
        )
        .expect("authorized");
    assert_eq!(authorized.status, 200);
    assert!(authorized.access_slot.is_some());
    assert!(
        authorized
            .body_without_secret_fields
            .get("access_token")
            .is_none()
    );
    assert_no_secrets(&format!("{authorized:?}"));
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 3);
    assert!(sent[1].body.contains("device_code="));
    assert!(sent[1].body.contains(DEVICE_ID));
    assert!(sent[2].body.contains(DEVICE_ID));

    let replay = host
        .transport(
            &policy(),
            provider_request(
                "/oauth/device/token",
                "grant_type=urn:ietf:params:oauth:grant-type:device_code",
            ),
            CredentialUse::Device(handle),
        )
        .expect_err("device replay");
    assert_eq!(replay.code(), "handle_replayed");
}

#[test]
fn device_slow_down_keeps_session_live_until_success() {
    let (host, transport, _, _, _, _) = default_host();
    transport.push_json(200, device_start_json());
    let started = host
        .transport(
            &policy(),
            provider_request("/oauth/device", "client_id=synthetic-client"),
            CredentialUse::None,
        )
        .expect("start");
    let handle = started.device_handle.expect("device handle");
    transport.push_json(400, serde_json::json!({"error": "slow_down"}));
    let slowed = host
        .transport(
            &policy(),
            provider_request(
                "/oauth/device/token",
                "grant_type=urn:ietf:params:oauth:grant-type:device_code",
            ),
            CredentialUse::Device(handle.clone()),
        )
        .expect("slow_down");
    assert_eq!(slowed.body_without_secret_fields["error"], "slow_down");
    transport.push_json(200, token_success_json());
    let authorized = host
        .transport(
            &policy(),
            provider_request(
                "/oauth/device/token",
                "grant_type=urn:ietf:params:oauth:grant-type:device_code",
            ),
            CredentialUse::Device(handle),
        )
        .expect("authorized after slow_down");
    assert!(authorized.access_slot.is_some());
}

#[test]
fn device_cancel_timeout_forged_stale_and_restart_fail_closed() {
    let (host, transport, _, _, clock, cancel) = default_host();
    transport.push_json(200, device_start_json());
    let started = host
        .transport(
            &policy(),
            provider_request("/oauth/device", "client_id=synthetic-client"),
            CredentialUse::None,
        )
        .expect("start");
    let handle = started.device_handle.expect("device handle");
    assert_eq!(
        host.transport(
            &policy(),
            provider_request(
                "/oauth/device/token",
                "grant_type=urn:ietf:params:oauth:grant-type:device_code",
            ),
            CredentialUse::Device(host.forged_device_handle()),
        )
        .expect_err("forged")
        .code(),
        "handle_invalid"
    );
    let mut stale = policy();
    stale.generation = 99;
    assert_eq!(
        host.transport(
            &stale,
            provider_request(
                "/oauth/device/token",
                "grant_type=urn:ietf:params:oauth:grant-type:device_code",
            ),
            CredentialUse::Device(handle.clone()),
        )
        .expect_err("stale policy")
        .code(),
        "handle_provenance"
    );
    cancel.cancel();
    assert_eq!(
        host.transport(
            &policy(),
            provider_request(
                "/oauth/device/token",
                "grant_type=urn:ietf:params:oauth:grant-type:device_code",
            ),
            CredentialUse::Device(handle.clone()),
        )
        .expect_err("cancel")
        .code(),
        "cancelled"
    );
    drop(host);
    let (restarted, _, _, _, _, _) = default_host();
    assert_eq!(
        restarted
            .transport(
                &policy(),
                provider_request(
                    "/oauth/device/token",
                    "grant_type=urn:ietf:params:oauth:grant-type:device_code",
                ),
                CredentialUse::Device(handle),
            )
            .expect_err("restart")
            .code(),
        "handle_invalid"
    );

    let (timed_host, timed_transport, _, _, timed_clock, _) = default_host();
    timed_transport.push_json(200, device_start_json());
    let timed = timed_host
        .transport(
            &policy(),
            provider_request("/oauth/device", "client_id=synthetic-client"),
            CredentialUse::None,
        )
        .expect("timed start");
    let timed_handle = timed.device_handle.expect("timed handle");
    timed_clock.expire();
    clock.expire();
    let expired = timed_host
        .transport(
            &policy(),
            provider_request(
                "/oauth/device/token",
                "grant_type=urn:ietf:params:oauth:grant-type:device_code",
            ),
            CredentialUse::Device(timed_handle),
        )
        .expect_err("expired");
    assert!(
        expired.code() == "deadline_exceeded" || expired.code() == "handle_expired",
        "{}",
        expired.code()
    );
}

#[test]
fn refresh_transport_mints_slots_bound_to_live_generation() {
    let root = tempfile_home("refresh-generation");
    let store = open_store(&root);
    seed_credential(&store);
    let metadata = store.load_metadata("primary").expect("metadata");
    assert_eq!(metadata.generation, 1);
    let handle = store
        .issue_refresh_handle("primary", 1, 1, "oauth-primitive-run")
        .expect("refresh handle");
    let (host, transport, _, _, _, _) = default_host();
    transport.push_json(200, token_success_json());
    let response = host
        .transport(
            &policy(),
            provider_request("/oauth/token", "grant_type=refresh_token"),
            CredentialUse::Refresh(handle),
        )
        .expect("refresh transport");
    let access = response.access_slot.expect("access slot");
    let refresh = response.refresh_slot.expect("refresh slot");
    let saved = store
        .save_if_generation(SaveCredentialRequest::new(
            CredentialId::new("primary").expect("id"),
            1,
            1,
            "oauth-primitive-run",
            CredentialConfig {
                provider: "synthetic-provider".to_string(),
                kind: "oauth".to_string(),
                source: "synthetic-test".to_string(),
                token_type: "Bearer".to_string(),
                expires_at_ms: 1_900_000_000_000,
                scopes: vec!["scope.synthetic".to_string()],
                account_id: Some("acct.synthetic".to_string()),
                generation: 1,
                status: "active".to_string(),
                last_refresh_at_ms: Some(1_900_000_000_000),
                has_refresh_token: true,
            },
            access,
            RefreshSecretAction::Replace(refresh),
        ))
        .expect("save generation 1");
    match saved {
        SaveOutcome::Committed { metadata } | SaveOutcome::Adopted { metadata } => {
            assert_eq!(metadata.generation, 2);
        }
    }
}

#[test]
fn copied_code_and_verifier_exchange_once_and_replay_fails() {
    let (host, transport, _, _, _, _) = default_host();
    let (code, verifier) = begin_code_exchange(&host);
    transport.push_json(200, token_success_json());
    let first = host
        .transport(
            &policy(),
            provider_request("/oauth/token", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode {
                code: code.clone(),
                verifier: verifier.clone(),
            },
        )
        .expect("first exchange");
    assert!(first.access_slot.is_some());
    let replay = host
        .transport(
            &policy(),
            provider_request("/oauth/token", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode { code, verifier },
        )
        .expect_err("replay");
    assert_eq!(replay.code(), "handle_replayed");
}

#[test]
fn local_code_validation_does_not_consume_but_transport_start_does() {
    let (host, transport, _, _, _, _) = default_host();
    let (code, verifier) = begin_code_exchange(&host);
    let denied = host
        .transport(
            &policy(),
            provider_request("/not-admitted", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode {
                code: code.clone(),
                verifier: verifier.clone(),
            },
        )
        .expect_err("local deny");
    assert_eq!(denied.code(), "path_denied");
    assert!(transport.take_sent().is_empty());

    let missing = host
        .transport(
            &policy(),
            provider_request("/oauth/token", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode {
                code: code.clone(),
                verifier: verifier.clone(),
            },
        )
        .expect_err("network missing");
    assert_eq!(missing.code(), "transport_error");
    let replay = host
        .transport(
            &policy(),
            provider_request("/oauth/token", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode { code, verifier },
        )
        .expect_err("no replay after send start");
    assert_eq!(replay.code(), "handle_replayed");
}

#[test]
fn forged_stale_expired_and_restart_code_handles_fail_closed() {
    let (host, _, _, _, clock, _) = default_host();
    let (code, verifier) = begin_code_exchange(&host);
    assert_eq!(
        host.transport(
            &policy(),
            provider_request("/oauth/token", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode {
                code: host.forged_code_handle(),
                verifier: verifier.clone(),
            },
        )
        .expect_err("forged code")
        .code(),
        "handle_invalid"
    );
    let mut stale = policy();
    stale.generation = 99;
    assert_eq!(
        host.transport(
            &stale,
            provider_request("/oauth/token", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode {
                code: code.clone(),
                verifier: verifier.clone(),
            },
        )
        .expect_err("stale")
        .code(),
        "handle_provenance"
    );
    clock.expire();
    let expired = host
        .transport(
            &policy(),
            provider_request("/oauth/token", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode {
                code: code.clone(),
                verifier,
            },
        )
        .expect_err("expired");
    assert!(
        expired.code() == "deadline_exceeded" || expired.code() == "handle_expired",
        "{}",
        expired.code()
    );
    drop(host);
    let (restarted, _, _, _, _, _) = default_host();
    assert_eq!(
        restarted
            .transport(
                &policy(),
                provider_request("/oauth/token", "grant_type=authorization_code"),
                CredentialUse::AuthorizationCode {
                    code,
                    verifier: restarted.forged_verifier_handle(),
                },
            )
            .expect_err("restart")
            .code(),
        "handle_invalid"
    );
}

fn tempfile_home(name: &str) -> std::path::PathBuf {
    let base = std::env::var_os("TEST_TMPDIR")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let path = base.join(format!(
        "rustscript-agent-oauth-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).expect("temp home");
    path
}

fn open_store(home: &std::path::Path) -> AuthStore {
    let paths = AgentPaths::from_home(home.join("home")).expect("paths");
    AuthStore::open(paths).expect("store")
}

fn seed_credential(store: &AuthStore) {
    let access = store
        .fixture_access_slot("primary", 0, 1, "oauth-primitive-run", ACCESS)
        .expect("access slot");
    let refresh = store
        .fixture_refresh_slot("primary", 0, 1, "oauth-primitive-run", REFRESH)
        .expect("refresh slot");
    store
        .save_if_generation(SaveCredentialRequest::new(
            CredentialId::new("primary").expect("id"),
            0,
            1,
            "oauth-primitive-run",
            CredentialConfig {
                provider: "synthetic-provider".to_string(),
                kind: "oauth".to_string(),
                source: "synthetic-test".to_string(),
                token_type: "Bearer".to_string(),
                expires_at_ms: 1_900_000_000_000,
                scopes: vec!["scope.synthetic".to_string()],
                account_id: Some("acct.synthetic".to_string()),
                generation: 0,
                status: "active".to_string(),
                last_refresh_at_ms: None,
                has_refresh_token: true,
            },
            access,
            RefreshSecretAction::Replace(refresh),
        ))
        .expect("seed");
}

// Silence unused imports if helpers shift during GREEN.
#[allow(dead_code)]
fn _clock_trait(_: &dyn OAuthClock) {}
#[allow(dead_code)]
fn _error_code(error: OAuthError) -> &'static str {
    error.code()
}
#[allow(dead_code)]
fn _lock<T>(value: T) -> Mutex<T> {
    Mutex::new(value)
}
#[allow(dead_code)]
fn _prepared(_request: PreparedHttpsRequest, _response: RawHttpsResponse) {}
