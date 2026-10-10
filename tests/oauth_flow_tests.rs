//! Task 3 primitive tests: generic PKCE, callback, and bounded transport.
//!
//! These tests exercise host-side primitives through a fake transport and
//! callback. They do not invoke a live provider or the production host catalog.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustscript_agent::auth::oauth::{
    BoundedHttpsTransport, BoundedPublicOAuthIntent, BrowserOpener, CallbackMode, CallbackWaiter,
    CredentialUse, MAX_LIVE_OAUTH_FLOWS, OAuthClock, OAuthError, OAuthFlowKind, OAuthHost,
    OAuthIoContext, OpaqueAuthorizationCodeHandle, OpaqueVerifierHandle, PreparedHttpsRequest,
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

// Advance only the injected host clock, leaving a long policy deadline live.
struct FlowTtlClock {
    base: Instant,
    offset: Mutex<Duration>,
}

impl FlowTtlClock {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
        }
    }

    fn advance(&self, duration: Duration) {
        *self.offset.lock().expect("clock offset") += duration;
    }

    fn long_policy(&self) -> TrustedTransportPolicy {
        let mut policy = policy();
        policy.deadline = self.base + Duration::from_secs(3600);
        policy
    }
}

impl OAuthClock for FlowTtlClock {
    fn now(&self) -> Instant {
        self.base + *self.offset.lock().expect("clock offset")
    }

    fn unix_ms(&self) -> u64 {
        1_900_000_000_000
    }
}

struct AdvancingTransport {
    scripted: Arc<ScriptedHttpsTransport>,
    clock: Arc<FlowTtlClock>,
    advance_on: &'static str,
    advance_by: Duration,
    deadlines: Mutex<Vec<Instant>>,
}

impl BoundedHttpsTransport for AdvancingTransport {
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        self.deadlines
            .lock()
            .expect("deadlines")
            .push(context.deadline());
        let response = self.scripted.send(request, context);
        if request.url.ends_with(self.advance_on) {
            self.clock.advance(self.advance_by);
        }
        response
    }
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
fn device_poll_rejects_flow_ttl_crossed_inside_send_and_revokes_session() {
    for (advance_by, late) in [(Duration::ZERO, false), (Duration::from_secs(901), true)] {
        let clock = Arc::new(FlowTtlClock::new());
        let policy = clock.long_policy();
        let scripted = Arc::new(ScriptedHttpsTransport::new());
        let transport = Arc::new(AdvancingTransport {
            scripted: Arc::clone(&scripted),
            clock: Arc::clone(&clock),
            advance_on: "/oauth/device/token",
            advance_by,
            deadlines: Mutex::new(Vec::new()),
        });
        let host = OAuthHost::new(
            Arc::clone(&transport) as Arc<_>,
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::clone(&clock) as Arc<_>,
            Arc::new(ScriptedCancel::new()),
        );
        scripted.push_json(200, device_start_json());
        let handle = host
            .transport(
                &policy,
                provider_request("/oauth/device", "client_id=synthetic-client"),
                CredentialUse::None,
            )
            .expect("start")
            .device_handle
            .expect("device handle");
        scripted.push_json(200, token_success_json());
        let result = host.transport(
            &policy,
            provider_request("/oauth/device/token", "grant_type=device_code"),
            CredentialUse::Device(handle.clone()),
        );
        if late {
            assert_eq!(
                result.expect_err("flow expired during device poll").code(),
                "deadline_exceeded"
            );
            assert_eq!(
                host.transport(
                    &policy,
                    provider_request("/oauth/device/token", "grant_type=device_code"),
                    CredentialUse::Device(handle),
                )
                .expect_err("expired session revoked")
                .code(),
                "handle_revoked"
            );
        } else {
            assert!(result.expect("within flow lifetime").access_slot.is_some());
            assert_eq!(
                host.transport(
                    &policy,
                    provider_request("/oauth/device/token", "grant_type=device_code"),
                    CredentialUse::Device(handle),
                )
                .expect_err("completed session replay")
                .code(),
                "handle_replayed"
            );
        }
        if late {
            assert_eq!(
                transport.deadlines.lock().expect("deadlines")[1],
                clock.base + Duration::from_secs(900)
            );
        }
    }
}

#[test]
fn device_terminal_consume_uses_fresh_clock_and_revokes_on_expiry() {
    struct CompletionClock {
        inner: FlowTtlClock,
        reads_until_jump: Mutex<Option<usize>>,
    }
    impl OAuthClock for CompletionClock {
        fn now(&self) -> Instant {
            let now = self.inner.now();
            let mut reads = self.reads_until_jump.lock().expect("reads");
            if let Some(remaining) = *reads {
                if remaining == 1 {
                    self.inner.advance(Duration::from_secs(901));
                    *reads = None;
                } else {
                    *reads = Some(remaining - 1);
                }
            }
            now
        }
        fn unix_ms(&self) -> u64 {
            self.inner.unix_ms()
        }
    }
    struct CompletionTransport {
        scripted: Arc<ScriptedHttpsTransport>,
        clock: Arc<CompletionClock>,
    }
    impl BoundedHttpsTransport for CompletionTransport {
        fn send(
            &self,
            request: &PreparedHttpsRequest,
            context: &OAuthIoContext,
        ) -> Result<RawHttpsResponse, OAuthError> {
            let result = self.scripted.send(request, context);
            if request.url.ends_with("/oauth/device/token") {
                // Host checks after send, then after sanitization. Advance just
                // after the latter returns its in-budget clock reading.
                *self.clock.reads_until_jump.lock().expect("reads") = Some(2);
            }
            result
        }
    }
    let clock = Arc::new(CompletionClock {
        inner: FlowTtlClock::new(),
        reads_until_jump: Mutex::new(None),
    });
    let policy = clock.inner.long_policy();
    let scripted = Arc::new(ScriptedHttpsTransport::new());
    let host = OAuthHost::new(
        Arc::new(CompletionTransport {
            scripted: Arc::clone(&scripted),
            clock: Arc::clone(&clock),
        }),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::clone(&clock) as Arc<_>,
        Arc::new(ScriptedCancel::new()),
    );
    scripted.push_json(200, device_start_json());
    let handle = host
        .transport(
            &policy,
            provider_request("/oauth/device", "client_id=synthetic-client"),
            CredentialUse::None,
        )
        .expect("start")
        .device_handle
        .expect("device handle");
    scripted.push_json(200, token_success_json());
    assert_eq!(
        host.transport(
            &policy,
            provider_request("/oauth/device/token", "grant_type=device_code"),
            CredentialUse::Device(handle.clone()),
        )
        .expect_err("expired at terminal completion")
        .code(),
        "handle_expired"
    );
    assert_eq!(
        host.transport(
            &policy,
            provider_request("/oauth/device/token", "grant_type=device_code"),
            CredentialUse::Device(handle),
        )
        .expect_err("revoked terminal flow")
        .code(),
        "handle_revoked"
    );
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
fn code_exchange_rejects_flow_ttl_crossed_inside_send_and_keeps_replay_consumed() {
    for (advance_by, late) in [(Duration::ZERO, false), (Duration::from_secs(901), true)] {
        let clock = Arc::new(FlowTtlClock::new());
        let policy = clock.long_policy();
        let scripted = Arc::new(ScriptedHttpsTransport::new());
        let transport = Arc::new(AdvancingTransport {
            scripted: Arc::clone(&scripted),
            clock: Arc::clone(&clock),
            advance_on: "/oauth/token",
            advance_by,
            deadlines: Mutex::new(Vec::new()),
        });
        let host = OAuthHost::new(
            Arc::clone(&transport) as Arc<_>,
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::clone(&clock) as Arc<_>,
            Arc::new(ScriptedCancel::new()),
        );
        let begun = host
            .pkce_begin(&policy, intent(CallbackMode::Manual))
            .expect("begin");
        host.inject_matching_callback(&begun.callback_handle, AUTH_CODE)
            .expect("inject");
        let code = host
            .callback_wait(&begun.callback_handle)
            .expect("wait")
            .code_handle
            .expect("code");
        let verifier = begun.verifier_handle;
        scripted.push_json(200, token_success_json());
        let result = host.transport(
            &policy,
            provider_request("/oauth/token", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode {
                code: code.clone(),
                verifier: verifier.clone(),
            },
        );
        if late {
            assert_eq!(
                result
                    .expect_err("flow expired during code exchange")
                    .code(),
                "deadline_exceeded"
            );
        } else {
            assert!(result.expect("within flow lifetime").access_slot.is_some());
        }
        if late {
            assert_eq!(
                transport.deadlines.lock().expect("deadlines").as_slice(),
                &[clock.base + Duration::from_secs(900)]
            );
        }
        assert_eq!(
            host.transport(
                &policy,
                provider_request("/oauth/token", "grant_type=authorization_code"),
                CredentialUse::AuthorizationCode { code, verifier },
            )
            .expect_err("consumed after send")
            .code(),
            "handle_replayed"
        );
    }
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

fn form_key_count(body: &str, key: &str) -> usize {
    body.split('&')
        .filter(|pair| {
            let raw = pair.split('=').next().unwrap_or("");
            form_key_matches(raw, key)
        })
        .count()
}

fn form_key_matches(raw: &str, expected: &str) -> bool {
    percent_decode_form(raw).eq_ignore_ascii_case(expected)
}

fn percent_decode_form(value: &str) -> String {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = &value[index + 1..index + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        } else if bytes[index] == b'+' {
            out.push(b' ');
            index += 1;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

struct FailBrowser;

impl BrowserOpener for FailBrowser {
    fn open(&self, _url: &str, _context: &OAuthIoContext) -> Result<(), OAuthError> {
        Err(OAuthError::Transport {
            message: "synthetic browser open failed".to_string(),
        })
    }
}

struct RaceCallback {
    on_wait: Box<dyn Fn() + Send + Sync>,
    queued: Mutex<VecDeque<RawCallbackInput>>,
}

impl CallbackWaiter for RaceCallback {
    fn wait_one(&self, _context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
        (self.on_wait)();
        self.queued
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .ok_or(OAuthError::CallbackTimeout)
    }

    fn inject(&self, input: RawCallbackInput) -> Result<(), OAuthError> {
        self.queued
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push_back(input);
        Ok(())
    }
}

#[test]
fn access_and_refresh_binding_mismatch_does_not_consume() {
    let root = tempfile_home("binding-mismatch");
    let store = open_store(&root);
    seed_credential(&store);
    let access = store
        .issue_access_handle("primary", 1, 1, "oauth-primitive-run")
        .expect("access handle");
    let refresh = store
        .issue_refresh_handle("primary", 1, 1, "oauth-primitive-run")
        .expect("refresh handle");
    let (host, transport, _, _, _, _) = default_host();

    let mut foreign = provider_request("/v1/me", "");
    foreign.method = "GET".to_string();
    foreign.credential_id = "other".to_string();
    let access_mismatch = host
        .transport(&policy(), foreign, CredentialUse::Access(access.clone()))
        .expect_err("access credential mismatch");
    assert_eq!(access_mismatch.code(), "handle_provenance");
    access.validate().expect("access still live");

    let mut stale = policy();
    stale.generation = 99;
    let refresh_stale = host
        .transport(
            &stale,
            provider_request("/oauth/token", "grant_type=refresh_token"),
            CredentialUse::Refresh(refresh.clone()),
        )
        .expect_err("refresh policy mismatch");
    assert_eq!(refresh_stale.code(), "handle_provenance");
    refresh.validate().expect("refresh still live");
    assert!(transport.take_sent().is_empty());
}

#[test]
fn access_transport_injects_bearer_after_binding() {
    let root = tempfile_home("access-send");
    let store = open_store(&root);
    seed_credential(&store);
    let access = store
        .issue_access_handle("primary", 1, 1, "oauth-primitive-run")
        .expect("access handle");
    let (host, transport, _, _, _, _) = default_host();
    transport.push_json(200, serde_json::json!({"ok": true}));
    let mut request = provider_request("/v1/me", "");
    request.method = "GET".to_string();
    let sent = host
        .transport(&policy(), request, CredentialUse::Access(access.clone()))
        .expect("access send");
    assert_eq!(sent.status, 200);
    let prepared = transport.take_sent();
    assert_eq!(prepared.len(), 1);
    assert_eq!(
        prepared[0].headers.get("authorization").map(String::as_str),
        Some("Bearer SYNTHETIC_ACCESS_TOKEN")
    );
    assert_eq!(
        access.consume().expect_err("consumed").code(),
        "handle_replayed"
    );
}

#[test]
fn reserved_form_keys_including_encoded_duplicates_fail_before_consume() {
    let root = tempfile_home("reserved-form");
    let store = open_store(&root);
    seed_credential(&store);
    let refresh = store
        .issue_refresh_handle("primary", 1, 1, "oauth-primitive-run")
        .expect("refresh handle");
    let (host, transport, _, _, _, _) = default_host();
    for body in [
        "grant_type=refresh_token&refresh_token=evil",
        "grant_type=refresh_token&refresh%5Ftoken=evil",
        "grant_type=refresh_token&Refresh_Token=evil",
    ] {
        let denied = host
            .transport(
                &policy(),
                provider_request("/oauth/token", body),
                CredentialUse::Refresh(refresh.clone()),
            )
            .expect_err("reserved refresh key");
        assert_eq!(denied.code(), "invalid_intent", "{body}");
        refresh.validate().expect("refresh still live");
    }

    let (code, verifier) = begin_code_exchange(&host);
    let code_denied = host
        .transport(
            &policy(),
            provider_request("/oauth/token", "grant_type=authorization_code&code=evil"),
            CredentialUse::AuthorizationCode {
                code: code.clone(),
                verifier: verifier.clone(),
            },
        )
        .expect_err("reserved code");
    assert_eq!(code_denied.code(), "invalid_intent");
    transport.push_json(200, token_success_json());
    let exchanged = host
        .transport(
            &policy(),
            provider_request("/oauth/token", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode { code, verifier },
        )
        .expect("code still live after reserved reject");
    assert!(exchanged.access_slot.is_some());
    assert_eq!(
        form_key_count(&transport.take_sent().last().expect("sent").body, "code"),
        1
    );
}

#[test]
fn host_injected_refresh_token_appears_exactly_once() {
    let root = tempfile_home("refresh-once");
    let store = open_store(&root);
    seed_credential(&store);
    let refresh = store
        .issue_refresh_handle("primary", 1, 1, "oauth-primitive-run")
        .expect("refresh handle");
    let (host, transport, _, _, _, _) = default_host();
    transport.push_json(200, token_success_json());
    host.transport(
        &policy(),
        provider_request("/oauth/token", "grant_type=refresh_token"),
        CredentialUse::Refresh(refresh),
    )
    .expect("refresh send");
    let sent = transport.take_sent();
    assert_eq!(form_key_count(&sent[0].body, "refresh_token"), 1);
}

#[test]
fn flows_registry_caps_at_64_and_recovers_expired_and_dropped_entries() {
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
    let mut long_lived = policy();
    long_lived.deadline = Instant::now() + Duration::from_secs(48 * 60 * 60);
    for _ in 0..MAX_LIVE_OAUTH_FLOWS {
        host.pkce_begin(&long_lived, intent(CallbackMode::Manual))
            .expect("fill");
    }
    let capped = host
        .pkce_begin(&long_lived, intent(CallbackMode::Manual))
        .expect_err("cap");
    assert_eq!(capped.code(), "invalid_intent");
    clock.expire();
    host.pkce_begin(&long_lived, intent(CallbackMode::Manual))
        .expect("sweep recovered");
}

#[test]
fn browser_open_failure_drops_the_flow_and_does_not_leak_cap() {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let callback = Arc::new(ScriptedCallback::new());
    let browser = Arc::new(FailBrowser);
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let cancel = Arc::new(ScriptedCancel::new());
    let host = OAuthHost::new(transport, callback, browser, clock, cancel);
    for _ in 0..MAX_LIVE_OAUTH_FLOWS {
        let failed = host
            .pkce_begin(&policy(), intent(CallbackMode::Browser))
            .expect_err("open failed");
        assert_eq!(failed.code(), "transport_error");
    }
    host.pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("failed opens must not occupy the cap");
}

#[test]
fn callback_finish_rechecks_cancel_and_deadline_after_wait() {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let cancel = Arc::new(ScriptedCancel::new());
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let wait_cancel = Arc::clone(&cancel);
    let host = OAuthHost::new(
        Arc::clone(&transport) as Arc<_>,
        Arc::new(RaceCallback {
            on_wait: Box::new(move || wait_cancel.cancel()),
            queued: Mutex::new(VecDeque::new()),
        }) as Arc<_>,
        Arc::new(ScriptedBrowser::new()) as Arc<_>,
        Arc::clone(&clock) as Arc<_>,
        Arc::clone(&cancel) as Arc<_>,
    );
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("begin");
    host.inject_matching_callback(&begun.callback_handle, AUTH_CODE)
        .expect("inject matching");
    let cancelled = host
        .callback_wait(&begun.callback_handle)
        .expect_err("cancel during wait");
    assert_eq!(cancelled.code(), "callback_cancelled");
    assert_eq!(
        host.callback_wait(&begun.callback_handle)
            .expect_err("cancel replay")
            .code(),
        "callback_cancelled"
    );
    assert!(
        host.inject_matching_callback(&begun.callback_handle, AUTH_CODE)
            .is_err()
    );

    let wait_clock = Arc::clone(&clock);
    let expire_host = OAuthHost::new(
        Arc::clone(&transport) as Arc<_>,
        Arc::new(RaceCallback {
            on_wait: Box::new(move || wait_clock.expire()),
            queued: Mutex::new(VecDeque::new()),
        }) as Arc<_>,
        Arc::new(ScriptedBrowser::new()) as Arc<_>,
        Arc::clone(&clock) as Arc<_>,
        Arc::new(ScriptedCancel::new()) as Arc<_>,
    );
    let timed = expire_host
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("timed begin");
    expire_host
        .inject_matching_callback(&timed.callback_handle, AUTH_CODE)
        .expect("inject timed");
    let expired = expire_host
        .callback_wait(&timed.callback_handle)
        .expect_err("expire during wait");
    assert_eq!(expired.code(), "callback_timeout");
    assert!(
        expire_host
            .inject_matching_callback(&timed.callback_handle, AUTH_CODE)
            .is_err()
    );
    assert!(expire_host.callback_wait(&timed.callback_handle).is_err());
}

#[test]
fn concurrent_callback_reserves_wait_before_native_call() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Sender};

    struct ReleaseOnDrop(Sender<()>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }
    struct BlockingCallback {
        entered: Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        calls: AtomicUsize,
        queued: Mutex<VecDeque<RawCallbackInput>>,
    }
    impl CallbackWaiter for BlockingCallback {
        fn wait_one(&self, context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
            context.check()?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.send(()).expect("entered receiver");
            self.release
                .lock()
                .expect("release lock")
                .recv_timeout(Duration::from_secs(5))
                .expect("release wait");
            self.queued
                .lock()
                .expect("queue")
                .pop_front()
                .ok_or(OAuthError::CallbackTimeout)
        }
        fn inject(&self, input: RawCallbackInput) -> Result<(), OAuthError> {
            self.queued.lock().expect("queue").push_back(input);
            Ok(())
        }
    }
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release = ReleaseOnDrop(release_tx);
    let callback = Arc::new(BlockingCallback {
        entered: entered_tx,
        release: Mutex::new(release_rx),
        calls: AtomicUsize::new(0),
        queued: Mutex::new(VecDeque::new()),
    });
    let host = Arc::new(OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::clone(&callback) as Arc<_>,
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(0)),
        Arc::new(ScriptedCancel::new()),
    ));
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("begin");
    host.inject_matching_callback(&begun.callback_handle, AUTH_CODE)
        .expect("inject");
    let first_host = Arc::clone(&host);
    let first_handle = begun.callback_handle.clone();
    let first = std::thread::spawn(move || first_host.callback_wait(&first_handle));
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("native entered");
    assert_eq!(
        host.callback_wait(&begun.callback_handle)
            .expect_err("second wait")
            .code(),
        "handle_replayed"
    );
    assert_eq!(callback.calls.load(Ordering::SeqCst), 1);
    drop(release);
    let waited = first.join().expect("join").expect("first succeeds");
    assert!(waited.code_handle.is_some());
}

#[test]
fn callback_error_after_cancellation_reports_cancel_and_revokes() {
    struct LateFailure(Arc<ScriptedCancel>);
    impl CallbackWaiter for LateFailure {
        fn wait_one(&self, context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
            assert!(context.remaining().is_ok());
            self.0.cancel();
            Err(OAuthError::Transport {
                message: "fixture failure".into(),
            })
        }
    }
    let cancel = Arc::new(ScriptedCancel::new());
    let host = OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(LateFailure(Arc::clone(&cancel))),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(0)),
        cancel,
    );
    let begun = host
        .pkce_begin(&policy(), intent(CallbackMode::Manual))
        .expect("begin");
    assert_eq!(
        host.callback_wait(&begun.callback_handle)
            .expect_err("late cancel")
            .code(),
        "callback_cancelled"
    );
    assert!(
        host.inject_matching_callback(&begun.callback_handle, AUTH_CODE)
            .is_err()
    );
}

#[test]
fn callback_waiter_error_revokes_flow_and_replay() {
    struct FailingWaiter(Instant);
    impl CallbackWaiter for FailingWaiter {
        fn wait_one(&self, context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
            assert!(context.remaining().is_ok());
            assert!(context.deadline() <= self.0 + Duration::from_secs(15 * 60));
            assert_eq!(context.max_request_body_bytes(), 64 * 1024);
            assert_eq!(context.max_response_body_bytes(), 64 * 1024);
            Err(OAuthError::Transport {
                message: "fixture callback failure".into(),
            })
        }
    }
    let clock = Arc::new(ScriptedClock::new(0));
    let start = rustscript_agent::auth::oauth::OAuthClock::now(clock.as_ref());
    let host = OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(FailingWaiter(start)),
        Arc::new(ScriptedBrowser::new()),
        clock,
        Arc::new(ScriptedCancel::new()),
    );
    let mut long_policy = policy();
    long_policy.deadline = Instant::now() + Duration::from_secs(3600);
    let begun = host
        .pkce_begin(&long_policy, intent(CallbackMode::Manual))
        .expect("begin");
    assert_eq!(
        host.callback_wait(&begun.callback_handle)
            .expect_err("wait failure")
            .code(),
        "transport_error"
    );
    assert_eq!(
        host.callback_wait(&begun.callback_handle)
            .expect_err("replay")
            .code(),
        "handle_revoked"
    );
    assert!(
        host.inject_matching_callback(&begun.callback_handle, AUTH_CODE)
            .is_err()
    );
}

#[test]
fn transport_deadline_crossed_inside_send_discards_response() {
    use rustscript_agent::auth::oauth::{BoundedHttpsTransport, RawHttpsResponse};
    struct ExpiringTransport(Arc<ScriptedClock>);
    impl BoundedHttpsTransport for ExpiringTransport {
        fn send(
            &self,
            _request: &PreparedHttpsRequest,
            context: &OAuthIoContext,
        ) -> Result<RawHttpsResponse, OAuthError> {
            assert!(context.remaining().is_ok());
            assert_eq!(context.max_response_body_bytes(), 64 * 1024);
            self.0.expire();
            Ok(RawHttpsResponse {
                status: 200,
                headers: BTreeMap::new(),
                body: token_success_json().to_string().into_bytes(),
            })
        }
    }
    let clock = Arc::new(ScriptedClock::new(0));
    let host = OAuthHost::new(
        Arc::new(ExpiringTransport(Arc::clone(&clock))),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        clock,
        Arc::new(ScriptedCancel::new()),
    );
    assert_eq!(
        host.transport(
            &policy(),
            provider_request("/oauth/token", ""),
            CredentialUse::None
        )
        .expect_err("late deadline")
        .code(),
        "deadline_exceeded"
    );
}

#[test]
fn browser_open_rejects_callback_ttl_crossed_inside_open() {
    struct AdvancingBrowser {
        clock: Arc<FlowTtlClock>,
        advance_by: Duration,
        deadlines: Mutex<Vec<Instant>>,
    }
    impl BrowserOpener for AdvancingBrowser {
        fn open(&self, _url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
            context.check()?;
            self.deadlines
                .lock()
                .expect("deadlines")
                .push(context.deadline());
            self.clock.advance(self.advance_by);
            Ok(())
        }
    }
    for (advance_by, late) in [(Duration::ZERO, false), (Duration::from_secs(901), true)] {
        let clock = Arc::new(FlowTtlClock::new());
        let policy = clock.long_policy();
        let browser = Arc::new(AdvancingBrowser {
            clock: Arc::clone(&clock),
            advance_by,
            deadlines: Mutex::new(Vec::new()),
        });
        let host = OAuthHost::new(
            Arc::new(ScriptedHttpsTransport::new()),
            Arc::new(ScriptedCallback::new()),
            Arc::clone(&browser) as Arc<_>,
            Arc::clone(&clock) as Arc<_>,
            Arc::new(ScriptedCancel::new()),
        );
        let result = host.pkce_begin(&policy, intent(CallbackMode::Browser));
        if late {
            let error = match result {
                Ok(_) => panic!("expired callback envelope was returned"),
                Err(error) => error,
            };
            assert_eq!(error.code(), "deadline_exceeded");
        } else {
            let begun = result.expect("live callback envelope");
            host.inject_matching_callback(&begun.callback_handle, AUTH_CODE)
                .expect("live flow");
        }
        if late {
            assert_eq!(
                browser.deadlines.lock().expect("deadlines").as_slice(),
                &[clock.base + Duration::from_secs(900)]
            );
        }
    }
}

#[test]
fn browser_failure_after_callback_expiry_reports_deadline_and_reclaims_cap() {
    struct FailingExpiringBrowser(Arc<FlowTtlClock>);
    impl BrowserOpener for FailingExpiringBrowser {
        fn open(&self, _url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
            context.check()?;
            self.0.advance(Duration::from_secs(901));
            Err(OAuthError::Transport {
                message: "fixture browser failure".into(),
            })
        }
    }
    let clock = Arc::new(FlowTtlClock::new());
    let policy = clock.long_policy();
    let host = OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(ScriptedCallback::new()),
        Arc::new(FailingExpiringBrowser(Arc::clone(&clock))),
        Arc::clone(&clock) as Arc<_>,
        Arc::new(ScriptedCancel::new()),
    );
    let error = match host.pkce_begin(&policy, intent(CallbackMode::Browser)) {
        Ok(_) => panic!("expired callback envelope was returned"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "deadline_exceeded");
    for _ in 0..MAX_LIVE_OAUTH_FLOWS {
        host.pkce_begin(&policy, intent(CallbackMode::Manual))
            .expect("failing browser flow must not occupy cap");
    }
}

#[test]
fn browser_error_after_late_cancel_is_classified_and_flow_revoked() {
    struct FailingCancellingBrowser(Arc<ScriptedCancel>);
    impl BrowserOpener for FailingCancellingBrowser {
        fn open(&self, _url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
            context.check()?;
            self.0.cancel();
            Err(OAuthError::Transport {
                message: "fixture browser failure".into(),
            })
        }
    }
    let cancel = Arc::new(ScriptedCancel::new());
    let clock = Arc::new(FlowTtlClock::new());
    let host = OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(ScriptedCallback::new()),
        Arc::new(FailingCancellingBrowser(Arc::clone(&cancel))),
        Arc::clone(&clock) as Arc<_>,
        cancel,
    );
    let error = match host.pkce_begin(&clock.long_policy(), intent(CallbackMode::Browser)) {
        Ok(_) => panic!("cancelled callback envelope was returned"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "cancelled");
}

#[test]
fn browser_open_observes_context_and_late_cancel_discards_begin() {
    struct CancellingBrowser(Arc<ScriptedCancel>);
    impl BrowserOpener for CancellingBrowser {
        fn open(&self, _url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
            assert!(context.remaining().is_ok());
            assert_eq!(context.max_request_body_bytes(), 64 * 1024);
            self.0.cancel();
            Ok(())
        }
    }
    let cancel = Arc::new(ScriptedCancel::new());
    let host = OAuthHost::new(
        Arc::new(ScriptedHttpsTransport::new()),
        Arc::new(ScriptedCallback::new()),
        Arc::new(CancellingBrowser(Arc::clone(&cancel))),
        Arc::new(ScriptedClock::new(0)),
        cancel,
    );
    assert_eq!(
        host.pkce_begin(&policy(), intent(CallbackMode::Browser))
            .expect_err("late browser cancellation")
            .code(),
        "cancelled"
    );
}

#[test]
fn cancelled_during_transport_discards_response_and_keeps_send_consumed() {
    use rustscript_agent::auth::oauth::{BoundedHttpsTransport, RawHttpsResponse};

    struct CancellingTransport(Arc<ScriptedCancel>);
    impl BoundedHttpsTransport for CancellingTransport {
        fn send(
            &self,
            _request: &PreparedHttpsRequest,
            context: &OAuthIoContext,
        ) -> Result<RawHttpsResponse, OAuthError> {
            assert!(context.remaining().is_ok());
            self.0.cancel();
            Ok(RawHttpsResponse {
                status: 200,
                headers: BTreeMap::new(),
                body: token_success_json().to_string().into_bytes(),
            })
        }
    }

    let root = tempfile_home("late-cancel");
    let store = open_store(&root);
    seed_credential(&store);
    let access = store
        .issue_access_handle("primary", 1, 1, "oauth-primitive-run")
        .expect("access handle");
    let cancel = Arc::new(ScriptedCancel::new());
    let host = OAuthHost::new(
        Arc::new(CancellingTransport(Arc::clone(&cancel))),
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        cancel,
    );
    let result = host.transport(
        &policy(),
        provider_request("/v1/me", ""),
        CredentialUse::Access(access.clone()),
    );
    assert_eq!(result.expect_err("cancel after send").code(), "cancelled");
    assert_eq!(
        access.consume().expect_err("consumed").code(),
        "handle_replayed"
    );
}

#[test]
fn prepared_https_request_debug_redacts_authorization_and_form_secrets() {
    let request = PreparedHttpsRequest {
        method: "POST".to_string(),
        url: "https://auth.example.test/oauth/token".to_string(),
        headers: BTreeMap::from([("authorization".to_string(), format!("Bearer {ACCESS}"))]),
        body: format!("grant_type=refresh_token&refresh_token={REFRESH}&code={AUTH_CODE}"),
    };
    let rendered = format!("{request:?}");
    assert_no_secrets(&rendered);
    assert!(!rendered.contains("Bearer "));
    assert!(!rendered.contains("refresh_token="));
}

#[test]
fn authorization_url_uses_admitted_exact_path_not_prefix() {
    let (host, _, _, _, _, _) = default_host();
    let mut consent = intent(CallbackMode::Manual);
    consent.path = "/authorize/consent".to_string();
    let begun = host.pkce_begin(&policy(), consent).expect("begin");
    assert!(
        begun
            .authorization_url
            .starts_with("https://auth.example.test/authorize/consent?"),
        "{}",
        begun.authorization_url
    );
    assert!(begun.redirect_uri.starts_with("http://127.0.0.1:"));
}

#[test]
fn device_terminal_revokes_capability_without_parsing_provider_errors() {
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
    host.terminal(&handle).expect("rss-owned terminal");
    let replay = host
        .transport(
            &policy(),
            provider_request(
                "/oauth/device/token",
                "grant_type=urn:ietf:params:oauth:grant-type:device_code",
            ),
            CredentialUse::Device(handle),
        )
        .expect_err("terminal consume");
    assert!(
        replay.code() == "handle_revoked" || replay.code() == "handle_invalid",
        "{}",
        replay.code()
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
