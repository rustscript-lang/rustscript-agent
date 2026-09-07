//! Generic OAuth primitives: PKCE session records, callback wait, and bounded
//! HTTPS transport. RSS owns flow sequencing, retry, and business errors.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use serde_json::{Map as JsonMap, Value as JsonValue};
use zeroize::Zeroizing;

use crate::auth::pkce::{self, PKCE_CHALLENGE_METHOD, PkceError};
use crate::auth::store::{AuthStoreError, OpaqueRefreshHandle, OpaqueSecretSlot, SecretSlotKind};
use crate::auth::token::CredentialId;

const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024;
const MAX_PUBLIC_QUERY_ENTRIES: usize = 32;
const MAX_PUBLIC_QUERY_BYTES: usize = 2048;
const MAX_JSON_DEPTH: usize = 8;
const CALLBACK_TTL: Duration = Duration::from_secs(15 * 60);
const HANDLE_LIVE: u8 = 0;
const HANDLE_USED: u8 = 1;
const HANDLE_EXPIRED: u8 = 2;
const HANDLE_REVOKED: u8 = 3;

/// RSS-visible class names for host-minted OAuth handles.
pub const CALLBACK_HANDLE_CLASS: &str = "OpaqueCallbackHandle";
pub const STATE_HANDLE_CLASS: &str = "OpaqueStateHandle";
pub const VERIFIER_HANDLE_CLASS: &str = "OpaqueVerifierHandle";
pub const CODE_HANDLE_CLASS: &str = "OpaqueAuthorizationCodeHandle";
pub const DEVICE_HANDLE_CLASS: &str = "OpaqueDeviceSessionHandle";

const SECRET_JSON_KEYS: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "device_code",
    "device_auth_id",
    "device_id",
    "code_verifier",
    "verifier",
    "client_secret",
    "password",
    "api_key",
    "authorization",
    "cookie",
    "code",
];

/// Structural OAuth flow tag. RSS interprets the meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthFlowKind {
    AuthorizationCodePkce,
    DeviceCode,
}

/// How the host should plumb a callback. Browser command policy is injected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackMode {
    Browser,
    Manual,
    None,
}

/// Public, bounded OAuth intent chosen by RSS. It cannot carry an authority.
#[derive(Clone, Debug)]
pub struct BoundedPublicOAuthIntent {
    pub flow: OAuthFlowKind,
    pub callback_mode: CallbackMode,
    pub path: String,
    pub scopes: Vec<String>,
    pub public_query: BTreeMap<String, String>,
    pub credential_id: String,
}

/// One admitted HTTPS authority + path prefix from trusted policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedEndpoint {
    pub authority: String,
    pub path_prefix: String,
}

/// Host-resolved transport policy. RSS cannot construct or widen it.
#[derive(Clone, Debug)]
pub struct TrustedTransportPolicy {
    pub generation: u64,
    pub run_id: String,
    pub deadline: Instant,
    pub endpoints: Vec<TrustedEndpoint>,
    pub allowed_header_names: BTreeSet<String>,
}

/// Public provider request. It has no credential field.
#[derive(Clone, Debug)]
pub struct ProviderRequest {
    pub method: String,
    pub path: String,
    pub public_headers: BTreeMap<String, String>,
    pub public_body: String,
    pub credential_id: String,
}

/// Host-side credential use for the final transport boundary.
pub enum CredentialUse {
    None,
    Access(crate::auth::store::OpaqueAccessHandle),
    Refresh(OpaqueRefreshHandle),
    AuthorizationCode {
        code: OpaqueAuthorizationCodeHandle,
        verifier: OpaqueVerifierHandle,
    },
    Device(OpaqueDeviceSessionHandle),
}

/// Result of `pkce_begin`. Verifier/state bytes are not present.
pub struct PkceBeginEnvelope {
    pub authorization_url: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub callback_handle: OpaqueCallbackHandle,
    pub verifier_handle: OpaqueVerifierHandle,
    pub state_handle: OpaqueStateHandle,
}

impl fmt::Debug for PkceBeginEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PkceBeginEnvelope")
            .field("authorization_url", &self.authorization_url)
            .field("redirect_uri", &self.redirect_uri)
            .field("code_challenge", &self.code_challenge)
            .field("code_challenge_method", &self.code_challenge_method)
            .field("callback_handle", &self.callback_handle)
            .field("verifier_handle", &self.verifier_handle)
            .field("state_handle", &self.state_handle)
            .finish()
    }
}

/// Sanitized callback wait result.
pub struct CallbackEnvelope {
    pub outcome: CallbackOutcome,
    pub code_handle: Option<OpaqueAuthorizationCodeHandle>,
}

impl fmt::Debug for CallbackEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallbackEnvelope")
            .field("outcome", &self.outcome)
            .field("code_handle", &self.code_handle)
            .finish()
    }
}

/// Terminal callback classification visible to RSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackOutcome {
    Success,
    Timeout,
    Cancelled,
    StateMismatch,
}

/// Bounded sanitized transport result plus opaque secret slots.
pub struct SanitizedProviderResponse {
    pub status: u16,
    pub public_headers: BTreeMap<String, String>,
    pub body_without_secret_fields: JsonValue,
    pub retry_after_ms: Option<u64>,
    pub access_slot: Option<OpaqueSecretSlot>,
    pub refresh_slot: Option<OpaqueSecretSlot>,
    pub device_handle: Option<OpaqueDeviceSessionHandle>,
    pub code_handle: Option<OpaqueAuthorizationCodeHandle>,
}

impl fmt::Debug for SanitizedProviderResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanitizedProviderResponse")
            .field("status", &self.status)
            .field("public_headers", &self.public_headers)
            .field(
                "body_without_secret_fields",
                &self.body_without_secret_fields,
            )
            .field("retry_after_ms", &self.retry_after_ms)
            .field(
                "access_slot",
                &self.access_slot.as_ref().map(|_| "OpaqueSecretSlot"),
            )
            .field(
                "refresh_slot",
                &self.refresh_slot.as_ref().map(|_| "OpaqueSecretSlot"),
            )
            .field("device_handle", &self.device_handle)
            .field("code_handle", &self.code_handle)
            .finish()
    }
}

/// Prepared HTTPS request at the host boundary. Tests may inspect it host-side.
#[derive(Clone, Debug)]
pub struct PreparedHttpsRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

/// Raw HTTPS response before sanitization.
#[derive(Clone, Debug)]
pub struct RawHttpsResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// Injected callback payload. State comparison stays host-side.
#[derive(Clone, Debug)]
pub enum RawCallbackInput {
    Query { state: String, code: String },
    ManualUrl(String),
    Timeout,
    Cancelled,
}

/// Injected bounded HTTPS transport.
pub trait BoundedHttpsTransport: Send + Sync {
    fn send(&self, request: &PreparedHttpsRequest) -> Result<RawHttpsResponse, OAuthError>;
}

/// Injected one-shot callback waiter.
pub trait CallbackWaiter: Send + Sync {
    fn wait_one(&self) -> Result<RawCallbackInput, OAuthError>;

    fn inject(&self, input: RawCallbackInput) -> Result<(), OAuthError> {
        let _ = input;
        Err(OAuthError::Transport {
            message: "callback waiter does not accept injected input".to_string(),
        })
    }
}

/// Injected browser opener. Command policy is not implemented here.
pub trait BrowserOpener: Send + Sync {
    fn open(&self, url: &str) -> Result<(), OAuthError>;
}

/// Injected clock used for deadlines.
pub trait OAuthClock: Send + Sync {
    fn now(&self) -> Instant;
    fn unix_ms(&self) -> u64;
}

/// Injected cancellation flag.
pub trait OAuthCancel: Send + Sync {
    fn is_cancelled(&self) -> bool;
}

/// Typed primitive failure. Codes are transport/security facts, not business policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OAuthError {
    Pkce(PkceError),
    Store(AuthStoreError),
    HandleInvalid { class: String },
    HandleReplayed { class: String },
    HandleExpired { class: String },
    HandleRevoked { class: String },
    HandleProvenance { class: String },
    AuthorityDenied { authority: String },
    PathDenied { path: String },
    HeaderDenied { name: String },
    MethodDenied { method: String },
    RequestTooLarge { max_bytes: usize },
    ResponseTooLarge { max_bytes: usize },
    MalformedResponse { reason: String },
    CallbackTimeout,
    CallbackCancelled,
    StateMismatch,
    Cancelled,
    DeadlineExceeded,
    InvalidIntent { reason: String },
    Transport { message: String },
}

impl OAuthError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Pkce(error) => error.code(),
            Self::Store(error) => error.code(),
            Self::HandleInvalid { .. } => "handle_invalid",
            Self::HandleReplayed { .. } => "handle_replayed",
            Self::HandleExpired { .. } => "handle_expired",
            Self::HandleRevoked { .. } => "handle_revoked",
            Self::HandleProvenance { .. } => "handle_provenance",
            Self::AuthorityDenied { .. } => "authority_denied",
            Self::PathDenied { .. } => "path_denied",
            Self::HeaderDenied { .. } => "header_denied",
            Self::MethodDenied { .. } => "method_denied",
            Self::RequestTooLarge { .. } => "request_too_large",
            Self::ResponseTooLarge { .. } => "response_too_large",
            Self::MalformedResponse { .. } => "malformed_response",
            Self::CallbackTimeout => "callback_timeout",
            Self::CallbackCancelled => "callback_cancelled",
            Self::StateMismatch => "state_mismatch",
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::InvalidIntent { .. } => "invalid_intent",
            Self::Transport { .. } => "transport_error",
        }
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pkce(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
            Self::HandleInvalid { class } => write!(formatter, "{class} is invalid"),
            Self::HandleReplayed { class } => write!(formatter, "{class} was replayed"),
            Self::HandleExpired { class } => write!(formatter, "{class} expired"),
            Self::HandleRevoked { class } => write!(formatter, "{class} was revoked"),
            Self::HandleProvenance { class } => {
                write!(formatter, "{class} failed provenance checks")
            }
            Self::AuthorityDenied { authority } => {
                write!(formatter, "authority {authority} is not admitted")
            }
            Self::PathDenied { path } => write!(formatter, "path {path} is not admitted"),
            Self::HeaderDenied { name } => write!(formatter, "header {name} is not admitted"),
            Self::MethodDenied { method } => write!(formatter, "method {method} is not admitted"),
            Self::RequestTooLarge { max_bytes } => {
                write!(formatter, "request exceeds {max_bytes} bytes")
            }
            Self::ResponseTooLarge { max_bytes } => {
                write!(formatter, "response exceeds {max_bytes} bytes")
            }
            Self::MalformedResponse { reason } => write!(formatter, "malformed response: {reason}"),
            Self::CallbackTimeout => formatter.write_str("callback timed out"),
            Self::CallbackCancelled => formatter.write_str("callback was cancelled"),
            Self::StateMismatch => formatter.write_str("callback state mismatch"),
            Self::Cancelled => formatter.write_str("oauth primitive was cancelled"),
            Self::DeadlineExceeded => formatter.write_str("oauth primitive deadline exceeded"),
            Self::InvalidIntent { reason } => write!(formatter, "invalid oauth intent: {reason}"),
            Self::Transport { message } => write!(formatter, "transport error: {message}"),
        }
    }
}

impl std::error::Error for OAuthError {}

impl From<PkceError> for OAuthError {
    fn from(error: PkceError) -> Self {
        Self::Pkce(error)
    }
}

impl From<AuthStoreError> for OAuthError {
    fn from(error: AuthStoreError) -> Self {
        Self::Store(error)
    }
}

struct FlowInner {
    id: u64,
    host: Weak<HostInner>,
    #[allow(dead_code)]
    policy_generation: u64,
    #[allow(dead_code)]
    run_id: String,
    #[allow(dead_code)]
    credential_id: String,
    expires_at: Instant,
    state: String,
    verifier: Mutex<Zeroizing<String>>,
    redirect_uri: String,
    callback: AtomicU8,
    verifier_state: AtomicU8,
    code_state: AtomicU8,
    code: Mutex<Option<String>>,
}

impl FlowInner {
    fn class_error(&self, class: &'static str, code: &'static str) -> OAuthError {
        match code {
            "handle_replayed" => OAuthError::HandleReplayed {
                class: class.to_string(),
            },
            "handle_expired" => OAuthError::HandleExpired {
                class: class.to_string(),
            },
            "handle_revoked" => OAuthError::HandleRevoked {
                class: class.to_string(),
            },
            _ => OAuthError::HandleInvalid {
                class: class.to_string(),
            },
        }
    }

    fn check_flag(
        &self,
        flag: &AtomicU8,
        class: &'static str,
        now: Instant,
    ) -> Result<(), OAuthError> {
        match flag.load(Ordering::Acquire) {
            HANDLE_USED => Err(self.class_error(class, "handle_replayed")),
            HANDLE_REVOKED => Err(self.class_error(class, "handle_revoked")),
            HANDLE_EXPIRED => Err(self.class_error(class, "handle_expired")),
            _ if now >= self.expires_at => {
                flag.store(HANDLE_EXPIRED, Ordering::Release);
                Err(self.class_error(class, "handle_expired"))
            }
            _ => Ok(()),
        }
    }

    fn consume_flag(
        &self,
        flag: &AtomicU8,
        class: &'static str,
        now: Instant,
    ) -> Result<(), OAuthError> {
        self.check_flag(flag, class, now)?;
        if flag
            .compare_exchange(
                HANDLE_LIVE,
                HANDLE_USED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(self.class_error(class, "handle_replayed"));
        }
        Ok(())
    }

    fn revoke(&self) {
        self.callback.store(HANDLE_REVOKED, Ordering::Release);
        self.verifier_state.store(HANDLE_REVOKED, Ordering::Release);
        self.code_state.store(HANDLE_REVOKED, Ordering::Release);
        if let Ok(mut verifier) = self.verifier.lock() {
            verifier.clear();
        }
        if let Ok(mut code) = self.code.lock() {
            *code = None;
        }
    }
}

macro_rules! opaque_handle {
    ($name:ident, $class:expr) => {
        #[derive(Clone)]
        pub struct $name {
            inner: Arc<FlowInner>,
        }

        impl $name {
            #[allow(dead_code)]
            fn from_inner(inner: Arc<FlowInner>) -> Self {
                Self { inner }
            }

            pub fn class(&self) -> &'static str {
                $class
            }

            #[allow(dead_code)]
            fn flow_id(&self) -> u64 {
                self.inner.id
            }

            #[allow(dead_code)]
            fn same_host(&self, host: &Arc<HostInner>) -> bool {
                self.inner
                    .host
                    .upgrade()
                    .is_some_and(|owned| Arc::ptr_eq(&owned, host))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct($class)
                    .field("id", &self.inner.id)
                    .finish_non_exhaustive()
            }
        }
    };
}

opaque_handle!(OpaqueCallbackHandle, CALLBACK_HANDLE_CLASS);
opaque_handle!(OpaqueStateHandle, STATE_HANDLE_CLASS);
opaque_handle!(OpaqueVerifierHandle, VERIFIER_HANDLE_CLASS);
opaque_handle!(OpaqueAuthorizationCodeHandle, CODE_HANDLE_CLASS);
opaque_handle!(OpaqueDeviceSessionHandle, DEVICE_HANDLE_CLASS);

struct HostInner {
    transport: Arc<dyn BoundedHttpsTransport>,
    callbacks: Arc<dyn CallbackWaiter>,
    browser: Arc<dyn BrowserOpener>,
    clock: Arc<dyn OAuthClock>,
    cancel: Arc<dyn OAuthCancel>,
    flows: Mutex<HashMap<u64, Arc<FlowInner>>>,
    next_id: AtomicU64,
}

/// Injected OAuth primitive host. It is not a login/refresh state machine.
pub struct OAuthHost {
    inner: Arc<HostInner>,
}

impl OAuthHost {
    pub fn new(
        transport: Arc<dyn BoundedHttpsTransport>,
        callbacks: Arc<dyn CallbackWaiter>,
        browser: Arc<dyn BrowserOpener>,
        clock: Arc<dyn OAuthClock>,
        cancel: Arc<dyn OAuthCancel>,
    ) -> Self {
        Self {
            inner: Arc::new(HostInner {
                transport,
                callbacks,
                browser,
                clock,
                cancel,
                flows: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(1),
            }),
        }
    }

    pub fn pkce_begin(
        &self,
        policy: &TrustedTransportPolicy,
        intent: BoundedPublicOAuthIntent,
    ) -> Result<PkceBeginEnvelope, OAuthError> {
        self.check_cancel_deadline(policy)?;
        validate_intent(&intent)?;
        let endpoint = admit_path(policy, &intent.path)?;
        let material = pkce::generate()?;
        let (challenge, verifier, state) = material.into_parts();
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let redirect_uri = format!("http://127.0.0.1:{}/callback", 10_000 + (id % 50_000));
        let mut query = BTreeMap::new();
        for (key, value) in &intent.public_query {
            query.insert(key.clone(), value.clone());
        }
        if !intent.scopes.is_empty() {
            query.insert("scope".to_string(), intent.scopes.join(" "));
        }
        query.insert("state".to_string(), state.as_str().to_string());
        query.insert("code_challenge".to_string(), challenge.clone());
        query.insert(
            "code_challenge_method".to_string(),
            PKCE_CHALLENGE_METHOD.to_string(),
        );
        query.insert("redirect_uri".to_string(), redirect_uri.clone());
        let authorization_url = format!(
            "https://{}{}?{}",
            endpoint.authority,
            endpoint.path_prefix,
            encode_query(&query)
        );
        let expires_at = min_deadline(policy.deadline, self.inner.clock.now() + CALLBACK_TTL);
        let flow = Arc::new(FlowInner {
            id,
            host: Arc::downgrade(&self.inner),
            policy_generation: policy.generation,
            run_id: policy.run_id.clone(),
            credential_id: intent.credential_id.clone(),
            expires_at,
            state: state.as_str().to_string(),
            verifier: Mutex::new(Zeroizing::new(verifier.as_str().to_string())),
            redirect_uri: redirect_uri.clone(),
            callback: AtomicU8::new(HANDLE_LIVE),
            verifier_state: AtomicU8::new(HANDLE_LIVE),
            code_state: AtomicU8::new(HANDLE_LIVE),
            code: Mutex::new(None),
        });
        self.inner
            .flows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, Arc::clone(&flow));
        if intent.callback_mode == CallbackMode::Browser {
            self.inner.browser.open(&authorization_url)?;
        }
        Ok(PkceBeginEnvelope {
            authorization_url,
            redirect_uri,
            code_challenge: challenge,
            code_challenge_method: PKCE_CHALLENGE_METHOD.to_string(),
            callback_handle: OpaqueCallbackHandle::from_inner(Arc::clone(&flow)),
            verifier_handle: OpaqueVerifierHandle::from_inner(Arc::clone(&flow)),
            state_handle: OpaqueStateHandle::from_inner(flow),
        })
    }

    pub fn callback_wait(
        &self,
        handle: &OpaqueCallbackHandle,
    ) -> Result<CallbackEnvelope, OAuthError> {
        let flow = self.live_flow(handle)?;
        let now = self.inner.clock.now();
        if self.inner.cancel.is_cancelled() {
            flow.revoke();
            return Err(OAuthError::CallbackCancelled);
        }
        flow.check_flag(&flow.callback, CALLBACK_HANDLE_CLASS, now)?;
        let input = self.inner.callbacks.wait_one()?;
        self.finish_callback(&flow, input, now)
    }

    pub fn transport(
        &self,
        policy: &TrustedTransportPolicy,
        request: ProviderRequest,
        credential_use: CredentialUse,
    ) -> Result<SanitizedProviderResponse, OAuthError> {
        self.check_cancel_deadline(policy)?;
        let method = request.method.to_ascii_uppercase();
        if method != "GET" && method != "POST" {
            return Err(OAuthError::MethodDenied { method });
        }
        if request.public_body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(OAuthError::RequestTooLarge {
                max_bytes: MAX_REQUEST_BODY_BYTES,
            });
        }
        let endpoint = admit_path(policy, &request.path)?;
        let headers = admit_headers(policy, &request.public_headers)?;
        let mut body = request.public_body.clone();
        let credential_id = CredentialId::new(request.credential_id.clone()).map_err(|_| {
            OAuthError::InvalidIntent {
                reason: "credential ID is invalid".to_string(),
            }
        })?;
        match &credential_use {
            CredentialUse::None => {}
            CredentialUse::Access(_) | CredentialUse::Refresh(_) => {}
            CredentialUse::AuthorizationCode { code, verifier } => {
                if !code.same_host(&self.inner) || !verifier.same_host(&self.inner) {
                    return Err(OAuthError::HandleInvalid {
                        class: CODE_HANDLE_CLASS.to_string(),
                    });
                }
                if code.flow_id() != verifier.flow_id() {
                    return Err(OAuthError::HandleProvenance {
                        class: CODE_HANDLE_CLASS.to_string(),
                    });
                }
            }
            CredentialUse::Device(handle) => {
                if !handle.same_host(&self.inner) {
                    return Err(OAuthError::HandleInvalid {
                        class: DEVICE_HANDLE_CLASS.to_string(),
                    });
                }
            }
        }
        let prepared_headers = headers;
        let mut prepared = PreparedHttpsRequest {
            method,
            url: format!("https://{}{}", endpoint.authority, request.path),
            headers: prepared_headers,
            body: String::new(),
        };
        match credential_use {
            CredentialUse::None => {
                prepared.body = body;
            }
            CredentialUse::Access(handle) => {
                let secret = handle.take_for_transport()?;
                prepared.headers.insert(
                    "authorization".to_string(),
                    format!("Bearer {}", secret.as_str()),
                );
                prepared.body = body;
            }
            CredentialUse::Refresh(handle) => {
                let secret = handle.take_for_transport()?;
                append_form(&mut body, "refresh_token", secret.as_str());
                prepared.body = body;
            }
            CredentialUse::AuthorizationCode { code, verifier } => {
                let now = self.inner.clock.now();
                let flow = self.live_flow(&code)?;
                flow.check_flag(&flow.verifier_state, VERIFIER_HANDLE_CLASS, now)?;
                flow.check_flag(&flow.code_state, CODE_HANDLE_CLASS, now)?;
                let raw_code = flow
                    .code
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
                    .ok_or_else(|| OAuthError::HandleInvalid {
                        class: CODE_HANDLE_CLASS.to_string(),
                    })?;
                let raw_verifier = flow
                    .verifier
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                flow.consume_flag(&flow.code_state, CODE_HANDLE_CLASS, now)?;
                flow.consume_flag(&flow.verifier_state, VERIFIER_HANDLE_CLASS, now)?;
                append_form(&mut body, "code", &raw_code);
                append_form(&mut body, "code_verifier", raw_verifier.as_str());
                append_form(&mut body, "redirect_uri", &flow.redirect_uri);
                prepared.body = body;
                let _ = verifier;
            }
            CredentialUse::Device(handle) => {
                let now = self.inner.clock.now();
                let flow = self.live_flow(&handle)?;
                flow.check_flag(&flow.callback, DEVICE_HANDLE_CLASS, now)?;
                prepared.body = body;
            }
        }
        let raw = self.inner.transport.send(&prepared)?;
        if raw.body.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(OAuthError::ResponseTooLarge {
                max_bytes: MAX_RESPONSE_BODY_BYTES,
            });
        }
        sanitize_response(&raw, credential_id.as_str(), policy)
    }

    pub fn inject_callback(
        &self,
        handle: &OpaqueCallbackHandle,
        input: RawCallbackInput,
    ) -> Result<(), OAuthError> {
        let flow = self.live_flow(handle)?;
        flow.check_flag(
            &flow.callback,
            CALLBACK_HANDLE_CLASS,
            self.inner.clock.now(),
        )?;
        self.inner.callbacks.inject(input)
    }

    pub fn inject_matching_callback(
        &self,
        handle: &OpaqueCallbackHandle,
        code: &str,
    ) -> Result<(), OAuthError> {
        let flow = self.live_flow(handle)?;
        self.inject_callback(
            handle,
            RawCallbackInput::Query {
                state: flow.state.clone(),
                code: code.to_string(),
            },
        )
    }

    pub fn forged_callback_handle(&self) -> OpaqueCallbackHandle {
        OpaqueCallbackHandle::from_inner(Arc::new(FlowInner {
            id: 0,
            host: Weak::new(),
            policy_generation: 0,
            run_id: "forged".to_string(),
            credential_id: "forged".to_string(),
            expires_at: Instant::now(),
            state: "forged".to_string(),
            verifier: Mutex::new(Zeroizing::new(String::new())),
            redirect_uri: String::new(),
            callback: AtomicU8::new(HANDLE_LIVE),
            verifier_state: AtomicU8::new(HANDLE_LIVE),
            code_state: AtomicU8::new(HANDLE_LIVE),
            code: Mutex::new(None),
        }))
    }

    fn finish_callback(
        &self,
        flow: &Arc<FlowInner>,
        input: RawCallbackInput,
        now: Instant,
    ) -> Result<CallbackEnvelope, OAuthError> {
        let (state, code) = match input {
            RawCallbackInput::Timeout => {
                flow.revoke();
                return Err(OAuthError::CallbackTimeout);
            }
            RawCallbackInput::Cancelled => {
                flow.revoke();
                return Err(OAuthError::CallbackCancelled);
            }
            RawCallbackInput::Query { state, code } => (state, code),
            RawCallbackInput::ManualUrl(url) => parse_callback_url(&url)?,
        };
        if code.len() > MAX_REQUEST_BODY_BYTES || state.len() > MAX_PUBLIC_QUERY_BYTES {
            flow.revoke();
            return Err(OAuthError::RequestTooLarge {
                max_bytes: MAX_REQUEST_BODY_BYTES,
            });
        }
        if state != flow.state {
            flow.revoke();
            return Err(OAuthError::StateMismatch);
        }
        flow.consume_flag(&flow.callback, CALLBACK_HANDLE_CLASS, now)?;
        *flow
            .code
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(code);
        Ok(CallbackEnvelope {
            outcome: CallbackOutcome::Success,
            code_handle: Some(OpaqueAuthorizationCodeHandle::from_inner(Arc::clone(flow))),
        })
    }

    fn live_flow<T: FlowHandle>(&self, handle: &T) -> Result<Arc<FlowInner>, OAuthError> {
        if !handle.same_host(&self.inner) {
            return Err(OAuthError::HandleInvalid {
                class: handle.class().to_string(),
            });
        }
        let flows = self
            .inner
            .flows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        flows
            .get(&handle.flow_id())
            .cloned()
            .ok_or_else(|| OAuthError::HandleInvalid {
                class: handle.class().to_string(),
            })
    }

    fn check_cancel_deadline(&self, policy: &TrustedTransportPolicy) -> Result<(), OAuthError> {
        if self.inner.cancel.is_cancelled() {
            return Err(OAuthError::Cancelled);
        }
        if self.inner.clock.now() >= policy.deadline {
            return Err(OAuthError::DeadlineExceeded);
        }
        Ok(())
    }
}

impl Drop for OAuthHost {
    fn drop(&mut self) {
        let flows: Vec<Arc<FlowInner>> = self
            .inner
            .flows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain()
            .map(|(_, flow)| flow)
            .collect();
        for flow in flows {
            flow.revoke();
        }
    }
}

trait FlowHandle {
    fn class(&self) -> &'static str;
    fn flow_id(&self) -> u64;
    fn same_host(&self, host: &Arc<HostInner>) -> bool;
}

impl FlowHandle for OpaqueCallbackHandle {
    fn class(&self) -> &'static str {
        CALLBACK_HANDLE_CLASS
    }
    fn flow_id(&self) -> u64 {
        self.flow_id()
    }
    fn same_host(&self, host: &Arc<HostInner>) -> bool {
        self.same_host(host)
    }
}

impl FlowHandle for OpaqueAuthorizationCodeHandle {
    fn class(&self) -> &'static str {
        CODE_HANDLE_CLASS
    }
    fn flow_id(&self) -> u64 {
        self.flow_id()
    }
    fn same_host(&self, host: &Arc<HostInner>) -> bool {
        self.same_host(host)
    }
}

impl FlowHandle for OpaqueDeviceSessionHandle {
    fn class(&self) -> &'static str {
        DEVICE_HANDLE_CLASS
    }
    fn flow_id(&self) -> u64 {
        self.flow_id()
    }
    fn same_host(&self, host: &Arc<HostInner>) -> bool {
        self.same_host(host)
    }
}

fn validate_intent(intent: &BoundedPublicOAuthIntent) -> Result<(), OAuthError> {
    if intent.public_query.len() > MAX_PUBLIC_QUERY_ENTRIES {
        return Err(OAuthError::InvalidIntent {
            reason: "too many public query parameters".to_string(),
        });
    }
    for (key, value) in &intent.public_query {
        let total = key.len().saturating_add(value.len());
        if total > MAX_PUBLIC_QUERY_BYTES {
            return Err(OAuthError::InvalidIntent {
                reason: "public query parameter exceeds the bound".to_string(),
            });
        }
        let lowered = key.to_ascii_lowercase();
        if matches!(
            lowered.as_str(),
            "host"
                | "authorization"
                | "cookie"
                | "redirect_uri"
                | "code_verifier"
                | "state"
                | "code_challenge"
                | "code_challenge_method"
                | "url"
                | "authority"
        ) {
            return Err(OAuthError::InvalidIntent {
                reason: format!("{key} cannot be supplied by RSS"),
            });
        }
    }
    if intent.path.contains("://") || intent.path.contains("..") || !intent.path.starts_with('/') {
        return Err(OAuthError::PathDenied {
            path: intent.path.clone(),
        });
    }
    Ok(())
}

fn admit_path<'a>(
    policy: &'a TrustedTransportPolicy,
    path: &str,
) -> Result<&'a TrustedEndpoint, OAuthError> {
    if path.contains("://") || path.contains("..") || !path.starts_with('/') {
        return Err(OAuthError::PathDenied {
            path: path.to_string(),
        });
    }
    policy
        .endpoints
        .iter()
        .find(|endpoint| path_matches(&endpoint.path_prefix, path))
        .ok_or_else(|| OAuthError::PathDenied {
            path: path.to_string(),
        })
}

fn path_matches(prefix: &str, path: &str) -> bool {
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn admit_headers(
    policy: &TrustedTransportPolicy,
    headers: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, OAuthError> {
    let mut admitted = BTreeMap::new();
    for (name, value) in headers {
        let lowered = name.to_ascii_lowercase();
        if matches!(
            lowered.as_str(),
            "authorization" | "cookie" | "host" | "cookie2" | "proxy-authorization"
        ) {
            return Err(OAuthError::HeaderDenied { name: lowered });
        }
        if !policy
            .allowed_header_names
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&lowered))
        {
            return Err(OAuthError::HeaderDenied { name: lowered });
        }
        admitted.insert(lowered, value.clone());
    }
    Ok(admitted)
}

fn min_deadline(left: Instant, right: Instant) -> Instant {
    if left < right { left } else { right }
}

fn encode_query(query: &BTreeMap<String, String>) -> String {
    let mut parts = Vec::new();
    for (key, value) in query {
        parts.push(format!("{}={}", percent_encode(key), percent_encode(value)));
    }
    parts.join("&")
}

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn append_form(body: &mut String, key: &str, value: &str) {
    if !body.is_empty() && !body.ends_with('&') {
        body.push('&');
    }
    body.push_str(&percent_encode(key));
    body.push('=');
    body.push_str(&percent_encode(value));
}

fn parse_callback_url(url: &str) -> Result<(String, String), OAuthError> {
    if url.len() > MAX_REQUEST_BODY_BYTES {
        return Err(OAuthError::RequestTooLarge {
            max_bytes: MAX_REQUEST_BODY_BYTES,
        });
    }
    let Some((_, query)) = url.split_once('?') else {
        return Err(OAuthError::MalformedResponse {
            reason: "callback URL is missing a query".to_string(),
        });
    };
    let mut state = None;
    let mut code = None;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        match key {
            "state" => state = Some(percent_decode(value)),
            "code" => code = Some(percent_decode(value)),
            _ => {}
        }
    }
    match (state, code) {
        (Some(state), Some(code)) => Ok((state, code)),
        _ => Err(OAuthError::MalformedResponse {
            reason: "callback URL is missing state or code".to_string(),
        }),
    }
}

fn percent_decode(value: &str) -> String {
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
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn sanitize_response(
    raw: &RawHttpsResponse,
    credential_id: &str,
    policy: &TrustedTransportPolicy,
) -> Result<SanitizedProviderResponse, OAuthError> {
    if raw.body.is_empty() {
        return Ok(SanitizedProviderResponse {
            status: raw.status,
            public_headers: public_headers(&raw.headers),
            body_without_secret_fields: JsonValue::Object(JsonMap::new()),
            retry_after_ms: retry_after_ms(&raw.headers),
            access_slot: None,
            refresh_slot: None,
            device_handle: None,
            code_handle: None,
        });
    }
    let text = std::str::from_utf8(&raw.body).map_err(|_| OAuthError::MalformedResponse {
        reason: "response is not UTF-8".to_string(),
    })?;
    let parsed: JsonValue =
        serde_json::from_str(text).map_err(|_| OAuthError::MalformedResponse {
            reason: "response is not JSON".to_string(),
        })?;
    if json_depth(&parsed) > MAX_JSON_DEPTH {
        return Err(OAuthError::MalformedResponse {
            reason: "response JSON exceeds depth".to_string(),
        });
    }
    let mut access = None;
    let mut refresh = None;
    let sanitized = strip_secrets(parsed, credential_id, policy, &mut access, &mut refresh)?;
    Ok(SanitizedProviderResponse {
        status: raw.status,
        public_headers: public_headers(&raw.headers),
        body_without_secret_fields: sanitized,
        retry_after_ms: retry_after_ms(&raw.headers),
        access_slot: access,
        refresh_slot: refresh,
        device_handle: None,
        code_handle: None,
    })
}

fn strip_secrets(
    value: JsonValue,
    credential_id: &str,
    policy: &TrustedTransportPolicy,
    access: &mut Option<OpaqueSecretSlot>,
    refresh: &mut Option<OpaqueSecretSlot>,
) -> Result<JsonValue, OAuthError> {
    match value {
        JsonValue::Object(map) => {
            let mut kept = JsonMap::new();
            for (key, nested) in map {
                if secret_key(&key) {
                    if let JsonValue::String(secret) = nested {
                        mint_slot(credential_id, policy, &key, &secret, access, refresh)?;
                    }
                    continue;
                }
                kept.insert(
                    key,
                    strip_secrets(nested, credential_id, policy, access, refresh)?,
                );
            }
            Ok(JsonValue::Object(kept))
        }
        JsonValue::Array(values) => {
            let mut kept = Vec::new();
            for nested in values {
                kept.push(strip_secrets(
                    nested,
                    credential_id,
                    policy,
                    access,
                    refresh,
                )?);
            }
            Ok(JsonValue::Array(kept))
        }
        other => Ok(other),
    }
}

fn mint_slot(
    credential_id: &str,
    policy: &TrustedTransportPolicy,
    key: &str,
    secret: &str,
    access: &mut Option<OpaqueSecretSlot>,
    refresh: &mut Option<OpaqueSecretSlot>,
) -> Result<(), OAuthError> {
    let kind = if key.eq_ignore_ascii_case("access_token") {
        Some(SecretSlotKind::Access)
    } else if key.eq_ignore_ascii_case("refresh_token") {
        Some(SecretSlotKind::Refresh)
    } else {
        None
    };
    let Some(kind) = kind else {
        return Ok(());
    };
    let slot = OpaqueSecretSlot::from_host_secret_until(
        kind,
        credential_id,
        0,
        policy.generation,
        &policy.run_id,
        Zeroizing::new(secret.as_bytes().to_vec()),
        policy.deadline,
    )?;
    match kind {
        SecretSlotKind::Access => *access = Some(slot),
        SecretSlotKind::Refresh => *refresh = Some(slot),
    }
    Ok(())
}

fn secret_key(key: &str) -> bool {
    SECRET_JSON_KEYS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(key))
}

fn public_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut public = BTreeMap::new();
    for (name, value) in headers {
        let lowered = name.to_ascii_lowercase();
        if matches!(
            lowered.as_str(),
            "authorization" | "cookie" | "set-cookie" | "proxy-authorization"
        ) {
            continue;
        }
        public.insert(lowered, value.clone());
    }
    public
}

fn retry_after_ms(headers: &BTreeMap<String, String>) -> Option<u64> {
    headers.iter().find_map(|(name, value)| {
        if name.eq_ignore_ascii_case("retry-after") {
            value
                .parse::<u64>()
                .ok()
                .map(|seconds| seconds.saturating_mul(1000))
        } else {
            None
        }
    })
}

fn json_depth(value: &JsonValue) -> usize {
    match value {
        JsonValue::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        JsonValue::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

/// Scripted HTTPS transport for fixture and primitive tests.
pub struct ScriptedHttpsTransport {
    responses: Mutex<VecDeque<RawHttpsResponse>>,
    sent: Mutex<Vec<PreparedHttpsRequest>>,
}

impl ScriptedHttpsTransport {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(VecDeque::new()),
            sent: Mutex::new(Vec::new()),
        }
    }

    pub fn push_json(&self, status: u16, body: JsonValue) {
        self.push_raw(status, &body.to_string());
    }

    pub fn push_raw(&self, status: u16, body: &str) {
        self.responses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push_back(RawHttpsResponse {
                status,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: body.as_bytes().to_vec(),
            });
    }

    pub fn take_sent(&self) -> Vec<PreparedHttpsRequest> {
        std::mem::take(
            &mut *self
                .sent
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }
}

impl Default for ScriptedHttpsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl BoundedHttpsTransport for ScriptedHttpsTransport {
    fn send(&self, request: &PreparedHttpsRequest) -> Result<RawHttpsResponse, OAuthError> {
        self.sent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(request.clone());
        self.responses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .ok_or_else(|| OAuthError::Transport {
                message: "scripted transport has no queued response".to_string(),
            })
    }
}

/// Scripted one-shot callback waiter.
pub struct ScriptedCallback {
    queued: Mutex<VecDeque<RawCallbackInput>>,
}

impl ScriptedCallback {
    pub fn new() -> Self {
        Self {
            queued: Mutex::new(VecDeque::new()),
        }
    }

    pub fn push(&self, input: RawCallbackInput) {
        self.queued
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push_back(input);
    }
}

impl Default for ScriptedCallback {
    fn default() -> Self {
        Self::new()
    }
}

impl CallbackWaiter for ScriptedCallback {
    fn wait_one(&self) -> Result<RawCallbackInput, OAuthError> {
        self.queued
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .ok_or(OAuthError::CallbackTimeout)
    }

    fn inject(&self, input: RawCallbackInput) -> Result<(), OAuthError> {
        self.push(input);
        Ok(())
    }
}

/// Records browser-open attempts without executing a command policy.
pub struct ScriptedBrowser {
    opened: Mutex<Vec<String>>,
}

impl ScriptedBrowser {
    pub fn new() -> Self {
        Self {
            opened: Mutex::new(Vec::new()),
        }
    }

    pub fn opened(&self) -> Vec<String> {
        self.opened
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl Default for ScriptedBrowser {
    fn default() -> Self {
        Self::new()
    }
}

impl BrowserOpener for ScriptedBrowser {
    fn open(&self, url: &str) -> Result<(), OAuthError> {
        self.opened
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(url.to_string());
        Ok(())
    }
}

/// Deterministic clock with an explicit expire jump.
pub struct ScriptedClock {
    unix_ms: AtomicU64,
    base: Instant,
    offset: Mutex<Duration>,
}

impl ScriptedClock {
    pub fn new(unix_ms: u64) -> Self {
        Self {
            unix_ms: AtomicU64::new(unix_ms),
            base: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
        }
    }

    pub fn expire(&self) {
        *self
            .offset
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Duration::from_secs(24 * 3600);
        self.unix_ms.fetch_add(86_400_000, Ordering::Relaxed);
    }
}

impl OAuthClock for ScriptedClock {
    fn now(&self) -> Instant {
        self.base
            + *self
                .offset
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn unix_ms(&self) -> u64 {
        self.unix_ms.load(Ordering::Relaxed)
    }
}

/// Cancellation flag for primitive tests.
pub struct ScriptedCancel {
    cancelled: AtomicBool,
}

impl ScriptedCancel {
    pub fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl Default for ScriptedCancel {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuthCancel for ScriptedCancel {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}
