//! Generic OAuth primitives: PKCE session records, callback wait, and bounded
//! HTTPS transport. RSS owns flow sequencing, retry, and business errors.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

#[allow(deprecated)]
use ring::constant_time;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map as JsonMap, Value as JsonValue};
use zeroize::Zeroizing;

use crate::auth::pkce::{self, PKCE_CHALLENGE_METHOD, PkceError};
use crate::auth::request_body::{self, SecretField};
use crate::auth::store::{AuthStoreError, OpaqueRefreshHandle, OpaqueSecretSlot, SecretSlotKind};
use crate::auth::token::CredentialId;

const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024;
const MAX_EXCHANGE_CODE_BYTES: usize = 4096;
const MAX_PUBLIC_QUERY_ENTRIES: usize = 32;
const MAX_PUBLIC_QUERY_BYTES: usize = 2048;
const MAX_JSON_DEPTH: usize = 8;
const CALLBACK_TTL: Duration = Duration::from_secs(15 * 60);
/// Live PKCE/device flow ceiling, matching the opaque registry bound.
pub const MAX_LIVE_OAUTH_FLOWS: usize = 64;
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

const RESERVED_FORM_KEYS: &[&str] = &["refresh_token", "code", "code_verifier", "device_code"];

const SECRET_JSON_KEYS: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "device_code",
    "device_auth_id",
    "device_id",
    "code_verifier",
    "authorization_code",
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

/// Which root-level response field contains a native authorization code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeCodeField {
    Code,
    AuthorizationCode,
}

/// Opt-in instructions for capturing an exchange pair without exposing its bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpaqueExchangeResponseIntent {
    pub code_field: ExchangeCodeField,
    pub redirect_uri: String,
}

/// Closed native aliases for a selected device-session identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceIdField {
    DeviceCode,
    DeviceAuthId,
    DeviceId,
}

/// Closed native selection of credentials to encode in a request body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretBodyFieldSelection {
    None,
    Device { field: DeviceIdField },
    AuthorizationCode { code_field: ExchangeCodeField },
}

/// Request-body encoding and native-only field selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRequestBodyIntent {
    pub encoding: crate::auth::request_body::RequestBodyEncoding,
    pub secret_fields: SecretBodyFieldSelection,
}

/// Optional native body serialization and exchange-response capture intents.
#[derive(Clone, Default)]
pub struct NativeTransportIntents {
    pub request_body: Option<NativeRequestBodyIntent>,
    pub exchange_response: Option<OpaqueExchangeResponseIntent>,
}

impl fmt::Debug for NativeTransportIntents {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTransportIntents")
            .field("request_body", &self.request_body)
            .field("has_exchange_response", &self.exchange_response.is_some())
            .finish()
    }
}

/// Same-flow opaque handles promoted from a device response.
#[derive(Debug)]
pub struct OpaqueExchangePair {
    pub code_handle: OpaqueAuthorizationCodeHandle,
    pub verifier_handle: OpaqueVerifierHandle,
}

/// Sanitized public transport response and optional native exchange pair.
#[derive(Debug)]
pub struct OpaqueExchangeResponse {
    pub response: SanitizedProviderResponse,
    pub pair: Option<OpaqueExchangePair>,
}

struct PendingExchangePair {
    code: Zeroizing<String>,
    verifier: Zeroizing<String>,
}

struct ExchangeCaptureContext<'a> {
    intent: &'a OpaqueExchangeResponseIntent,
    device_flow: &'a Arc<FlowInner>,
    io: &'a OAuthIoContext,
}

/// Prepared HTTPS request at the host boundary. Tests may inspect it host-side.
#[derive(Clone)]
pub struct PreparedHttpsRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

impl fmt::Debug for PreparedHttpsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut headers = BTreeMap::new();
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("authorization")
                || name.eq_ignore_ascii_case("cookie")
                || name.eq_ignore_ascii_case("proxy-authorization")
            {
                headers.insert(name.clone(), "<redacted>".to_string());
            } else {
                headers.insert(name.clone(), value.clone());
            }
        }
        formatter
            .debug_struct("PreparedHttpsRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field("body", &"<redacted>")
            .finish()
    }
}

/// Raw HTTPS response before sanitization.
#[derive(Clone, Debug)]
pub struct RawHttpsResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// Native-only HTTPS response head for incremental body reads.
pub struct RawHttpsResponseHead {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
}

impl fmt::Debug for RawHttpsResponseHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawHttpsResponseHead")
            .field("status", &self.status)
            .field("headers", &"<redacted>")
            .finish()
    }
}

/// Native-only incremental reader over a bounded HTTPS response body.
pub trait BoundedHttpsStream: Send {
    fn head(&self) -> &RawHttpsResponseHead;
    fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, OAuthError>;
    fn cancel(&mut self);
}

/// Injected callback payload. State comparison stays host-side.
#[derive(Clone)]
pub enum RawCallbackInput {
    Query { state: String, code: String },
    ManualUrl(String),
    Timeout,
    Cancelled,
}

impl fmt::Debug for RawCallbackInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query { .. } => formatter.write_str("Query { <redacted> }"),
            Self::ManualUrl(_) => formatter.write_str("ManualUrl(<redacted>)"),
            Self::Timeout => formatter.write_str("Timeout"),
            Self::Cancelled => formatter.write_str("Cancelled"),
        }
    }
}

/// Per-flow native callback resource prepared before the authorization URL is opened.
pub trait PreparedCallbackSession: Send + Sync {
    fn redirect_uri(&self) -> &str;
    fn wait_one(&self, context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError>;
    fn revoke(&self);
}

/// Injected bounded HTTPS transport.
pub trait BoundedHttpsTransport: Send + Sync {
    /// Check the context at every blocking step and bound reads by its caps.
    /// A synchronous implementation cannot be preempted by this interface.
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError>;

    /// Start an incremental response read when the implementation supports it.
    fn start_stream(
        &self,
        _request: &PreparedHttpsRequest,
        _context: &OAuthIoContext,
    ) -> Result<Box<dyn BoundedHttpsStream>, OAuthError> {
        Err(OAuthError::Transport {
            message: "stream_transport_unavailable".to_string(),
        })
    }
}

/// Injected one-shot callback waiter.
pub trait CallbackWaiter: Send + Sync {
    /// Prepare an owned callback resource for one flow, if supported.
    fn prepare(
        &self,
        _mode: CallbackMode,
        _context: &OAuthIoContext,
    ) -> Result<Option<Arc<dyn PreparedCallbackSession>>, OAuthError> {
        Ok(None)
    }

    /// Bound the native wait by `remaining()` and observe cancellation while waiting.
    fn wait_one(&self, context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError>;

    fn inject(&self, input: RawCallbackInput) -> Result<(), OAuthError> {
        let _ = input;
        Err(OAuthError::Transport {
            message: "callback waiter does not accept injected input".to_string(),
        })
    }
}

/// Injected browser opener. Command policy is not implemented here.
pub trait BrowserOpener: Send + Sync {
    /// Bound each blocking browser-launch step by the context; do not detach an
    /// unbounded worker to simulate cancellation of synchronous code.
    fn open(&self, url: &str, context: &OAuthIoContext) -> Result<(), OAuthError>;
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

struct CombinedOAuthCancel {
    host: Arc<dyn OAuthCancel>,
    owner: Arc<dyn OAuthCancel>,
}

impl OAuthCancel for CombinedOAuthCancel {
    fn is_cancelled(&self) -> bool {
        self.host.is_cancelled() || self.owner.is_cancelled()
    }
}

/// Immutable host-issued I/O budget. Implementations must use its remaining
/// time and cancellation at every blocking step; the host checks again after
/// the call. The context itself does not preempt arbitrary synchronous code.
#[derive(Clone)]
pub struct OAuthIoContext {
    deadline: Instant,
    clock: Arc<dyn OAuthClock>,
    cancel: Arc<dyn OAuthCancel>,
}

impl OAuthIoContext {
    pub(crate) fn new(
        deadline: Instant,
        clock: Arc<dyn OAuthClock>,
        cancel: Arc<dyn OAuthCancel>,
    ) -> Self {
        Self {
            deadline,
            clock,
            cancel,
        }
    }

    pub(crate) fn with_additional_cancel(&self, extra: Arc<dyn OAuthCancel>) -> Self {
        Self {
            deadline: self.deadline,
            clock: Arc::clone(&self.clock),
            cancel: Arc::new(CombinedOAuthCancel {
                host: Arc::clone(&self.cancel),
                owner: extra,
            }),
        }
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn max_request_body_bytes(&self) -> usize {
        MAX_REQUEST_BODY_BYTES
    }
    pub fn max_response_body_bytes(&self) -> usize {
        MAX_RESPONSE_BODY_BYTES
    }

    pub fn check(&self) -> Result<(), OAuthError> {
        if self.cancel.is_cancelled() {
            return Err(OAuthError::Cancelled);
        }
        if self.clock.now() >= self.deadline {
            return Err(OAuthError::DeadlineExceeded);
        }
        Ok(())
    }

    pub fn remaining(&self) -> Result<Duration, OAuthError> {
        if self.cancel.is_cancelled() {
            return Err(OAuthError::Cancelled);
        }
        let now = self.clock.now();
        if now >= self.deadline {
            return Err(OAuthError::DeadlineExceeded);
        }
        Ok(self.deadline.duration_since(now))
    }
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
    policy_generation: u64,
    run_id: String,
    credential_id: String,
    expires_at: Instant,
    state: Mutex<Zeroizing<String>>,
    verifier: Mutex<Zeroizing<String>>,
    redirect_uri: String,
    prepared_callback: Option<Arc<dyn PreparedCallbackSession>>,
    callback: AtomicU8,
    callback_succeeded: AtomicBool,
    revoked: AtomicBool,
    verifier_state: AtomicU8,
    code_state: AtomicU8,
    code: Mutex<Option<Zeroizing<String>>>,
    device_code: Mutex<Zeroizing<String>>,
    device_state: AtomicU8,
    device_in_flight: AtomicBool,
}

struct DevicePollGuard<'a> {
    flag: &'a AtomicBool,
}

impl Drop for DevicePollGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

impl FlowInner {
    fn forged() -> Arc<Self> {
        Arc::new(Self {
            id: 0,
            host: Weak::new(),
            policy_generation: 0,
            run_id: "forged".to_string(),
            credential_id: "forged".to_string(),
            expires_at: Instant::now(),
            state: Mutex::new(Zeroizing::new("forged".to_string())),
            verifier: Mutex::new(Zeroizing::new(String::new())),
            redirect_uri: String::new(),
            prepared_callback: None,
            callback: AtomicU8::new(HANDLE_LIVE),
            callback_succeeded: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
            verifier_state: AtomicU8::new(HANDLE_LIVE),
            code_state: AtomicU8::new(HANDLE_LIVE),
            code: Mutex::new(None),
            device_code: Mutex::new(Zeroizing::new(String::new())),
            device_state: AtomicU8::new(HANDLE_LIVE),
            device_in_flight: AtomicBool::new(false),
        })
    }

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

    fn check_binding(
        &self,
        policy: &TrustedTransportPolicy,
        credential_id: &str,
        class: &'static str,
    ) -> Result<(), OAuthError> {
        if self.policy_generation != policy.generation
            || self.run_id != policy.run_id
            || self.credential_id != credential_id
        {
            return Err(OAuthError::HandleProvenance {
                class: class.to_string(),
            });
        }
        Ok(())
    }

    fn preview_exchange(
        &self,
        now: Instant,
    ) -> Result<(Zeroizing<String>, Zeroizing<String>), OAuthError> {
        self.check_flag(&self.code_state, CODE_HANDLE_CLASS, now)?;
        self.check_flag(&self.verifier_state, VERIFIER_HANDLE_CLASS, now)?;
        let raw_code = self
            .code
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or_else(|| OAuthError::HandleInvalid {
                class: CODE_HANDLE_CLASS.to_string(),
            })?;
        let raw_verifier = self
            .verifier
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if raw_verifier.is_empty() {
            return Err(OAuthError::HandleInvalid {
                class: VERIFIER_HANDLE_CLASS.to_string(),
            });
        }
        Ok((raw_code, raw_verifier))
    }

    fn consume_exchange(
        &self,
        now: Instant,
    ) -> Result<(Zeroizing<String>, Zeroizing<String>), OAuthError> {
        let (raw_code, raw_verifier) = self.preview_exchange(now)?;
        if self
            .code_state
            .compare_exchange(
                HANDLE_LIVE,
                HANDLE_USED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(self.class_error(CODE_HANDLE_CLASS, "handle_replayed"));
        }
        if self
            .verifier_state
            .compare_exchange(
                HANDLE_LIVE,
                HANDLE_USED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(self.class_error(VERIFIER_HANDLE_CLASS, "handle_replayed"));
        }
        if let Ok(mut code) = self.code.lock() {
            *code = None;
        }
        if let Ok(mut verifier) = self.verifier.lock() {
            verifier.clear();
        }
        Ok((raw_code, raw_verifier))
    }

    fn begin_device_poll(&self, now: Instant) -> Result<DevicePollGuard<'_>, OAuthError> {
        self.check_flag(&self.device_state, DEVICE_HANDLE_CLASS, now)?;
        if self
            .device_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(self.class_error(DEVICE_HANDLE_CLASS, "handle_replayed"));
        }
        Ok(DevicePollGuard {
            flag: &self.device_in_flight,
        })
    }

    fn device_id(&self) -> Result<Zeroizing<String>, OAuthError> {
        let device_code = self
            .device_code
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if device_code.is_empty() {
            return Err(OAuthError::HandleInvalid {
                class: DEVICE_HANDLE_CLASS.to_string(),
            });
        }
        Ok(Zeroizing::new(device_code.as_str().to_string()))
    }

    fn clear_device_code(&self) {
        if let Ok(mut device_code) = self.device_code.lock() {
            device_code.clear();
        }
    }

    fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
        self.callback.store(HANDLE_REVOKED, Ordering::Release);
        self.verifier_state.store(HANDLE_REVOKED, Ordering::Release);
        self.code_state.store(HANDLE_REVOKED, Ordering::Release);
        self.device_state.store(HANDLE_REVOKED, Ordering::Release);
        self.device_in_flight.store(false, Ordering::Release);
        if let Some(session) = &self.prepared_callback {
            session.revoke();
        }
        if let Ok(mut verifier) = self.verifier.lock() {
            verifier.clear();
        }
        if let Ok(mut code) = self.code.lock() {
            *code = None;
        }
        self.clear_device_code();
        if let Ok(mut state) = self.state.lock() {
            state.clear();
        }
    }

    fn csrf_state(&self) -> String {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_str()
            .to_string()
    }

    fn is_terminal(&self) -> bool {
        !flag_live(&self.callback)
            && !flag_live(&self.verifier_state)
            && !flag_live(&self.code_state)
            && !flag_live(&self.device_state)
    }
}

impl Drop for FlowInner {
    fn drop(&mut self) {
        if let Some(session) = &self.prepared_callback {
            session.revoke();
        }
    }
}

fn flag_live(flag: &AtomicU8) -> bool {
    flag.load(Ordering::Acquire) == HANDLE_LIVE
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
            fn flow_inner(&self) -> Arc<FlowInner> {
                Arc::clone(&self.inner)
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
    native_callbacks: bool,
    flows: Mutex<HashMap<u64, Arc<FlowInner>>>,
    next_id: AtomicU64,
}

struct PreparedCallbackGuard(Option<Arc<dyn PreparedCallbackSession>>);

impl PreparedCallbackGuard {
    fn new(session: Option<Arc<dyn PreparedCallbackSession>>) -> Self {
        Self(session)
    }

    fn disarm(&mut self) {
        self.0.take();
    }
}

impl Drop for PreparedCallbackGuard {
    fn drop(&mut self) {
        if let Some(session) = self.0.take() {
            session.revoke();
        }
    }
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
        Self::with_callbacks(transport, callbacks, browser, clock, cancel, false)
    }

    /// Construct a native callback host with private per-flow FD inputs.
    pub fn new_with_native_inputs(
        transport: Arc<dyn BoundedHttpsTransport>,
        browser: Arc<dyn BrowserOpener>,
        manual_input: Option<std::os::fd::OwnedFd>,
        clock: Arc<dyn OAuthClock>,
        cancel: Arc<dyn OAuthCancel>,
    ) -> Result<Self, OAuthError> {
        let callbacks = Arc::new(
            crate::auth::native_callback::composite::NativeCallbackInputs::new(manual_input)?,
        );
        Ok(Self::with_callbacks(
            transport, callbacks, browser, clock, cancel, true,
        ))
    }

    /// Construct an OAuth host with owned native loopback callback sessions.
    pub fn new_with_native_callbacks(
        transport: Arc<dyn BoundedHttpsTransport>,
        browser: Arc<dyn BrowserOpener>,
        clock: Arc<dyn OAuthClock>,
        cancel: Arc<dyn OAuthCancel>,
    ) -> Self {
        Self::with_callbacks(
            transport,
            Arc::new(crate::auth::native_callback::NativeLoopbackCallbacks),
            browser,
            clock,
            cancel,
            true,
        )
    }

    fn with_callbacks(
        transport: Arc<dyn BoundedHttpsTransport>,
        callbacks: Arc<dyn CallbackWaiter>,
        browser: Arc<dyn BrowserOpener>,
        clock: Arc<dyn OAuthClock>,
        cancel: Arc<dyn OAuthCancel>,
        native_callbacks: bool,
    ) -> Self {
        Self {
            inner: Arc::new(HostInner {
                transport,
                callbacks,
                browser,
                clock,
                cancel,
                native_callbacks,
                flows: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(1),
            }),
        }
    }

    /// Reports whether this host was explicitly constructed with native callbacks.
    pub fn has_native_callbacks(&self) -> bool {
        self.inner.native_callbacks
    }

    pub(crate) fn clock_now_ms(&self) -> u64 {
        self.inner.clock.unix_ms()
    }

    pub fn pkce_begin(
        &self,
        policy: &TrustedTransportPolicy,
        intent: BoundedPublicOAuthIntent,
    ) -> Result<PkceBeginEnvelope, OAuthError> {
        self.pkce_begin_inner(policy, intent, None)
    }

    pub(crate) fn pkce_begin_scoped(
        &self,
        policy: &TrustedTransportPolicy,
        intent: BoundedPublicOAuthIntent,
        owner_cancel: Arc<dyn OAuthCancel>,
    ) -> Result<PkceBeginEnvelope, OAuthError> {
        self.pkce_begin_inner(policy, intent, Some(owner_cancel))
    }

    fn pkce_begin_inner(
        &self,
        policy: &TrustedTransportPolicy,
        intent: BoundedPublicOAuthIntent,
        owner_cancel: Option<Arc<dyn OAuthCancel>>,
    ) -> Result<PkceBeginEnvelope, OAuthError> {
        if let Some(owner_cancel) = owner_cancel.as_ref() {
            self.io_context_with_cancel(policy.deadline, Arc::clone(owner_cancel))
                .check()?;
        } else {
            self.check_cancel_deadline(policy)?;
        }
        if intent.flow == OAuthFlowKind::DeviceCode {
            return Err(OAuthError::InvalidIntent {
                reason: "device_code flow does not use pkce_begin".to_string(),
            });
        }
        validate_intent(&intent)?;
        let endpoint = admit_path(policy, &intent.path)?;
        let material = pkce::generate()?;
        let (challenge, verifier, state) = material.into_parts();
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let expires_at = min_deadline(policy.deadline, self.inner.clock.now() + CALLBACK_TTL);
        let context = match owner_cancel {
            Some(owner_cancel) => self.io_context_with_cancel(expires_at, owner_cancel),
            None => self.io_context(expires_at),
        };
        context.check()?;
        let prepared_callback = self
            .inner
            .callbacks
            .prepare(intent.callback_mode, &context)?;
        let mut prepared_guard = PreparedCallbackGuard::new(prepared_callback.clone());
        context.check()?;
        if self.inner.native_callbacks && prepared_callback.is_none() {
            return Err(OAuthError::Transport {
                message: "native callback session preparation failed".to_string(),
            });
        }
        let redirect_uri = prepared_callback.as_ref().map_or_else(
            || format!("http://127.0.0.1:{}/callback", 10_000 + (id % 50_000)),
            |session| session.redirect_uri().to_string(),
        );
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
            intent.path,
            encode_query(&query)
        );
        let flow = Arc::new(FlowInner {
            id,
            host: Arc::downgrade(&self.inner),
            policy_generation: policy.generation,
            run_id: policy.run_id.clone(),
            credential_id: intent.credential_id.clone(),
            expires_at,
            state: Mutex::new(Zeroizing::new(state.as_str().to_string())),
            verifier: Mutex::new(Zeroizing::new(verifier.as_str().to_string())),
            redirect_uri: redirect_uri.clone(),
            prepared_callback: prepared_callback.clone(),
            callback: AtomicU8::new(HANDLE_LIVE),
            callback_succeeded: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
            verifier_state: AtomicU8::new(HANDLE_LIVE),
            code_state: AtomicU8::new(HANDLE_LIVE),
            code: Mutex::new(None),
            device_code: Mutex::new(Zeroizing::new(String::new())),
            device_state: AtomicU8::new(HANDLE_REVOKED),
            device_in_flight: AtomicBool::new(false),
        });
        self.insert_flow(Arc::clone(&flow))?;
        prepared_guard.disarm();
        let opened = context.check().and_then(|()| {
            if intent.callback_mode == CallbackMode::Browser {
                self.inner.browser.open(&authorization_url, &context)?;
            }
            Ok(())
        });
        let opened = context.check().and(opened);
        if let Err(error) = opened {
            self.drop_and_revoke(&flow);
            return Err(error);
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
        self.callback_wait_inner(None, handle, None)
    }

    pub(crate) fn callback_wait_scoped(
        &self,
        policy: &TrustedTransportPolicy,
        handle: &OpaqueCallbackHandle,
        owner_cancel: Arc<dyn OAuthCancel>,
    ) -> Result<CallbackEnvelope, OAuthError> {
        self.callback_wait_inner(Some(policy), handle, Some(owner_cancel))
    }

    fn callback_wait_inner(
        &self,
        policy: Option<&TrustedTransportPolicy>,
        handle: &OpaqueCallbackHandle,
        owner_cancel: Option<Arc<dyn OAuthCancel>>,
    ) -> Result<CallbackEnvelope, OAuthError> {
        let flow = self.live_flow(handle)?;
        if self.inner.cancel.is_cancelled() {
            self.drop_and_revoke(&flow);
            return Err(OAuthError::CallbackCancelled);
        }
        if flow.revoked.load(Ordering::Acquire) {
            return Err(OAuthError::HandleRevoked {
                class: CALLBACK_HANDLE_CLASS.to_string(),
            });
        }
        if let Some(policy) = policy
            && let Err(error) =
                flow.check_binding(policy, &flow.credential_id, CALLBACK_HANDLE_CLASS)
        {
            self.drop_and_revoke(&flow);
            return Err(error);
        }
        let deadline = policy.map_or(flow.expires_at, |policy| {
            min_deadline(flow.expires_at, policy.deadline)
        });
        let context = match owner_cancel {
            Some(owner_cancel) => self.io_context_with_cancel(deadline, owner_cancel),
            None => self.io_context(deadline),
        };
        if policy.is_some()
            && let Err(error) = context.check()
        {
            self.drop_and_revoke(&flow);
            return Err(callback_wait_error(error));
        }
        let now = self.inner.clock.now();
        if let Err(error) = flow.consume_flag(&flow.callback, CALLBACK_HANDLE_CLASS, now) {
            if error.code() == "handle_expired" || flow.revoked.load(Ordering::Acquire) {
                self.drop_and_revoke(&flow);
            }
            return Err(error);
        }
        let result = context.check().and_then(|()| {
            if let Some(session) = &flow.prepared_callback {
                session.wait_one(&context)
            } else {
                self.inner.callbacks.wait_one(&context)
            }
        });
        let post = context.check();
        let result = post.and(result);
        match result {
            Ok(input) => {
                let finished = self.finish_callback(&flow, input)?;
                if let Err(error) = context.check() {
                    self.drop_and_revoke(&flow);
                    return Err(callback_wait_error(error));
                }
                Ok(finished)
            }
            Err(error) => {
                self.drop_and_revoke(&flow);
                Err(callback_wait_error(error))
            }
        }
    }

    pub fn transport(
        &self,
        policy: &TrustedTransportPolicy,
        request: ProviderRequest,
        credential_use: CredentialUse,
    ) -> Result<SanitizedProviderResponse, OAuthError> {
        self.transport_inner(
            policy,
            request,
            credential_use,
            NativeTransportIntents::default(),
            None,
            None,
        )
        .map(|result| result.response)
    }

    pub fn transport_with_intents(
        &self,
        policy: &TrustedTransportPolicy,
        request: ProviderRequest,
        credential_use: CredentialUse,
        intents: NativeTransportIntents,
    ) -> Result<OpaqueExchangeResponse, OAuthError> {
        self.transport_inner(policy, request, credential_use, intents, None, None)
    }

    #[allow(dead_code)]
    pub(crate) fn transport_with_intents_scoped(
        &self,
        policy: &TrustedTransportPolicy,
        request: ProviderRequest,
        credential_use: CredentialUse,
        intents: NativeTransportIntents,
        owner_cancel: Arc<dyn OAuthCancel>,
        response_slot_generation_override: Option<u64>,
    ) -> Result<OpaqueExchangeResponse, OAuthError> {
        self.transport_inner(
            policy,
            request,
            credential_use,
            intents,
            Some(owner_cancel),
            response_slot_generation_override,
        )
    }

    pub(crate) fn transport_scoped(
        &self,
        policy: &TrustedTransportPolicy,
        request: ProviderRequest,
        credential_use: CredentialUse,
        owner_cancel: Arc<dyn OAuthCancel>,
        response_slot_generation_override: Option<u64>,
    ) -> Result<SanitizedProviderResponse, OAuthError> {
        self.transport_inner(
            policy,
            request,
            credential_use,
            NativeTransportIntents::default(),
            Some(owner_cancel),
            response_slot_generation_override,
        )
        .map(|result| result.response)
    }

    pub fn transport_exchange_pair(
        &self,
        policy: &TrustedTransportPolicy,
        request: ProviderRequest,
        device: OpaqueDeviceSessionHandle,
        intent: OpaqueExchangeResponseIntent,
    ) -> Result<OpaqueExchangeResponse, OAuthError> {
        self.transport_inner(
            policy,
            request,
            CredentialUse::Device(device),
            NativeTransportIntents {
                request_body: None,
                exchange_response: Some(intent),
            },
            None,
            None,
        )
    }

    #[allow(dead_code)]
    pub(crate) fn transport_exchange_pair_scoped(
        &self,
        policy: &TrustedTransportPolicy,
        request: ProviderRequest,
        device: OpaqueDeviceSessionHandle,
        intent: OpaqueExchangeResponseIntent,
        owner_cancel: Arc<dyn OAuthCancel>,
        response_slot_generation_override: Option<u64>,
    ) -> Result<OpaqueExchangeResponse, OAuthError> {
        self.transport_inner(
            policy,
            request,
            CredentialUse::Device(device),
            NativeTransportIntents {
                request_body: None,
                exchange_response: Some(intent),
            },
            Some(owner_cancel),
            response_slot_generation_override,
        )
    }

    fn transport_inner(
        &self,
        policy: &TrustedTransportPolicy,
        request: ProviderRequest,
        credential_use: CredentialUse,
        intents: NativeTransportIntents,
        owner_cancel: Option<Arc<dyn OAuthCancel>>,
        response_slot_generation_override: Option<u64>,
    ) -> Result<OpaqueExchangeResponse, OAuthError> {
        let request_body_intent = intents.request_body;
        let capture_intent = intents.exchange_response;
        if let Some(intent) = capture_intent.as_ref() {
            if !matches!(&credential_use, CredentialUse::Device(_)) {
                return Err(OAuthError::HandleProvenance {
                    class: DEVICE_HANDLE_CLASS.to_string(),
                });
            }
            validate_exchange_response_intent(intent)?;
        }
        if response_slot_generation_override.is_some()
            && !matches!(
                &credential_use,
                CredentialUse::AuthorizationCode { .. } | CredentialUse::Device(_)
            )
        {
            return Err(OAuthError::HandleProvenance {
                class: CODE_HANDLE_CLASS.to_string(),
            });
        }
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
        let mut headers = admit_headers(policy, &request.public_headers)?;
        let credential_id = CredentialId::new(request.credential_id.clone()).map_err(|_| {
            OAuthError::InvalidIntent {
                reason: "credential ID is invalid".to_string(),
            }
        })?;
        self.validate_credential_use(policy, credential_id.as_str(), &credential_use)?;
        if request_body_intent.is_none() {
            reject_reserved_form_keys(&request.public_body)?;
        }
        let submitted_flow = match &credential_use {
            CredentialUse::AuthorizationCode { code, .. } => Some(self.live_flow(code)?),
            CredentialUse::Device(handle) => Some(self.live_flow(handle)?),
            CredentialUse::None | CredentialUse::Access(_) | CredentialUse::Refresh(_) => None,
        };
        // Capture the flow bound before code/verifier consumption removes its
        // registry entry. A policy may outlive a callback or device session.
        let operation_deadline = submitted_flow.as_ref().map_or(policy.deadline, |flow| {
            min_deadline(policy.deadline, flow.expires_at)
        });
        let context = match owner_cancel {
            Some(owner_cancel) => self.io_context_with_cancel(operation_deadline, owner_cancel),
            None => self.io_context(operation_deadline),
        };
        if let Some(intent) = request_body_intent {
            let admission = (|| {
                validate_native_body_selection(Some(intent), &credential_use)?;
                let canonical = intent.encoding.content_type();
                match headers.get("content-type") {
                    Some(value) if value.trim().eq_ignore_ascii_case(canonical) => {
                        headers.insert("content-type".to_string(), canonical.to_string());
                    }
                    Some(_) => {
                        return Err(OAuthError::InvalidIntent {
                            reason: "selected request body content type does not match encoding"
                                .to_string(),
                        });
                    }
                    None => {
                        headers.insert("content-type".to_string(), canonical.to_string());
                    }
                }
                Ok(())
            })();
            if let Err(error) = admission {
                self.revoke_submitted_if_context_inactive(&context, submitted_flow.as_ref());
                return Err(error);
            }
        }
        if let Err(error) = context.check() {
            self.revoke_credential_use(&credential_use);
            return Err(error);
        }
        let expected_generation = response_slot_generation_override
            .unwrap_or_else(|| credential_expected_generation(&credential_use));
        let mut prepared = PreparedHttpsRequest {
            method,
            url: format!("https://{}{}", endpoint.authority, request.path),
            headers,
            body: String::new(),
        };
        let device_session = if matches!(&credential_use, CredentialUse::Device(_)) {
            submitted_flow.clone()
        } else {
            None
        };
        let mut selected_poll_guard = None;
        if matches!(
            request_body_intent.map(|intent| intent.secret_fields),
            Some(SecretBodyFieldSelection::Device { .. })
        ) {
            let flow = submitted_flow.as_ref().expect("validated device flow");
            match flow.begin_device_poll(self.inner.clock.now()) {
                Ok(guard) => selected_poll_guard = Some(guard),
                Err(error) => {
                    self.revoke_submitted_if_context_inactive(&context, submitted_flow.as_ref());
                    return Err(error);
                }
            }
        }
        let selected_body = if let Some(intent) = request_body_intent {
            let prepared_body = (|| {
                let mut fields = Vec::new();
                match intent.secret_fields {
                    SecretBodyFieldSelection::None => {}
                    SecretBodyFieldSelection::Device { field } => {
                        let flow = submitted_flow.as_ref().ok_or_else(invalid_native_body)?;
                        let value = flow.device_id()?;
                        fields.push(
                            SecretField::new(device_field_name(field), value.as_str().to_string())
                                .map_err(map_request_body_error)?,
                        );
                    }
                    SecretBodyFieldSelection::AuthorizationCode { code_field } => {
                        let flow = submitted_flow.as_ref().ok_or_else(invalid_native_body)?;
                        let (code, verifier) = flow.preview_exchange(self.inner.clock.now())?;
                        fields.push(
                            SecretField::new(exchange_code_field_name(code_field), code.as_str())
                                .map_err(map_request_body_error)?,
                        );
                        fields.push(
                            SecretField::new("code_verifier", verifier.as_str())
                                .map_err(map_request_body_error)?,
                        );
                        fields.push(
                            SecretField::new("redirect_uri", flow.redirect_uri.clone())
                                .map_err(map_request_body_error)?,
                        );
                    }
                }
                request_body::encode_injected_body(&request.public_body, intent.encoding, &fields)
                    .map_err(map_request_body_error)
            })();
            match prepared_body {
                Ok(body) => Some(body),
                Err(error) => {
                    self.revoke_submitted_if_context_inactive(&context, submitted_flow.as_ref());
                    return Err(error);
                }
            }
        } else {
            None
        };
        if let Err(error) = context.check() {
            if let Some(flow) = submitted_flow.as_ref() {
                self.drop_and_revoke(flow);
            }
            return Err(error);
        }
        let mut body = selected_body.map_or(request.public_body, |encoded| {
            encoded.as_str_for_transport().to_string()
        });
        match credential_use {
            CredentialUse::None => {}
            CredentialUse::Access(handle) => {
                let secret = handle.take_for_transport()?;
                prepared.headers.insert(
                    "authorization".to_string(),
                    format!("Bearer {}", secret.as_str()),
                );
            }
            CredentialUse::Refresh(handle) => {
                let secret = handle.take_for_transport()?;
                append_form(&mut body, "refresh_token", secret.as_str());
            }
            CredentialUse::AuthorizationCode { code, verifier } => {
                let now = self.inner.clock.now();
                let flow = self.live_flow(&code)?;
                let (raw_code, raw_verifier) = match flow.consume_exchange(now) {
                    Ok(parts) => parts,
                    Err(error) => {
                        self.drop_and_revoke(&flow);
                        return Err(error);
                    }
                };
                if request_body_intent.is_none() {
                    append_form(&mut body, "code", raw_code.as_str());
                    append_form(&mut body, "code_verifier", raw_verifier.as_str());
                    append_form(&mut body, "redirect_uri", &flow.redirect_uri);
                }
                self.drop_flow(flow.id);
                let _ = verifier;
            }
            CredentialUse::Device(_handle) => {}
        }
        let _poll_guard = if let Some(guard) = selected_poll_guard {
            Some(guard)
        } else if request_body_intent.is_none() {
            match device_session.as_ref() {
                Some(flow) => {
                    let guard = flow.begin_device_poll(self.inner.clock.now())?;
                    let device_id = flow.device_id()?;
                    append_form(&mut body, "device_code", device_id.as_str());
                    Some(guard)
                }
                None => None,
            }
        } else {
            None
        };
        prepared.body = body;
        let sent = context
            .check()
            .and_then(|()| self.inner.transport.send(&prepared, &context));
        if let Err(error) = context.check() {
            if let Some(flow) = device_session.as_ref() {
                self.drop_and_revoke(flow);
            }
            return Err(error);
        }
        let raw = match sent {
            Ok(raw) => raw,
            Err(error) => {
                if let Some(flow) = device_session.as_ref() {
                    self.drop_and_revoke(flow);
                }
                return Err(error);
            }
        };
        if raw.body.len() > MAX_RESPONSE_BODY_BYTES {
            if let Some(flow) = device_session.as_ref() {
                self.drop_and_revoke(flow);
            }
            return Err(OAuthError::ResponseTooLarge {
                max_bytes: MAX_RESPONSE_BODY_BYTES,
            });
        }
        let sanitized_result = match capture_intent.as_ref() {
            Some(intent) => {
                let Some(device_flow) = device_session.as_ref() else {
                    return Err(OAuthError::HandleInvalid {
                        class: DEVICE_HANDLE_CLASS.to_string(),
                    });
                };
                sanitize_exchange_response(
                    self,
                    &raw,
                    credential_id.as_str(),
                    policy,
                    expected_generation,
                    ExchangeCaptureContext {
                        intent,
                        device_flow,
                        io: &context,
                    },
                )
            }
            None => sanitize_response(
                self,
                &raw,
                credential_id.as_str(),
                policy,
                expected_generation,
            )
            .map(|response| (response, None)),
        };
        let (sanitized, pair) = match sanitized_result {
            Ok(response) => response,
            Err(error) => {
                if let Some(flow) = device_session.as_ref() {
                    self.drop_and_revoke(flow);
                }
                return Err(error);
            }
        };
        if let Err(error) = context.check() {
            if let Some(flow) = device_session.as_ref() {
                self.drop_and_revoke(flow);
            }
            if let Some(handle) = sanitized.device_handle.as_ref()
                && let Ok(flow) = self.live_flow(handle)
            {
                self.drop_and_revoke(&flow);
            }
            if let Some(pair) = pair.as_ref() {
                self.drop_and_revoke(&pair.code_handle.flow_inner());
            }
            return Err(error);
        }
        if pair.is_none() {
            match device_session.as_ref() {
                Some(flow)
                    if sanitized.access_slot.is_some() || sanitized.refresh_slot.is_some() =>
                {
                    if let Err(error) = flow.consume_flag(
                        &flow.device_state,
                        DEVICE_HANDLE_CLASS,
                        self.inner.clock.now(),
                    ) {
                        self.drop_and_revoke(flow);
                        return Err(error);
                    }
                    flow.clear_device_code();
                    self.drop_flow(flow.id);
                }
                _ => {}
            }
        }
        Ok(OpaqueExchangeResponse {
            response: sanitized,
            pair,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn exchange_pair_matches_binding(
        &self,
        code: &OpaqueAuthorizationCodeHandle,
        verifier: &OpaqueVerifierHandle,
        policy_generation: u64,
        run_id: &str,
        credential_id: &str,
    ) -> bool {
        code.same_host(&self.inner)
            && verifier.same_host(&self.inner)
            && Arc::ptr_eq(&code.inner, &verifier.inner)
            && code.inner.policy_generation == policy_generation
            && code.inner.run_id == run_id
            && code.inner.credential_id == credential_id
    }

    #[allow(dead_code)]
    pub(crate) fn exchange_pair_live(
        &self,
        code: &OpaqueAuthorizationCodeHandle,
        verifier: &OpaqueVerifierHandle,
        policy_generation: u64,
        run_id: &str,
        credential_id: &str,
    ) -> bool {
        if !self.exchange_pair_matches_binding(
            code,
            verifier,
            policy_generation,
            run_id,
            credential_id,
        ) {
            return false;
        }
        let flow = &code.inner;
        if self.inner.clock.now() >= flow.expires_at
            || flow.revoked.load(Ordering::Acquire)
            || flow.code_state.load(Ordering::Acquire) != HANDLE_LIVE
            || flow.verifier_state.load(Ordering::Acquire) != HANDLE_LIVE
            || flow
                .code
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                .is_none_or(|value| value.is_empty())
            || flow
                .verifier
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
        {
            return false;
        }
        self.lock_flows()
            .get(&flow.id)
            .is_some_and(|registered| Arc::ptr_eq(registered, flow))
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
                state: flow.csrf_state(),
                code: code.to_string(),
            },
        )
    }

    pub(crate) fn revoke_callback_flow(
        &self,
        handle: &OpaqueCallbackHandle,
    ) -> Result<(), OAuthError> {
        let flow = self.live_flow(handle)?;
        self.drop_and_revoke(&flow);
        Ok(())
    }

    pub(crate) fn callback_result_live(&self, handle: &OpaqueCallbackHandle) -> bool {
        let Ok(flow) = self.live_flow(handle) else {
            return false;
        };
        let now = self.inner.clock.now();
        flow.callback_succeeded.load(Ordering::Acquire)
            && !flow.revoked.load(Ordering::Acquire)
            && flow
                .check_flag(&flow.code_state, CODE_HANDLE_CLASS, now)
                .is_ok()
            && flow
                .check_flag(&flow.verifier_state, VERIFIER_HANDLE_CLASS, now)
                .is_ok()
    }

    pub(crate) fn close_callback_resource(
        &self,
        handle: &OpaqueCallbackHandle,
    ) -> Result<(), OAuthError> {
        let flow = self.live_flow(handle)?;
        if !self.callback_result_live(handle) {
            self.drop_and_revoke(&flow);
        }
        Ok(())
    }

    pub(crate) fn close_verifier_resource(
        &self,
        handle: &OpaqueVerifierHandle,
    ) -> Result<(), OAuthError> {
        let flow = self.live_flow(handle)?;
        self.drop_and_revoke(&flow);
        Ok(())
    }

    pub(crate) fn close_code_resource(
        &self,
        handle: &OpaqueAuthorizationCodeHandle,
    ) -> Result<(), OAuthError> {
        let flow = self.live_flow(handle)?;
        self.drop_and_revoke(&flow);
        Ok(())
    }

    pub(crate) fn revoke_run(&self, run_id: &str) {
        let mut flows = self.lock_flows();
        flows.retain(|_, flow| {
            if flow.run_id == run_id {
                flow.revoke();
                false
            } else {
                true
            }
        });
    }

    #[cfg(any(test, feature = "config-fixture"))]
    pub(crate) fn live_flow_count(&self) -> usize {
        let mut flows = self.lock_flows();
        self.sweep_locked(&mut flows);
        flows.len()
    }

    pub fn forged_callback_handle(&self) -> OpaqueCallbackHandle {
        OpaqueCallbackHandle::from_inner(FlowInner::forged())
    }

    pub fn forged_code_handle(&self) -> OpaqueAuthorizationCodeHandle {
        OpaqueAuthorizationCodeHandle::from_inner(FlowInner::forged())
    }

    pub fn forged_verifier_handle(&self) -> OpaqueVerifierHandle {
        OpaqueVerifierHandle::from_inner(FlowInner::forged())
    }

    pub fn forged_device_handle(&self) -> OpaqueDeviceSessionHandle {
        OpaqueDeviceSessionHandle::from_inner(FlowInner::forged())
    }

    fn validate_credential_use(
        &self,
        policy: &TrustedTransportPolicy,
        credential_id: &str,
        credential_use: &CredentialUse,
    ) -> Result<(), OAuthError> {
        let now = self.inner.clock.now();
        match credential_use {
            CredentialUse::None => Ok(()),
            CredentialUse::Access(handle) => handle
                .validate_binding(
                    credential_id,
                    handle.generation(),
                    policy.generation,
                    policy.run_id.as_str(),
                )
                .map_err(OAuthError::from),
            CredentialUse::Refresh(handle) => handle
                .validate_binding(
                    credential_id,
                    handle.generation(),
                    policy.generation,
                    policy.run_id.as_str(),
                )
                .map_err(OAuthError::from),
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
                let flow = self.live_flow(code)?;
                flow.check_binding(policy, credential_id, CODE_HANDLE_CLASS)?;
                flow.check_flag(&flow.code_state, CODE_HANDLE_CLASS, now)?;
                flow.check_flag(&flow.verifier_state, VERIFIER_HANDLE_CLASS, now)?;
                Ok(())
            }
            CredentialUse::Device(handle) => {
                if !handle.same_host(&self.inner) {
                    return Err(OAuthError::HandleInvalid {
                        class: DEVICE_HANDLE_CLASS.to_string(),
                    });
                }
                let flow = self.live_flow(handle)?;
                flow.check_binding(policy, credential_id, DEVICE_HANDLE_CLASS)?;
                flow.check_flag(&flow.device_state, DEVICE_HANDLE_CLASS, now)?;
                Ok(())
            }
        }
    }

    fn revoke_credential_use(&self, credential_use: &CredentialUse) {
        match credential_use {
            CredentialUse::AuthorizationCode { code, .. } => {
                if let Ok(flow) = self.live_flow(code) {
                    self.drop_and_revoke(&flow);
                }
            }
            CredentialUse::Device(handle) => {
                if let Ok(flow) = self.live_flow(handle) {
                    self.drop_and_revoke(&flow);
                }
            }
            CredentialUse::None | CredentialUse::Access(_) | CredentialUse::Refresh(_) => {}
        }
    }

    fn revoke_submitted_if_context_inactive(
        &self,
        context: &OAuthIoContext,
        submitted_flow: Option<&Arc<FlowInner>>,
    ) {
        if context.check().is_err()
            && let Some(flow) = submitted_flow
        {
            self.drop_and_revoke(flow);
        }
    }

    fn mint_device_session(
        &self,
        policy: &TrustedTransportPolicy,
        credential_id: &str,
        device_id: &str,
    ) -> Result<OpaqueDeviceSessionHandle, OAuthError> {
        if device_id.is_empty() || device_id.len() > MAX_REQUEST_BODY_BYTES {
            return Err(OAuthError::MalformedResponse {
                reason: "device identifier is outside the bounded range".to_string(),
            });
        }
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let expires_at = min_deadline(policy.deadline, self.inner.clock.now() + CALLBACK_TTL);
        let flow = Arc::new(FlowInner {
            id,
            host: Arc::downgrade(&self.inner),
            policy_generation: policy.generation,
            run_id: policy.run_id.clone(),
            credential_id: credential_id.to_string(),
            expires_at,
            state: Mutex::new(Zeroizing::new(String::new())),
            verifier: Mutex::new(Zeroizing::new(String::new())),
            redirect_uri: String::new(),
            prepared_callback: None,
            callback: AtomicU8::new(HANDLE_REVOKED),
            callback_succeeded: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
            verifier_state: AtomicU8::new(HANDLE_REVOKED),
            code_state: AtomicU8::new(HANDLE_REVOKED),
            code: Mutex::new(None),
            device_code: Mutex::new(Zeroizing::new(device_id.to_string())),
            device_state: AtomicU8::new(HANDLE_LIVE),
            device_in_flight: AtomicBool::new(false),
        });
        self.insert_flow(Arc::clone(&flow))?;
        Ok(OpaqueDeviceSessionHandle::from_inner(flow))
    }

    fn promote_device_session(
        &self,
        device_flow: &Arc<FlowInner>,
        policy: &TrustedTransportPolicy,
        redirect_uri: &str,
        code: Zeroizing<String>,
        verifier: Zeroizing<String>,
        context: &OAuthIoContext,
    ) -> Result<OpaqueExchangePair, OAuthError> {
        if let Err(error) = context.check() {
            self.drop_and_revoke(device_flow);
            return Err(error);
        }
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let exchange_flow = Arc::new(FlowInner {
            id,
            host: Arc::downgrade(&self.inner),
            policy_generation: device_flow.policy_generation,
            run_id: device_flow.run_id.clone(),
            credential_id: device_flow.credential_id.clone(),
            expires_at: min_deadline(device_flow.expires_at, policy.deadline),
            state: Mutex::new(Zeroizing::new(String::new())),
            verifier: Mutex::new(verifier),
            redirect_uri: redirect_uri.to_string(),
            prepared_callback: None,
            callback: AtomicU8::new(HANDLE_REVOKED),
            callback_succeeded: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
            verifier_state: AtomicU8::new(HANDLE_LIVE),
            code_state: AtomicU8::new(HANDLE_LIVE),
            code: Mutex::new(Some(code)),
            device_code: Mutex::new(Zeroizing::new(String::new())),
            device_state: AtomicU8::new(HANDLE_REVOKED),
            device_in_flight: AtomicBool::new(false),
        });
        let publication = {
            let mut flows = self.lock_flows();
            self.sweep_locked(&mut flows);
            let source_is_registered = flows
                .get(&device_flow.id)
                .is_some_and(|registered| Arc::ptr_eq(registered, device_flow));
            if !source_is_registered
                || device_flow.revoked.load(Ordering::Acquire)
                || device_flow.device_state.load(Ordering::Acquire) != HANDLE_LIVE
            {
                Err(OAuthError::HandleRevoked {
                    class: DEVICE_HANDLE_CLASS.to_string(),
                })
            } else if let Err(error) = context.check() {
                Err(error)
            } else {
                device_flow.revoke();
                flows.remove(&device_flow.id);
                flows.insert(exchange_flow.id, Arc::clone(&exchange_flow));
                match context.check() {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        flows.remove(&exchange_flow.id);
                        Err(error)
                    }
                }
            }
        };
        if let Err(error) = publication {
            self.drop_and_revoke(device_flow);
            self.drop_and_revoke(&exchange_flow);
            return Err(error);
        }
        Ok(OpaqueExchangePair {
            code_handle: OpaqueAuthorizationCodeHandle::from_inner(Arc::clone(&exchange_flow)),
            verifier_handle: OpaqueVerifierHandle::from_inner(exchange_flow),
        })
    }

    /// RSS-owned terminal action. Host revokes and drops without interpreting
    /// provider error strings.
    pub fn terminal(&self, handle: &OpaqueDeviceSessionHandle) -> Result<(), OAuthError> {
        let flow = self.live_flow(handle)?;
        self.drop_and_revoke(&flow);
        Ok(())
    }

    pub(crate) fn device_session_matches_binding(
        &self,
        handle: &OpaqueDeviceSessionHandle,
        policy_generation: u64,
        run_id: &str,
        credential_id: &str,
    ) -> bool {
        if !handle.same_host(&self.inner) {
            return false;
        }
        let Ok(flow) = self.live_flow(handle) else {
            return false;
        };
        flow.policy_generation == policy_generation
            && flow.run_id == run_id
            && flow.credential_id == credential_id
    }

    pub(crate) fn device_session_live(
        &self,
        handle: &OpaqueDeviceSessionHandle,
        policy_generation: u64,
        run_id: &str,
        credential_id: &str,
    ) -> bool {
        if !self.device_session_matches_binding(handle, policy_generation, run_id, credential_id) {
            return false;
        }
        let Ok(flow) = self.live_flow(handle) else {
            return false;
        };
        if flow
            .check_flag(
                &flow.device_state,
                DEVICE_HANDLE_CLASS,
                self.inner.clock.now(),
            )
            .is_err()
            || flow
                .device_code
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
        {
            return false;
        }
        self.lock_flows()
            .get(&flow.id)
            .is_some_and(|registered| Arc::ptr_eq(registered, &flow))
    }

    /// Fixture wait primitive. Checks cancel; does not busy-poll.
    /// Production sleep belongs to Task 4.
    pub fn wait_ms(&self, _millis: u64) -> Result<(), OAuthError> {
        if self.inner.cancel.is_cancelled() {
            return Err(OAuthError::Cancelled);
        }
        Ok(())
    }

    fn finish_callback(
        &self,
        flow: &Arc<FlowInner>,
        input: RawCallbackInput,
    ) -> Result<CallbackEnvelope, OAuthError> {
        if flow.revoked.load(Ordering::Acquire) {
            return Err(OAuthError::HandleRevoked {
                class: CALLBACK_HANDLE_CLASS.to_string(),
            });
        }
        let now = self.inner.clock.now();
        if self.inner.cancel.is_cancelled() {
            self.drop_and_revoke(flow);
            return Err(OAuthError::CallbackCancelled);
        }
        if now >= flow.expires_at {
            self.drop_and_revoke(flow);
            return Err(OAuthError::CallbackTimeout);
        }
        let (state, code) = match input {
            RawCallbackInput::Timeout => {
                self.drop_and_revoke(flow);
                return Err(OAuthError::CallbackTimeout);
            }
            RawCallbackInput::Cancelled => {
                self.drop_and_revoke(flow);
                return Err(OAuthError::CallbackCancelled);
            }
            RawCallbackInput::Query { state, code } => (state, code),
            RawCallbackInput::ManualUrl(url) => match parse_callback_url(&url) {
                Ok(parts) => parts,
                Err(error) => {
                    self.drop_and_revoke(flow);
                    return Err(error);
                }
            },
        };
        if code.len() > MAX_REQUEST_BODY_BYTES || state.len() > MAX_PUBLIC_QUERY_BYTES {
            self.drop_and_revoke(flow);
            return Err(OAuthError::RequestTooLarge {
                max_bytes: MAX_REQUEST_BODY_BYTES,
            });
        }
        if !state_matches(&state, &flow.csrf_state()) {
            self.drop_and_revoke(flow);
            return Err(OAuthError::StateMismatch);
        }
        flow.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        *flow
            .code
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Zeroizing::new(code));
        flow.callback_succeeded.store(true, Ordering::Release);
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
        Ok(handle.flow_inner())
    }

    fn insert_flow(&self, flow: Arc<FlowInner>) -> Result<(), OAuthError> {
        let mut flows = self.lock_flows();
        self.sweep_locked(&mut flows);
        if flows.len() >= MAX_LIVE_OAUTH_FLOWS {
            drop(flows);
            flow.revoke();
            return Err(OAuthError::InvalidIntent {
                reason: "live oauth flow limit reached".to_string(),
            });
        }
        flows.insert(flow.id, flow);
        Ok(())
    }

    fn drop_flow(&self, id: u64) {
        self.lock_flows().remove(&id);
    }

    fn drop_and_revoke(&self, flow: &Arc<FlowInner>) {
        flow.revoke();
        self.drop_flow(flow.id);
    }

    fn lock_flows(&self) -> MutexGuard<'_, HashMap<u64, Arc<FlowInner>>> {
        self.inner
            .flows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn sweep_locked(&self, flows: &mut HashMap<u64, Arc<FlowInner>>) {
        let now = self.inner.clock.now();
        flows.retain(|_, flow| {
            if now >= flow.expires_at || flow.is_terminal() {
                flow.revoke();
                false
            } else {
                true
            }
        });
    }

    fn check_cancel_deadline(&self, policy: &TrustedTransportPolicy) -> Result<(), OAuthError> {
        self.io_context(policy.deadline).check()
    }

    fn io_context(&self, deadline: Instant) -> OAuthIoContext {
        OAuthIoContext::new(
            deadline,
            Arc::clone(&self.inner.clock),
            Arc::clone(&self.inner.cancel),
        )
    }

    fn io_context_with_cancel(
        &self,
        deadline: Instant,
        owner_cancel: Arc<dyn OAuthCancel>,
    ) -> OAuthIoContext {
        OAuthIoContext::new(
            deadline,
            Arc::clone(&self.inner.clock),
            Arc::new(CombinedOAuthCancel {
                host: Arc::clone(&self.inner.cancel),
                owner: owner_cancel,
            }),
        )
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
    #[allow(dead_code)]
    fn flow_id(&self) -> u64;
    fn same_host(&self, host: &Arc<HostInner>) -> bool;
    fn flow_inner(&self) -> Arc<FlowInner>;
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
    fn flow_inner(&self) -> Arc<FlowInner> {
        self.flow_inner()
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
    fn flow_inner(&self) -> Arc<FlowInner> {
        self.flow_inner()
    }
}

impl FlowHandle for OpaqueVerifierHandle {
    fn class(&self) -> &'static str {
        VERIFIER_HANDLE_CLASS
    }
    fn flow_id(&self) -> u64 {
        self.flow_id()
    }
    fn same_host(&self, host: &Arc<HostInner>) -> bool {
        self.same_host(host)
    }
    fn flow_inner(&self) -> Arc<FlowInner> {
        self.flow_inner()
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
    fn flow_inner(&self) -> Arc<FlowInner> {
        self.flow_inner()
    }
}

fn validate_native_body_selection(
    intent: Option<NativeRequestBodyIntent>,
    credential_use: &CredentialUse,
) -> Result<(), OAuthError> {
    let Some(intent) = intent else {
        return Ok(());
    };
    let matches = match intent.secret_fields {
        SecretBodyFieldSelection::None => {
            matches!(
                credential_use,
                CredentialUse::None | CredentialUse::Access(_)
            )
        }
        SecretBodyFieldSelection::Device { .. } => {
            matches!(credential_use, CredentialUse::Device(_))
        }
        SecretBodyFieldSelection::AuthorizationCode { .. } => {
            matches!(credential_use, CredentialUse::AuthorizationCode { .. })
        }
    };
    if matches {
        Ok(())
    } else {
        Err(OAuthError::InvalidIntent {
            reason: "selected request body does not match credential use".to_string(),
        })
    }
}

fn device_field_name(field: DeviceIdField) -> &'static str {
    match field {
        DeviceIdField::DeviceCode => "device_code",
        DeviceIdField::DeviceAuthId => "device_auth_id",
        DeviceIdField::DeviceId => "device_id",
    }
}

fn exchange_code_field_name(field: ExchangeCodeField) -> &'static str {
    match field {
        ExchangeCodeField::Code => "code",
        ExchangeCodeField::AuthorizationCode => "authorization_code",
    }
}

fn invalid_native_body() -> OAuthError {
    OAuthError::InvalidIntent {
        reason: "selected request body is invalid".to_string(),
    }
}

fn map_request_body_error(error: request_body::RequestBodyError) -> OAuthError {
    match error {
        request_body::RequestBodyError::InputTooLarge
        | request_body::RequestBodyError::OutputTooLarge => OAuthError::RequestTooLarge {
            max_bytes: MAX_REQUEST_BODY_BYTES,
        },
        _ => invalid_native_body(),
    }
}

fn validate_exchange_response_intent(
    intent: &OpaqueExchangeResponseIntent,
) -> Result<(), OAuthError> {
    let uri = intent.redirect_uri.as_str();
    let invalid = || OAuthError::InvalidIntent {
        reason: "redirect URI is not an admitted absolute URI".to_string(),
    };
    if uri.is_empty() || uri.len() > 2048 || uri.chars().any(char::is_control) {
        return Err(invalid());
    }
    let Some((raw_scheme, after_scheme)) = uri.split_once("://") else {
        return Err(invalid());
    };
    if !(raw_scheme.eq_ignore_ascii_case("https") || raw_scheme.eq_ignore_ascii_case("http"))
        || uri.contains('\\')
    {
        return Err(invalid());
    }
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let raw_authority = &after_scheme[..authority_end];
    if raw_authority.is_empty() || raw_authority.contains('@') {
        return Err(invalid());
    }

    let parsed = url::Url::parse(uri).map_err(|_| invalid())?;
    if !raw_scheme.eq_ignore_ascii_case(parsed.scheme())
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid());
    }
    match parsed.scheme() {
        "https" if parsed.host_str().is_some() => Ok(()),
        "http" => {
            let loopback = parsed.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            });
            if loopback && parsed.port().is_some() {
                Ok(())
            } else {
                Err(invalid())
            }
        }
        _ => Err(invalid()),
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

fn callback_wait_error(error: OAuthError) -> OAuthError {
    match error {
        OAuthError::Cancelled => OAuthError::CallbackCancelled,
        OAuthError::DeadlineExceeded => OAuthError::CallbackTimeout,
        other => other,
    }
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

fn reject_reserved_form_keys(body: &str) -> Result<(), OAuthError> {
    if body.is_empty() {
        return Ok(());
    }
    for pair in body.split('&') {
        let raw_key = pair.split('=').next().unwrap_or("");
        if reserved_form_key(&decode_form_key(raw_key)) {
            return Err(OAuthError::InvalidIntent {
                reason: "public body must not include host-owned form keys".to_string(),
            });
        }
    }
    Ok(())
}

fn decode_form_key(raw: &str) -> String {
    percent_decode(&raw.replace('+', " "))
}

fn reserved_form_key(key: &str) -> bool {
    RESERVED_FORM_KEYS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(key))
}

#[allow(deprecated)]
fn state_matches(left: &str, right: &str) -> bool {
    constant_time::verify_slices_are_equal(left.as_bytes(), right.as_bytes()).is_ok()
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

struct StrictJsonSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = JsonValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_JSON_DEPTH {
            return Err(<D::Error as serde::de::Error>::custom(
                "response JSON exceeds depth",
            ));
        }
        deserializer.deserialize_any(StrictJsonVisitor { depth: self.depth })
    }
}

struct StrictJsonVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(JsonValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(JsonValue::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(JsonValue::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(JsonValue::String(value))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(JsonValue::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictJsonSeed {
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(JsonValue::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = JsonMap::new();
        let mut seen = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(<A::Error as serde::de::Error>::custom(
                    "response JSON contains a duplicate object key",
                ));
            }
            let value = object.next_value_seed(StrictJsonSeed {
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(JsonValue::Object(values))
    }
}

fn parse_strict_json(text: &str) -> Result<JsonValue, OAuthError> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let parsed = StrictJsonSeed { depth: 1 }
        .deserialize(&mut deserializer)
        .map_err(|error| OAuthError::MalformedResponse {
            reason: error.to_string(),
        })?;
    deserializer
        .end()
        .map_err(|error| OAuthError::MalformedResponse {
            reason: error.to_string(),
        })?;
    Ok(parsed)
}

fn sanitize_response(
    host: &OAuthHost,
    raw: &RawHttpsResponse,
    credential_id: &str,
    policy: &TrustedTransportPolicy,
    expected_generation: u64,
) -> Result<SanitizedProviderResponse, OAuthError> {
    if raw.body.is_empty() {
        return Ok(empty_sanitized_response(raw));
    }
    let text = std::str::from_utf8(&raw.body).map_err(|_| OAuthError::MalformedResponse {
        reason: "response is not UTF-8".to_string(),
    })?;
    let parsed = parse_strict_json(text)?;
    if json_depth(&parsed) > MAX_JSON_DEPTH {
        return Err(OAuthError::MalformedResponse {
            reason: "response JSON exceeds depth".to_string(),
        });
    }
    sanitize_parsed_response(
        host,
        raw,
        parsed,
        credential_id,
        policy,
        expected_generation,
    )
}

fn sanitize_exchange_response(
    host: &OAuthHost,
    raw: &RawHttpsResponse,
    credential_id: &str,
    policy: &TrustedTransportPolicy,
    expected_generation: u64,
    capture: ExchangeCaptureContext<'_>,
) -> Result<(SanitizedProviderResponse, Option<OpaqueExchangePair>), OAuthError> {
    if raw.body.is_empty() {
        return Ok((empty_sanitized_response(raw), None));
    }
    let text = std::str::from_utf8(&raw.body).map_err(|_| OAuthError::MalformedResponse {
        reason: "response is not UTF-8".to_string(),
    })?;
    let mut parsed = parse_strict_json(text)?;
    let pending_pair = if (200..300).contains(&raw.status) {
        take_exchange_pair(&mut parsed, capture.intent.code_field)?
    } else {
        None
    };
    if pending_pair.is_some() && contains_new_exchange_controls(&parsed) {
        return Err(OAuthError::MalformedResponse {
            reason: "exchange response combined a pair with newly issued credentials".to_string(),
        });
    }
    let response = sanitize_parsed_response(
        host,
        raw,
        parsed,
        credential_id,
        policy,
        expected_generation,
    )?;
    let pair = match pending_pair {
        Some(pair) => Some(host.promote_device_session(
            capture.device_flow,
            policy,
            &capture.intent.redirect_uri,
            pair.code,
            pair.verifier,
            capture.io,
        )?),
        None => None,
    };
    Ok((response, pair))
}

fn empty_sanitized_response(raw: &RawHttpsResponse) -> SanitizedProviderResponse {
    SanitizedProviderResponse {
        status: raw.status,
        public_headers: public_headers(&raw.headers),
        body_without_secret_fields: JsonValue::Object(JsonMap::new()),
        retry_after_ms: retry_after_ms(&raw.headers),
        access_slot: None,
        refresh_slot: None,
        device_handle: None,
        code_handle: None,
    }
}

fn sanitize_parsed_response(
    host: &OAuthHost,
    raw: &RawHttpsResponse,
    parsed: JsonValue,
    credential_id: &str,
    policy: &TrustedTransportPolicy,
    expected_generation: u64,
) -> Result<SanitizedProviderResponse, OAuthError> {
    let mut sink = SecretSink {
        access: None,
        refresh: None,
        device_id: None,
        expected_generation,
    };
    let sanitized = strip_secrets(parsed, credential_id, policy, &mut sink)?;
    let device_handle = match sink.device_id {
        Some(device_id) => Some(host.mint_device_session(policy, credential_id, &device_id)?),
        None => None,
    };
    Ok(SanitizedProviderResponse {
        status: raw.status,
        public_headers: public_headers(&raw.headers),
        body_without_secret_fields: sanitized,
        retry_after_ms: retry_after_ms(&raw.headers),
        access_slot: sink.access,
        refresh_slot: sink.refresh,
        device_handle,
        code_handle: None,
    })
}

fn take_exchange_pair(
    value: &mut JsonValue,
    code_field: ExchangeCodeField,
) -> Result<Option<PendingExchangePair>, OAuthError> {
    let Some(object) = value.as_object_mut() else {
        return Ok(None);
    };
    let code_keys = object
        .keys()
        .filter(|key| key.eq_ignore_ascii_case("code"))
        .cloned()
        .collect::<Vec<_>>();
    let authorization_code_keys = object
        .keys()
        .filter(|key| key.eq_ignore_ascii_case("authorization_code"))
        .cloned()
        .collect::<Vec<_>>();
    let verifier_keys = object
        .keys()
        .filter(|key| key.eq_ignore_ascii_case("code_verifier"))
        .cloned()
        .collect::<Vec<_>>();
    let malformed = || OAuthError::MalformedResponse {
        reason: "exchange response contains ambiguous or invalid controls".to_string(),
    };
    if code_keys.len() > 1
        || authorization_code_keys.len() > 1
        || verifier_keys.len() > 1
        || (!code_keys.is_empty() && !authorization_code_keys.is_empty())
    {
        return Err(malformed());
    }
    let selected_code_key = match code_field {
        ExchangeCodeField::Code => code_keys.first(),
        ExchangeCodeField::AuthorizationCode => authorization_code_keys.first(),
    };
    let has_any_code = !code_keys.is_empty() || !authorization_code_keys.is_empty();
    let verifier_key = verifier_keys.first();
    if selected_code_key.is_none() && verifier_key.is_none() && !has_any_code {
        return Ok(None);
    }
    let (Some(code_key), Some(verifier_key)) = (selected_code_key, verifier_key) else {
        return Err(malformed());
    };
    let code = match object.remove(code_key) {
        Some(JsonValue::String(code)) => Zeroizing::new(code),
        _ => return Err(malformed()),
    };
    let verifier = match object.remove(verifier_key) {
        Some(JsonValue::String(verifier)) => Zeroizing::new(verifier),
        _ => return Err(malformed()),
    };
    if code.is_empty()
        || code.len() > MAX_EXCHANGE_CODE_BYTES
        || code.chars().any(char::is_control)
        || !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(malformed());
    }
    Ok(Some(PendingExchangePair { code, verifier }))
}

fn contains_new_exchange_controls(value: &JsonValue) -> bool {
    match value {
        JsonValue::Object(object) => {
            object.keys().any(|key| {
                matches!(
                    key.to_ascii_lowercase().as_str(),
                    "access_token"
                        | "refresh_token"
                        | "device_code"
                        | "device_id"
                        | "device_auth_id"
                )
            }) || object.values().any(contains_new_exchange_controls)
        }
        JsonValue::Array(values) => values.iter().any(contains_new_exchange_controls),
        _ => false,
    }
}

struct SecretSink {
    access: Option<OpaqueSecretSlot>,
    refresh: Option<OpaqueSecretSlot>,
    device_id: Option<String>,
    expected_generation: u64,
}

fn strip_secrets(
    value: JsonValue,
    credential_id: &str,
    policy: &TrustedTransportPolicy,
    sink: &mut SecretSink,
) -> Result<JsonValue, OAuthError> {
    match value {
        JsonValue::Object(map) => {
            let mut kept = JsonMap::new();
            for (key, nested) in map {
                if secret_key(&key) {
                    if let JsonValue::String(secret) = nested {
                        if device_secret_key(&key) {
                            if sink.device_id.is_none() {
                                sink.device_id = Some(secret);
                            }
                        } else {
                            mint_slot(credential_id, policy, sink, &key, &secret)?;
                        }
                    }
                    continue;
                }
                kept.insert(key, strip_secrets(nested, credential_id, policy, sink)?);
            }
            Ok(JsonValue::Object(kept))
        }
        JsonValue::Array(values) => {
            let mut kept = Vec::new();
            for nested in values {
                kept.push(strip_secrets(nested, credential_id, policy, sink)?);
            }
            Ok(JsonValue::Array(kept))
        }
        other => Ok(other),
    }
}

fn mint_slot(
    credential_id: &str,
    policy: &TrustedTransportPolicy,
    sink: &mut SecretSink,
    key: &str,
    secret: &str,
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
        sink.expected_generation,
        policy.generation,
        &policy.run_id,
        Zeroizing::new(secret.as_bytes().to_vec()),
        policy.deadline,
    )?;
    match kind {
        SecretSlotKind::Access => sink.access = Some(slot),
        SecretSlotKind::Refresh => sink.refresh = Some(slot),
    }
    Ok(())
}

fn credential_expected_generation(credential_use: &CredentialUse) -> u64 {
    match credential_use {
        CredentialUse::Access(handle) => handle.generation(),
        CredentialUse::Refresh(handle) => handle.generation(),
        CredentialUse::None
        | CredentialUse::AuthorizationCode { .. }
        | CredentialUse::Device(_) => 0,
    }
}

fn secret_key(key: &str) -> bool {
    SECRET_JSON_KEYS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(key))
}

fn device_secret_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "device_code" | "device_id" | "device_auth_id"
    )
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
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        context.check()?;
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
    fn wait_one(&self, context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
        context.check()?;
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
    fn open(&self, url: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
        context.check()?;
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

#[cfg(test)]
mod exchange_pair_binding_tests {
    use super::*;

    fn policy() -> TrustedTransportPolicy {
        TrustedTransportPolicy {
            generation: 41,
            run_id: "pair-binding-native-test".to_string(),
            deadline: Instant::now() + Duration::from_secs(120),
            endpoints: vec![TrustedEndpoint {
                authority: "auth.example.test".to_string(),
                path_prefix: "/oauth".to_string(),
            }],
            allowed_header_names: BTreeSet::new(),
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

    fn start_device(
        host: &OAuthHost,
        transport: &ScriptedHttpsTransport,
        policy: &TrustedTransportPolicy,
    ) -> OpaqueDeviceSessionHandle {
        transport.push_json(
            200,
            serde_json::json!({
                "device_code": "PAIR_BINDING_DEVICE_MARKER",
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
    ) -> OpaqueExchangePair {
        let device = start_device(host, transport, policy);
        transport.push_json(
            200,
            serde_json::json!({
                "authorization_code": "PAIR_BINDING_CODE_MARKER",
                "code_verifier": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            }),
        );
        host.transport_exchange_pair(
            policy,
            request("/oauth/device/token", "grant_type=device_code"),
            device,
            OpaqueExchangeResponseIntent {
                code_field: ExchangeCodeField::AuthorizationCode,
                redirect_uri: "https://redirect.example.test/callback".to_string(),
            },
        )
        .expect("native device pair capture")
        .pair
        .expect("native pair")
    }

    fn make_host() -> (OAuthHost, Arc<ScriptedHttpsTransport>, Arc<ScriptedClock>) {
        let transport = Arc::new(ScriptedHttpsTransport::new());
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let host = OAuthHost::new(
            Arc::clone(&transport) as Arc<_>,
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::clone(&clock) as Arc<_>,
            Arc::new(ScriptedCancel::new()),
        );
        (host, transport, clock)
    }

    #[test]
    fn native_promoted_pairs_require_exact_host_and_binding_and_remain_live_until_used() {
        let (host, transport, _) = make_host();
        let policy = policy();
        let pair = capture_pair(&host, &transport, &policy);
        assert!(host.exchange_pair_matches_binding(
            &pair.code_handle,
            &pair.verifier_handle,
            policy.generation,
            &policy.run_id,
            "primary",
        ));
        assert!(host.exchange_pair_live(
            &pair.code_handle,
            &pair.verifier_handle,
            policy.generation,
            &policy.run_id,
            "primary",
        ));
        assert!(!host.exchange_pair_matches_binding(
            &pair.code_handle,
            &pair.verifier_handle,
            policy.generation + 1,
            &policy.run_id,
            "primary",
        ));
        assert!(!host.exchange_pair_matches_binding(
            &pair.code_handle,
            &pair.verifier_handle,
            policy.generation,
            "another-run",
            "primary",
        ));
        assert!(!host.exchange_pair_matches_binding(
            &pair.code_handle,
            &pair.verifier_handle,
            policy.generation,
            &policy.run_id,
            "another-credential",
        ));

        let other_pair = capture_pair(&host, &transport, &policy);
        assert!(!host.exchange_pair_matches_binding(
            &pair.code_handle,
            &other_pair.verifier_handle,
            policy.generation,
            &policy.run_id,
            "primary",
        ));
        let (other_host, _, _) = make_host();
        assert!(!other_host.exchange_pair_matches_binding(
            &pair.code_handle,
            &pair.verifier_handle,
            policy.generation,
            &policy.run_id,
            "primary",
        ));

        let mut callback_policy = policy.clone();
        callback_policy.run_id = "callback-pair-binding-test".to_string();
        let callback_begin = host
            .pkce_begin(
                &callback_policy,
                BoundedPublicOAuthIntent {
                    flow: OAuthFlowKind::AuthorizationCodePkce,
                    callback_mode: CallbackMode::None,
                    path: "/oauth/authorize".to_string(),
                    scopes: Vec::new(),
                    public_query: BTreeMap::new(),
                    credential_id: "primary".to_string(),
                },
            )
            .expect("native PKCE begin");
        host.inject_matching_callback(&callback_begin.callback_handle, "CALLBACK_CODE_MARKER")
            .expect("native callback input");
        let callback_code = host
            .callback_wait(&callback_begin.callback_handle)
            .expect("native callback result")
            .code_handle
            .expect("native callback code handle");
        assert!(host.exchange_pair_live(
            &callback_code,
            &callback_begin.verifier_handle,
            callback_policy.generation,
            &callback_policy.run_id,
            "primary",
        ));
    }

    #[test]
    fn expired_native_pair_remains_structurally_bound_but_is_not_live() {
        let (host, transport, clock) = make_host();
        let policy = policy();
        let pair = capture_pair(&host, &transport, &policy);
        clock.expire();

        assert!(host.exchange_pair_matches_binding(
            &pair.code_handle,
            &pair.verifier_handle,
            policy.generation,
            &policy.run_id,
            "primary",
        ));
        assert!(!host.exchange_pair_live(
            &pair.code_handle,
            &pair.verifier_handle,
            policy.generation,
            &policy.run_id,
            "primary",
        ));
    }

    #[test]
    fn binding_remains_structural_after_one_use_while_liveness_closes() {
        let (host, transport, _) = make_host();
        let policy = policy();
        let pair = capture_pair(&host, &transport, &policy);
        transport.push_raw(200, "{}");
        host.transport(
            &policy,
            request("/oauth/token", "grant_type=authorization_code"),
            CredentialUse::AuthorizationCode {
                code: pair.code_handle.clone(),
                verifier: pair.verifier_handle.clone(),
            },
        )
        .expect("native one-use exchange");
        assert!(host.exchange_pair_matches_binding(
            &pair.code_handle,
            &pair.verifier_handle,
            policy.generation,
            &policy.run_id,
            "primary",
        ));
        assert!(!host.exchange_pair_live(
            &pair.code_handle,
            &pair.verifier_handle,
            policy.generation,
            &policy.run_id,
            "primary",
        ));
    }
}

#[cfg(test)]
mod native_selected_cleanup_tests {
    use super::*;
    use crate::auth::request_body::RequestBodyEncoding;

    fn policy() -> TrustedTransportPolicy {
        TrustedTransportPolicy {
            generation: 52,
            run_id: "native-selected-cleanup-test".to_string(),
            deadline: Instant::now() + Duration::from_secs(120),
            endpoints: vec![TrustedEndpoint {
                authority: "auth.example.test".to_string(),
                path_prefix: "/oauth".to_string(),
            }],
            allowed_header_names: BTreeSet::new(),
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

    fn start_device(
        host: &OAuthHost,
        transport: &ScriptedHttpsTransport,
        policy: &TrustedTransportPolicy,
    ) -> OpaqueDeviceSessionHandle {
        transport.push_json(
            200,
            serde_json::json!({
                "device_code": "CLEANUP_DEVICE_MARKER",
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

    fn selected_device_intents() -> NativeTransportIntents {
        NativeTransportIntents {
            request_body: Some(NativeRequestBodyIntent {
                encoding: RequestBodyEncoding::JsonObject,
                secret_fields: SecretBodyFieldSelection::Device {
                    field: DeviceIdField::DeviceCode,
                },
            }),
            exchange_response: None,
        }
    }

    #[test]
    fn cancelled_owner_selection_rejection_reclaims_only_admitted_device() {
        let scripted = Arc::new(ScriptedHttpsTransport::new());
        let owner_cancel = Arc::new(ScriptedCancel::new());
        let host = OAuthHost::new(
            scripted.clone(),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(1_900_000_000_000)),
            Arc::new(ScriptedCancel::new()),
        );
        let policy = policy();
        let device = start_device(&host, &scripted, &policy);
        let sibling = start_device(&host, &scripted, &policy);
        assert_eq!(host.live_flow_count(), 2);
        scripted.take_sent();
        owner_cancel.cancel();
        let mut intents = selected_device_intents();
        intents.request_body.as_mut().unwrap().secret_fields = SecretBodyFieldSelection::None;
        let error = host
            .transport_with_intents_scoped(
                &policy,
                request("/oauth/device/token", "{}"),
                CredentialUse::Device(device.clone()),
                intents,
                owner_cancel,
                None,
            )
            .expect_err("local selector mismatch");
        assert_eq!(error.code(), "invalid_intent");
        assert!(scripted.take_sent().is_empty());
        assert!(host.device_session_live(&sibling, policy.generation, &policy.run_id, "primary"));
        assert!(!host.device_session_live(&device, policy.generation, &policy.run_id, "primary"));
        assert_eq!(host.live_flow_count(), 1);
    }

    #[derive(Clone, Copy)]
    enum EarlyRejection {
        Selection,
        ContentType,
    }

    #[derive(Clone, Copy)]
    enum OwnerState {
        Active,
        Cancelled,
        Deadline,
    }

    enum AdmittedFamily {
        Device(OpaqueDeviceSessionHandle),
        Pair(OpaqueExchangePair),
    }

    impl AdmittedFamily {
        fn credential(&self) -> CredentialUse {
            match self {
                Self::Device(device) => CredentialUse::Device(device.clone()),
                Self::Pair(pair) => CredentialUse::AuthorizationCode {
                    code: pair.code_handle.clone(),
                    verifier: pair.verifier_handle.clone(),
                },
            }
        }

        fn intents(&self) -> NativeTransportIntents {
            match self {
                Self::Device(_) => selected_device_intents(),
                Self::Pair(_) => NativeTransportIntents {
                    request_body: Some(NativeRequestBodyIntent {
                        encoding: RequestBodyEncoding::JsonObject,
                        secret_fields: SecretBodyFieldSelection::AuthorizationCode {
                            code_field: ExchangeCodeField::Code,
                        },
                    }),
                    exchange_response: None,
                },
            }
        }

        fn is_live(&self, host: &OAuthHost, policy: &TrustedTransportPolicy) -> bool {
            match self {
                Self::Device(device) => {
                    host.device_session_live(device, policy.generation, &policy.run_id, "primary")
                }
                Self::Pair(pair) => host.exchange_pair_live(
                    &pair.code_handle,
                    &pair.verifier_handle,
                    policy.generation,
                    &policy.run_id,
                    "primary",
                ),
            }
        }
    }

    fn assert_early_admission(code_pair: bool, rejection: EarlyRejection, state: OwnerState) {
        let scripted = Arc::new(ScriptedHttpsTransport::new());
        let owner_cancel = Arc::new(ScriptedCancel::new());
        let host = OAuthHost::new(
            scripted.clone(),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(1_900_000_000_000)),
            Arc::new(ScriptedCancel::new()),
        );
        let mut policy = policy();
        policy
            .allowed_header_names
            .insert("content-type".to_string());
        let device = start_device(&host, &scripted, &policy);
        let family = if code_pair {
            scripted.push_json(
                200,
                serde_json::json!({
                    "authorization_code": "CLEANUP_CODE_MARKER",
                    "code_verifier": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
                }),
            );
            AdmittedFamily::Pair(
                host.transport_exchange_pair(
                    &policy,
                    request("/oauth/device/token", "grant_type=device_code"),
                    device,
                    OpaqueExchangeResponseIntent {
                        code_field: ExchangeCodeField::AuthorizationCode,
                        redirect_uri: "https://redirect.example.test/callback".to_string(),
                    },
                )
                .expect("native promoted pair")
                .pair
                .expect("opaque native pair"),
            )
        } else {
            AdmittedFamily::Device(device)
        };
        let sibling = start_device(&host, &scripted, &policy);
        assert!(family.is_live(&host, &policy));
        assert_eq!(host.live_flow_count(), 2);
        scripted.take_sent();
        let mut call_policy = policy.clone();
        match state {
            OwnerState::Active => {}
            OwnerState::Cancelled => owner_cancel.cancel(),
            OwnerState::Deadline => {
                call_policy.deadline = Instant::now() - Duration::from_secs(1);
            }
        }
        let mut intents = family.intents();
        let mut rejected_request = request("/oauth/token", "{}");
        match rejection {
            EarlyRejection::Selection => {
                intents.request_body.as_mut().unwrap().secret_fields =
                    SecretBodyFieldSelection::None;
            }
            EarlyRejection::ContentType => {
                rejected_request
                    .public_headers
                    .insert("content-type".to_string(), "text/plain".to_string());
            }
        }
        let error = host
            .transport_with_intents_scoped(
                &call_policy,
                rejected_request,
                family.credential(),
                intents,
                owner_cancel.clone(),
                None,
            )
            .expect_err("original structural admission error");
        assert_eq!(error.code(), "invalid_intent");
        assert!(scripted.take_sent().is_empty());
        assert!(host.device_session_live(&sibling, policy.generation, &policy.run_id, "primary"));
        match state {
            OwnerState::Active => {
                assert!(family.is_live(&host, &policy));
                assert_eq!(host.live_flow_count(), 2);
                scripted.push_raw(200, "{}");
                host.transport_with_intents_scoped(
                    &policy,
                    request("/oauth/token", "{}"),
                    family.credential(),
                    family.intents(),
                    owner_cancel,
                    None,
                )
                .expect("corrected local input retries same live family");
                let sent = scripted.take_sent();
                assert_eq!(sent.len(), 1);
                assert_eq!(sent[0].headers["content-type"], "application/json");
                let body: JsonValue = serde_json::from_str(&sent[0].body).unwrap();
                if code_pair {
                    assert_eq!(body["code"], "CLEANUP_CODE_MARKER");
                    assert!(!family.is_live(&host, &policy));
                    assert_eq!(host.live_flow_count(), 1);
                } else {
                    assert_eq!(body["device_code"], "CLEANUP_DEVICE_MARKER");
                    assert!(family.is_live(&host, &policy));
                }
            }
            OwnerState::Cancelled | OwnerState::Deadline => {
                assert!(!family.is_live(&host, &policy));
                assert_eq!(host.live_flow_count(), 1);
            }
        }
        assert!(host.device_session_live(&sibling, policy.generation, &policy.run_id, "primary"));
    }

    #[test]
    fn cancelled_owner_content_type_rejection_reclaims_device_and_native_pair() {
        for code_pair in [false, true] {
            assert_early_admission(
                code_pair,
                EarlyRejection::ContentType,
                OwnerState::Cancelled,
            );
        }
    }

    #[test]
    fn cancelled_owner_selection_rejection_reclaims_native_pair() {
        assert_early_admission(true, EarlyRejection::Selection, OwnerState::Cancelled);
    }

    #[test]
    fn policy_deadline_rejections_reclaim_only_admitted_device_or_pair() {
        for code_pair in [false, true] {
            for rejection in [EarlyRejection::Selection, EarlyRejection::ContentType] {
                assert_early_admission(code_pair, rejection, OwnerState::Deadline);
            }
        }
    }

    #[test]
    fn active_early_admission_errors_allow_same_device_and_pair_retry() {
        for code_pair in [false, true] {
            for rejection in [EarlyRejection::Selection, EarlyRejection::ContentType] {
                assert_early_admission(code_pair, rejection, OwnerState::Active);
            }
        }
    }

    #[test]
    fn inactive_owner_cannot_reclaim_foreign_host_family() {
        let scripted = Arc::new(ScriptedHttpsTransport::new());
        let make_host = || {
            OAuthHost::new(
                scripted.clone(),
                Arc::new(ScriptedCallback::new()),
                Arc::new(ScriptedBrowser::new()),
                Arc::new(ScriptedClock::new(1_900_000_000_000)),
                Arc::new(ScriptedCancel::new()),
            )
        };
        let origin = make_host();
        let receiver = make_host();
        let policy = policy();
        let foreign = start_device(&origin, &scripted, &policy);
        let receiver_sibling = start_device(&receiver, &scripted, &policy);
        scripted.take_sent();
        let owner_cancel = Arc::new(ScriptedCancel::new());
        owner_cancel.cancel();
        let mut intents = selected_device_intents();
        intents.request_body.as_mut().unwrap().secret_fields = SecretBodyFieldSelection::None;
        let error = receiver
            .transport_with_intents_scoped(
                &policy,
                request("/oauth/token", "{}"),
                CredentialUse::Device(foreign.clone()),
                intents,
                owner_cancel,
                None,
            )
            .expect_err("foreign provenance rejected before family cleanup");
        assert_eq!(error.code(), "handle_invalid");
        assert!(scripted.take_sent().is_empty());
        assert!(origin.device_session_live(&foreign, policy.generation, &policy.run_id, "primary"));
        assert!(receiver.device_session_live(
            &receiver_sibling,
            policy.generation,
            &policy.run_id,
            "primary",
        ));
        assert_eq!(origin.live_flow_count(), 1);
        assert_eq!(receiver.live_flow_count(), 1);
    }

    #[test]
    fn absent_intent_retains_legacy_reserved_form_error_precedence() {
        let scripted = Arc::new(ScriptedHttpsTransport::new());
        let host = OAuthHost::new(
            scripted.clone(),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(1_900_000_000_000)),
            Arc::new(ScriptedCancel::new()),
        );
        let policy = policy();
        let device = start_device(&host, &scripted, &policy);
        scripted.take_sent();
        let owner_cancel = Arc::new(ScriptedCancel::new());
        owner_cancel.cancel();
        let expected = reject_reserved_form_keys("code=synthetic-public").unwrap_err();
        let error = host
            .transport_with_intents_scoped(
                &policy,
                request("/oauth/token", "code=synthetic-public"),
                CredentialUse::Device(device.clone()),
                NativeTransportIntents::default(),
                owner_cancel,
                None,
            )
            .expect_err("legacy form admission before owner check");
        assert_eq!(error.code(), expected.code());
        assert!(scripted.take_sent().is_empty());
        assert!(host.device_session_live(&device, policy.generation, &policy.run_id, "primary"));
        assert_eq!(host.live_flow_count(), 1);
    }

    struct OwnerCancelAfterPoll {
        scripted: Arc<ScriptedHttpsTransport>,
        owner_cancel: Arc<ScriptedCancel>,
    }

    impl BoundedHttpsTransport for OwnerCancelAfterPoll {
        fn send(
            &self,
            request: &PreparedHttpsRequest,
            context: &OAuthIoContext,
        ) -> Result<RawHttpsResponse, OAuthError> {
            let response = self.scripted.send(request, context)?;
            if request.url.ends_with("/oauth/device/token") {
                self.owner_cancel.cancel();
            }
            Ok(response)
        }
    }

    struct ExpireClockAfterPoll {
        scripted: Arc<ScriptedHttpsTransport>,
        clock: Arc<ScriptedClock>,
    }

    impl BoundedHttpsTransport for ExpireClockAfterPoll {
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
    fn owner_cancel_and_original_flow_deadline_revoke_only_the_submitted_family() {
        let scripted = Arc::new(ScriptedHttpsTransport::new());
        let owner_cancel = Arc::new(ScriptedCancel::new());
        let host = OAuthHost::new(
            Arc::new(OwnerCancelAfterPoll {
                scripted: Arc::clone(&scripted),
                owner_cancel: Arc::clone(&owner_cancel),
            }),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(1_900_000_000_000)),
            Arc::new(ScriptedCancel::new()),
        );
        let policy = policy();
        let device = start_device(&host, &scripted, &policy);
        let sibling = start_device(&host, &scripted, &policy);
        scripted.push_json(200, serde_json::json!({"status": "waiting"}));
        let error = host
            .transport_with_intents_scoped(
                &policy,
                request("/oauth/device/token", r#"{"grant_type":"device_code"}"#),
                CredentialUse::Device(device.clone()),
                selected_device_intents(),
                Arc::clone(&owner_cancel) as Arc<_>,
                None,
            )
            .expect_err("owner cancellation after I/O");
        assert_eq!(error.code(), "cancelled");
        assert_eq!(
            host.transport(
                &policy,
                request("/oauth/device/token", "grant_type=device_code"),
                CredentialUse::Device(device),
            )
            .expect_err("submitted device family revoked")
            .code(),
            "handle_revoked"
        );

        scripted.push_json(200, serde_json::json!({"status": "waiting"}));
        host.transport(
            &policy,
            request("/oauth/device/token", "grant_type=device_code"),
            CredentialUse::Device(sibling),
        )
        .expect("sibling remains live after scoped owner cancellation");
        let sent = scripted.take_sent();
        assert_eq!(sent.len(), 4);
        let selected_body: serde_json::Value =
            serde_json::from_str(&sent[2].body).expect("selected request reached I/O");
        assert_eq!(selected_body["device_code"], "CLEANUP_DEVICE_MARKER");

        let scripted = Arc::new(ScriptedHttpsTransport::new());
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let host = OAuthHost::new(
            Arc::new(ExpireClockAfterPoll {
                scripted: Arc::clone(&scripted),
                clock: Arc::clone(&clock),
            }),
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::clone(&clock) as Arc<_>,
            Arc::new(ScriptedCancel::new()),
        );
        let mut deadline_policy = self::policy();
        deadline_policy.deadline = Instant::now() + Duration::from_secs(48 * 60 * 60);
        let device = start_device(&host, &scripted, &deadline_policy);
        scripted.push_json(200, serde_json::json!({"status": "waiting"}));
        let error = host
            .transport_with_intents_scoped(
                &deadline_policy,
                request("/oauth/device/token", r#"{"grant_type":"device_code"}"#),
                CredentialUse::Device(device.clone()),
                selected_device_intents(),
                Arc::new(ScriptedCancel::new()),
                None,
            )
            .expect_err("submitted device original expiry bounds I/O");
        assert_eq!(error.code(), "deadline_exceeded");
        assert_eq!(
            host.transport(
                &deadline_policy,
                request("/oauth/device/token", "grant_type=device_code"),
                CredentialUse::Device(device),
            )
            .expect_err("deadline cleanup revokes submitted family")
            .code(),
            "handle_revoked"
        );
        assert_eq!(scripted.take_sent().len(), 2);
    }
}

#[cfg(test)]
mod device_poll_tests {
    use super::*;

    #[test]
    fn single_flight_rejects_overlap_then_releases_live_device_session() {
        let now = Instant::now();
        let mut flow = FlowInner::forged();
        let flow = Arc::get_mut(&mut flow).expect("exclusive fixture flow");
        flow.expires_at = now + Duration::from_secs(60);
        flow.device_code = Mutex::new(Zeroizing::new("fixture-device".to_string()));
        flow.device_state.store(HANDLE_LIVE, Ordering::Release);

        let first_poll = flow.begin_device_poll(now).expect("first poll admitted");
        assert!(matches!(
            flow.begin_device_poll(now),
            Err(OAuthError::HandleReplayed { .. })
        ));
        assert!(flow.device_in_flight.load(Ordering::Acquire));
        assert_eq!(flow.device_state.load(Ordering::Acquire), HANDLE_LIVE);
        assert_eq!(
            flow.device_id().expect("first poll keeps session").as_str(),
            "fixture-device"
        );

        drop(first_poll);
        let retry = flow
            .begin_device_poll(now)
            .expect("retry after first completes");
        assert_eq!(flow.device_state.load(Ordering::Acquire), HANDLE_LIVE);
        assert!(!flow.revoked.load(Ordering::Acquire));
        drop(retry);
    }
}
