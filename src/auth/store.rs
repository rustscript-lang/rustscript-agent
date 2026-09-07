//! Generic, confined persistence primitives for the RSS-owned auth store.
//!
//! This module owns filesystem safety, bounded YAML persistence, generation CAS,
//! and opaque secret slots. It does not select providers, refresh policies, or
//! status transitions. Those decisions stay in RSS and its host adapter.

use std::collections::HashMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};

use zeroize::{Zeroize, Zeroizing};

use crate::auth::config::{
    AuthConfig, AuthConfigError, CredentialConfig, SecretText, StoredAuthConfig,
    StoredCredentialConfig, parse_stored_yaml,
};
use crate::auth::token::{CredentialId, TokenError};
use crate::config_file::{AUTH_FILE_NAME, AUTH_LOCK_FILE_NAME, AgentPaths};

/// A bounded upper limit for one persisted authentication document.
pub const MAX_AUTH_STORE_BYTES: usize = crate::auth::config::MAX_AUTH_YAML_BYTES;
const MAX_SECRET_SLOT_BYTES: usize = 64 * 1024;
const SLOT_LIVE: u8 = 0;
const SLOT_USED: u8 = 1;
const SLOT_EXPIRED: u8 = 2;
const HANDLE_LIVE: u8 = 0;
const HANDLE_USED: u8 = 1;
const HANDLE_EXPIRED: u8 = 2;
const HANDLE_REVOKED: u8 = 3;
const ACCESS_HANDLE_TTL: Duration = Duration::from_secs(5 * 60);
const REFRESH_HANDLE_TTL: Duration = Duration::from_secs(60);
#[cfg(any(test, feature = "config-fixture"))]
const SECRET_SLOT_TTL: Duration = Duration::from_secs(5 * 60);

/// RSS-visible class name for a host-minted access handle.
pub const ACCESS_HANDLE_CLASS: &str = "OpaqueAccessHandle";
/// RSS-visible class name for a host-minted refresh handle.
pub const REFRESH_HANDLE_CLASS: &str = "OpaqueRefreshHandle";

/// The kind of secret held by an opaque slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretSlotKind {
    Access,
    Refresh,
}

impl SecretSlotKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Refresh => "refresh",
        }
    }
}

/// A host-owned, one-shot secret slot. The secret bytes are not readable
/// through this public type and its diagnostic representation is redacted.
#[derive(Clone)]
pub struct OpaqueSecretSlot {
    inner: Arc<SecretSlotInner>,
}

struct SecretSlotInner {
    kind: SecretSlotKind,
    credential_id: String,
    expected_generation: u64,
    policy_generation: u64,
    run_id: String,
    bytes: Mutex<Zeroizing<Vec<u8>>>,
    state: AtomicU8,
    expires_at: Instant,
}

impl fmt::Debug for OpaqueSecretSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueSecretSlot")
            .field("kind", &self.inner.kind)
            .field("credential_id", &self.inner.credential_id)
            .field("expected_generation", &self.inner.expected_generation)
            .field("policy_generation", &self.inner.policy_generation)
            .field("run_id", &self.inner.run_id)
            .field("state", &self.inner.state.load(Ordering::Acquire))
            .finish()
    }
}

impl OpaqueSecretSlot {
    #[cfg(any(test, feature = "config-fixture"))]
    pub(crate) fn from_host_secret(
        kind: SecretSlotKind,
        credential_id: &str,
        expected_generation: u64,
        policy_generation: u64,
        run_id: &str,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Self, AuthStoreError> {
        Self::from_host_secret_until(
            kind,
            credential_id,
            expected_generation,
            policy_generation,
            run_id,
            bytes,
            Instant::now() + SECRET_SLOT_TTL,
        )
    }

    pub(crate) fn from_host_secret_until(
        kind: SecretSlotKind,
        credential_id: &str,
        expected_generation: u64,
        policy_generation: u64,
        run_id: &str,
        bytes: Zeroizing<Vec<u8>>,
        expires_at: Instant,
    ) -> Result<Self, AuthStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_SLOT_BYTES {
            return Err(AuthStoreError::SecretSlotInvalid {
                credential_id: credential_id.to_string(),
                kind: kind.as_str().to_string(),
                reason: "secret slot size is outside the bounded range".to_string(),
            });
        }
        if std::str::from_utf8(&bytes).is_err() {
            return Err(AuthStoreError::SecretSlotInvalid {
                credential_id: credential_id.to_string(),
                kind: kind.as_str().to_string(),
                reason: "secret slot is not valid UTF-8".to_string(),
            });
        }
        validate_slot_provenance(
            credential_id,
            expected_generation,
            policy_generation,
            run_id,
        )?;
        Ok(Self {
            inner: Arc::new(SecretSlotInner {
                kind,
                credential_id: credential_id.to_string(),
                expected_generation,
                policy_generation,
                run_id: run_id.to_string(),
                bytes: Mutex::new(bytes),
                state: AtomicU8::new(SLOT_LIVE),
                expires_at,
            }),
        })
    }

    fn expired_error(&self) -> AuthStoreError {
        AuthStoreError::SecretSlotExpired {
            credential_id: self.inner.credential_id.clone(),
            kind: self.inner.kind.as_str().to_string(),
        }
    }

    fn zeroize_bytes(&self) {
        let mut bytes = self
            .inner
            .bytes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        bytes.zeroize();
    }

    fn mark_expired(&self) {
        if self
            .inner
            .state
            .compare_exchange(SLOT_LIVE, SLOT_EXPIRED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.zeroize_bytes();
        }
    }

    fn expire_if_due(&self) -> Result<(), AuthStoreError> {
        if self.inner.state.load(Ordering::Acquire) == SLOT_EXPIRED {
            self.zeroize_bytes();
            return Err(self.expired_error());
        }
        if Instant::now() >= self.inner.expires_at {
            self.mark_expired();
            return Err(self.expired_error());
        }
        Ok(())
    }

    pub(crate) fn validate_for_request(
        &self,
        kind: SecretSlotKind,
        credential_id: &str,
        expected_generation: u64,
        policy_generation: u64,
        run_id: &str,
    ) -> Result<(), AuthStoreError> {
        self.expire_if_due()?;
        if self.inner.kind != kind
            || self.inner.credential_id != credential_id
            || self.inner.expected_generation != expected_generation
            || self.inner.policy_generation != policy_generation
            || self.inner.run_id != run_id
        {
            return Err(AuthStoreError::SecretSlotProvenance {
                credential_id: credential_id.to_string(),
                kind: kind.as_str().to_string(),
            });
        }
        if self.inner.state.load(Ordering::Acquire) != SLOT_LIVE {
            return Err(AuthStoreError::SecretSlotReplayed {
                credential_id: credential_id.to_string(),
                kind: kind.as_str().to_string(),
            });
        }
        let bytes = self
            .inner
            .bytes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if bytes.is_empty() {
            return Err(AuthStoreError::SecretSlotInvalid {
                credential_id: credential_id.to_string(),
                kind: kind.as_str().to_string(),
                reason: "secret slot is empty".to_string(),
            });
        }
        if std::str::from_utf8(&bytes).is_err() {
            return Err(AuthStoreError::SecretSlotInvalid {
                credential_id: credential_id.to_string(),
                kind: kind.as_str().to_string(),
                reason: "secret slot is not valid UTF-8".to_string(),
            });
        }
        Ok(())
    }

    fn snapshot_text(
        &self,
        kind: SecretSlotKind,
        credential_id: &str,
        expected_generation: u64,
        policy_generation: u64,
        run_id: &str,
    ) -> Result<SecretText, AuthStoreError> {
        self.validate_for_request(
            kind,
            credential_id,
            expected_generation,
            policy_generation,
            run_id,
        )?;
        let bytes = self
            .inner
            .bytes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        SecretText::from_bytes(Zeroizing::new(bytes.as_slice().to_vec())).map_err(|_| {
            AuthStoreError::SecretSlotInvalid {
                credential_id: credential_id.to_string(),
                kind: kind.as_str().to_string(),
                reason: "secret slot is not valid UTF-8".to_string(),
            }
        })
    }

    pub(crate) fn consume(&self) -> Result<(), AuthStoreError> {
        self.expire_if_due()?;
        if self
            .inner
            .state
            .compare_exchange(SLOT_LIVE, SLOT_USED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(AuthStoreError::SecretSlotReplayed {
                credential_id: self.inner.credential_id.clone(),
                kind: self.inner.kind.as_str().to_string(),
            });
        }
        let mut bytes = self
            .inner
            .bytes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        bytes.zeroize();
        Ok(())
    }

    pub(crate) fn revoke(&self) {
        if self.inner.state.swap(SLOT_USED, Ordering::AcqRel) != SLOT_USED {
            let mut bytes = self
                .inner
                .bytes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            bytes.zeroize();
        }
    }
}

fn credential_remaining(expires_at_ms: u64) -> Duration {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_millis(expires_at_ms))
        .and_then(|deadline| deadline.duration_since(SystemTime::now()).ok())
        .unwrap_or(Duration::ZERO)
}

fn handle_deadline(kind: SecretSlotKind, expires_at_ms: u64, request_deadline: Instant) -> Instant {
    let now = Instant::now();
    let cap = match kind {
        SecretSlotKind::Access => ACCESS_HANDLE_TTL,
        SecretSlotKind::Refresh => REFRESH_HANDLE_TTL,
    };
    let capped = now + cap;
    let request_bound = if request_deadline > now {
        request_deadline
    } else {
        now
    };
    match kind {
        SecretSlotKind::Access => {
            let credential_bound = now + credential_remaining(expires_at_ms);
            capped.min(request_bound).min(credential_bound)
        }
        SecretSlotKind::Refresh => capped.min(request_bound),
    }
}

struct IssuedHandleInner {
    kind: SecretSlotKind,
    credential_id: String,
    generation: u64,
    policy_generation: u64,
    run_id: String,
    expires_at: Instant,
    state: AtomicU8,
    slot: OpaqueSecretSlot,
    store: Weak<StoreInner>,
}

impl IssuedHandleInner {
    fn class(&self) -> &'static str {
        match self.kind {
            SecretSlotKind::Access => ACCESS_HANDLE_CLASS,
            SecretSlotKind::Refresh => REFRESH_HANDLE_CLASS,
        }
    }

    fn kind_label(&self) -> String {
        self.kind.as_str().to_string()
    }

    fn replayed_error(&self) -> AuthStoreError {
        AuthStoreError::HandleReplayed {
            credential_id: self.credential_id.clone(),
            kind: self.kind_label(),
        }
    }

    fn revoked_error(&self) -> AuthStoreError {
        AuthStoreError::HandleRevoked {
            credential_id: self.credential_id.clone(),
            kind: self.kind_label(),
        }
    }

    fn expired_error(&self) -> AuthStoreError {
        AuthStoreError::HandleExpired {
            credential_id: self.credential_id.clone(),
            kind: self.kind_label(),
        }
    }

    fn host_store(&self) -> Result<AuthStore, AuthStoreError> {
        self.store
            .upgrade()
            .map(|inner| AuthStore { inner })
            .ok_or_else(|| self.revoked_error())
    }

    fn is_time_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    fn is_inflight(&self) -> bool {
        self.state.load(Ordering::Acquire) == HANDLE_LIVE && !self.is_time_expired()
    }

    fn matches_refresh_flight(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.policy_generation == other.policy_generation
            && self.run_id == other.run_id
    }

    fn mark_revoked(&self) {
        let previous = self.state.swap(HANDLE_REVOKED, Ordering::AcqRel);
        if previous != HANDLE_USED && previous != HANDLE_REVOKED {
            self.slot.revoke();
        }
    }

    fn mark_expired(&self) {
        if self
            .state
            .compare_exchange(
                HANDLE_LIVE,
                HANDLE_EXPIRED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.slot.revoke();
        }
    }

    fn check_live(&self) -> Result<(), AuthStoreError> {
        match self.state.load(Ordering::Acquire) {
            HANDLE_USED => return Err(self.replayed_error()),
            HANDLE_REVOKED => return Err(self.revoked_error()),
            HANDLE_EXPIRED => {
                self.slot.revoke();
                return Err(self.expired_error());
            }
            _ => {}
        }
        if self.is_time_expired() {
            self.mark_expired();
            return Err(self.expired_error());
        }
        Ok(())
    }

    fn check_binding(
        &self,
        credential_id: &str,
        generation: u64,
        policy_generation: u64,
        run_id: &str,
    ) -> Result<(), AuthStoreError> {
        if self.credential_id != credential_id
            || self.generation != generation
            || self.policy_generation != policy_generation
            || self.run_id != run_id
        {
            return Err(AuthStoreError::HandleProvenance {
                credential_id: credential_id.to_string(),
                kind: self.kind_label(),
            });
        }
        Ok(())
    }

    fn consume_live(&self) -> Result<(), AuthStoreError> {
        self.check_live()?;
        if self
            .state
            .compare_exchange(
                HANDLE_LIVE,
                HANDLE_USED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(self.replayed_error());
        }
        self.slot.revoke();
        Ok(())
    }

    fn force_expire(&self) {
        self.mark_expired();
        if let Ok(store) = self.host_store() {
            store.unregister_issued(self);
        }
    }

    fn validate_against_store(&self) -> Result<(), AuthStoreError> {
        self.host_store()?.revalidate_issued(self)
    }

    fn consume_against_store(&self) -> Result<(), AuthStoreError> {
        self.host_store()?.consume_issued(self)
    }
}

/// One-shot access handle. Copies alias the same host entry; Debug is redacted.
#[derive(Clone)]
pub struct OpaqueAccessHandle {
    inner: Arc<IssuedHandleInner>,
}

impl OpaqueAccessHandle {
    fn from_inner(inner: Arc<IssuedHandleInner>) -> Self {
        Self { inner }
    }

    pub fn class(&self) -> &'static str {
        ACCESS_HANDLE_CLASS
    }

    pub fn generation(&self) -> u64 {
        self.inner.generation
    }

    pub fn credential_id(&self) -> &str {
        &self.inner.credential_id
    }

    pub fn validate(&self) -> Result<(), AuthStoreError> {
        self.inner.validate_against_store()
    }

    pub fn validate_binding(
        &self,
        credential_id: &str,
        generation: u64,
        policy_generation: u64,
        run_id: &str,
    ) -> Result<(), AuthStoreError> {
        self.inner.check_live()?;
        self.inner
            .check_binding(credential_id, generation, policy_generation, run_id)
    }

    pub fn consume(&self) -> Result<(), AuthStoreError> {
        self.inner.consume_against_store()
    }

    pub fn force_expire(&self) {
        self.inner.force_expire();
    }
}

impl fmt::Debug for OpaqueAccessHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct(self.inner.class())
            .field("credential_id", &self.inner.credential_id)
            .field("generation", &self.inner.generation)
            .finish_non_exhaustive()
    }
}

/// One-shot refresh handle. Local validation does not consume the send slot.
#[derive(Clone)]
pub struct OpaqueRefreshHandle {
    inner: Arc<IssuedHandleInner>,
}

impl OpaqueRefreshHandle {
    fn from_inner(inner: Arc<IssuedHandleInner>) -> Self {
        Self { inner }
    }

    pub fn class(&self) -> &'static str {
        REFRESH_HANDLE_CLASS
    }

    pub fn generation(&self) -> u64 {
        self.inner.generation
    }

    pub fn credential_id(&self) -> &str {
        &self.inner.credential_id
    }

    pub fn validate(&self) -> Result<(), AuthStoreError> {
        self.inner.validate_against_store()
    }

    pub fn validate_binding(
        &self,
        credential_id: &str,
        generation: u64,
        policy_generation: u64,
        run_id: &str,
    ) -> Result<(), AuthStoreError> {
        self.inner.check_live()?;
        self.inner
            .check_binding(credential_id, generation, policy_generation, run_id)
    }

    pub fn consume(&self) -> Result<(), AuthStoreError> {
        self.inner.consume_against_store()
    }

    pub fn force_expire(&self) {
        self.inner.force_expire();
    }
}

impl fmt::Debug for OpaqueRefreshHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct(self.inner.class())
            .field("credential_id", &self.inner.credential_id)
            .field("generation", &self.inner.generation)
            .finish_non_exhaustive()
    }
}

/// Sanitized metadata returned by the store. It has no access or refresh bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthMetadata {
    pub credential_id: String,
    pub provider: String,
    pub kind: String,
    pub source: String,
    pub token_type: String,
    pub expires_at_ms: u64,
    pub scopes: Vec<String>,
    pub account_id: Option<String>,
    pub generation: u64,
    pub status: String,
    pub last_refresh_at_ms: Option<u64>,
    pub has_refresh_token: bool,
}

impl AuthMetadata {
    fn from_stored(credential_id: &str, credential: &StoredCredentialConfig) -> Self {
        Self {
            credential_id: credential_id.to_string(),
            provider: credential.provider.clone(),
            kind: credential.kind.clone(),
            source: credential.source.clone(),
            token_type: credential.token_type.clone(),
            expires_at_ms: credential.expires_at_ms,
            scopes: credential.scopes.clone(),
            account_id: credential.account_id.clone(),
            generation: credential.generation,
            status: credential.status.clone(),
            last_refresh_at_ms: credential.last_refresh_at_ms,
            has_refresh_token: credential.refresh_token.is_some(),
        }
    }
}

/// RSS selects whether an existing refresh slot is preserved, replaced, or
/// cleared. The Rust store only persists the requested structural operation.
#[derive(Clone, Debug)]
pub enum RefreshSecretAction {
    Preserve,
    Replace(OpaqueSecretSlot),
    Clear,
}

/// A generation-checked structural update. Secret slots are opaque capabilities,
/// never raw token arguments.
#[derive(Clone, Debug)]
pub struct SaveCredentialRequest {
    pub credential_id: CredentialId,
    pub expected_generation: u64,
    pub policy_generation: u64,
    pub run_id: String,
    pub metadata: CredentialConfig,
    pub access_slot: OpaqueSecretSlot,
    pub refresh: RefreshSecretAction,
}

impl SaveCredentialRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_id: CredentialId,
        expected_generation: u64,
        policy_generation: u64,
        run_id: impl Into<String>,
        metadata: CredentialConfig,
        access_slot: OpaqueSecretSlot,
        refresh: RefreshSecretAction,
    ) -> Self {
        Self {
            credential_id,
            expected_generation,
            policy_generation,
            run_id: run_id.into(),
            metadata,
            access_slot,
            refresh,
        }
    }

    fn validate(&self) -> Result<(), AuthStoreError> {
        validate_slot_provenance(
            self.credential_id.as_str(),
            self.expected_generation,
            self.policy_generation,
            &self.run_id,
        )?;
        validate_metadata(&self.credential_id, &self.metadata)?;
        if self.metadata.generation != self.expected_generation {
            return Err(AuthStoreError::InvalidGeneration {
                credential_id: self.credential_id.to_string(),
                expected: self.expected_generation,
                supplied: self.metadata.generation,
            });
        }
        self.access_slot.validate_for_request(
            SecretSlotKind::Access,
            self.credential_id.as_str(),
            self.expected_generation,
            self.policy_generation,
            &self.run_id,
        )?;
        if let RefreshSecretAction::Replace(slot) = &self.refresh {
            slot.validate_for_request(
                SecretSlotKind::Refresh,
                self.credential_id.as_str(),
                self.expected_generation,
                self.policy_generation,
                &self.run_id,
            )?;
        }
        Ok(())
    }

    fn revoke_slots(&self) {
        self.access_slot.revoke();
        if let RefreshSecretAction::Replace(slot) = &self.refresh {
            slot.revoke();
        }
    }
}

/// Result of a generation-checked update. A newer writer is adopted without
/// touching the candidate slots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SaveOutcome {
    Committed { metadata: AuthMetadata },
    Adopted { metadata: AuthMetadata },
}

impl SaveOutcome {
    pub fn metadata(&self) -> &AuthMetadata {
        match self {
            Self::Committed { metadata } | Self::Adopted { metadata } => metadata,
        }
    }

    pub fn is_adopted(&self) -> bool {
        matches!(self, Self::Adopted { .. })
    }
}

/// A typed, redaction-safe store failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthStoreError {
    UnsupportedPlatform,
    BackendUnavailable {
        operation: String,
        message: String,
    },
    InvalidPath {
        path: PathBuf,
        reason: String,
    },
    Io {
        operation: String,
        path: PathBuf,
        message: String,
    },
    Lock {
        path: PathBuf,
        message: String,
    },
    SymlinkRejected {
        path: PathBuf,
    },
    NonRegularFile {
        path: PathBuf,
    },
    OwnerMismatch {
        path: PathBuf,
    },
    InsecurePermissions {
        path: PathBuf,
        mode: u32,
    },
    CorruptFile {
        path: PathBuf,
        artifact: Option<PathBuf>,
        reason: String,
    },
    FileTooLarge {
        path: PathBuf,
        max_bytes: usize,
    },
    CredentialNotFound {
        credential_id: String,
    },
    GenerationConflict {
        credential_id: String,
        expected: u64,
        actual: u64,
    },
    InvalidGeneration {
        credential_id: String,
        expected: u64,
        supplied: u64,
    },
    GenerationOverflow {
        credential_id: String,
    },
    InvalidCredential {
        credential_id: String,
        reason: String,
    },
    InvalidMetadata {
        credential_id: String,
        field: String,
        reason: String,
    },
    SecretSlotInvalid {
        credential_id: String,
        kind: String,
        reason: String,
    },
    SecretSlotProvenance {
        credential_id: String,
        kind: String,
    },
    SecretSlotReplayed {
        credential_id: String,
        kind: String,
    },
    SecretSlotExpired {
        credential_id: String,
        kind: String,
    },
    HandleInvalid {
        credential_id: String,
        kind: String,
    },
    HandleExpired {
        credential_id: String,
        kind: String,
    },
    HandleProvenance {
        credential_id: String,
        kind: String,
    },
    HandleReplayed {
        credential_id: String,
        kind: String,
    },
    HandleRevoked {
        credential_id: String,
        kind: String,
    },
    Serialization {
        message: String,
    },
}

impl AuthStoreError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedPlatform | Self::BackendUnavailable { .. } => "backend_unavailable",
            Self::InvalidPath { .. } => "invalid_path",
            Self::Io { .. } => "io_error",
            Self::Lock { .. } => "lock_error",
            Self::SymlinkRejected { .. } => "symlink_rejected",
            Self::NonRegularFile { .. } => "non_regular_file",
            Self::OwnerMismatch { .. } => "owner_mismatch",
            Self::InsecurePermissions { .. } => "insecure_permissions",
            Self::CorruptFile { .. } => "corrupt_file",
            Self::FileTooLarge { .. } => "file_too_large",
            Self::CredentialNotFound { .. } => "credential_not_found",
            Self::GenerationConflict { .. } => "generation_conflict",
            Self::InvalidGeneration { .. } => "invalid_generation",
            Self::GenerationOverflow { .. } => "generation_overflow",
            Self::InvalidCredential { .. } => "invalid_credential",
            Self::InvalidMetadata { .. } => "invalid_metadata",
            Self::SecretSlotInvalid { .. } => "secret_slot_invalid",
            Self::SecretSlotProvenance { .. } => "secret_slot_provenance",
            Self::SecretSlotReplayed { .. } => "secret_slot_replayed",
            Self::SecretSlotExpired { .. } => "secret_slot_expired",
            Self::HandleInvalid { .. } => "handle_invalid",
            Self::HandleExpired { .. } => "handle_expired",
            Self::HandleProvenance { .. } => "handle_provenance",
            Self::HandleReplayed { .. } => "handle_replayed",
            Self::HandleRevoked { .. } => "handle_revoked",
            Self::Serialization { .. } => "serialization_error",
        }
    }

    fn from_auth_config(error: AuthConfigError, path: &Path) -> Self {
        Self::CorruptFile {
            path: path.to_path_buf(),
            artifact: None,
            reason: error.to_string(),
        }
    }
}

impl fmt::Display for AuthStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                write!(
                    formatter,
                    "secure auth storage is unsupported on this platform"
                )
            }
            Self::BackendUnavailable { operation, message } => {
                write!(
                    formatter,
                    "auth store backend unavailable during {operation}: {message}"
                )
            }
            Self::InvalidPath { path, reason } => {
                write!(
                    formatter,
                    "invalid auth store path {}: {reason}",
                    path.display()
                )
            }
            Self::Io {
                operation,
                path,
                message,
            } => write!(
                formatter,
                "auth store {operation} {}: {message}",
                path.display()
            ),
            Self::Lock { path, message } => {
                write!(
                    formatter,
                    "cannot lock auth store {}: {message}",
                    path.display()
                )
            }
            Self::SymlinkRejected { path } => {
                write!(formatter, "auth store refuses symlink {}", path.display())
            }
            Self::NonRegularFile { path } => {
                write!(
                    formatter,
                    "auth store requires a regular file: {}",
                    path.display()
                )
            }
            Self::OwnerMismatch { path } => {
                write!(
                    formatter,
                    "auth store owner is not the current user: {}",
                    path.display()
                )
            }
            Self::InsecurePermissions { path, mode } => write!(
                formatter,
                "auth store permissions for {} are too broad ({mode:o})",
                path.display()
            ),
            Self::CorruptFile {
                path,
                artifact,
                reason,
            } => {
                if let Some(artifact) = artifact {
                    write!(
                        formatter,
                        "auth file {} is corrupt ({reason}); preserved copy: {}",
                        path.display(),
                        artifact.display()
                    )
                } else {
                    write!(
                        formatter,
                        "auth file {} is corrupt ({reason})",
                        path.display()
                    )
                }
            }
            Self::FileTooLarge { path, max_bytes } => write!(
                formatter,
                "auth file {} exceeds the {max_bytes}-byte limit",
                path.display()
            ),
            Self::CredentialNotFound { credential_id } => {
                write!(formatter, "credential {credential_id:?} is not present")
            }
            Self::GenerationConflict {
                credential_id,
                expected,
                actual,
            } => write!(
                formatter,
                "credential {credential_id:?} generation conflict (expected {expected}, found {actual})"
            ),
            Self::InvalidGeneration {
                credential_id,
                expected,
                supplied,
            } => write!(
                formatter,
                "credential {credential_id:?} supplied generation {supplied}, expected {expected}"
            ),
            Self::GenerationOverflow { credential_id } => write!(
                formatter,
                "credential {credential_id:?} generation cannot be incremented"
            ),
            Self::InvalidCredential {
                credential_id,
                reason,
            } => write!(formatter, "invalid credential {credential_id:?}: {reason}"),
            Self::InvalidMetadata {
                credential_id,
                field,
                reason,
            } => write!(
                formatter,
                "invalid metadata field {field} for credential {credential_id:?}: {reason}"
            ),
            Self::SecretSlotInvalid {
                credential_id,
                kind,
                reason,
            } => write!(
                formatter,
                "invalid {kind} secret slot for credential {credential_id:?}: {reason}"
            ),
            Self::SecretSlotProvenance {
                credential_id,
                kind,
            } => write!(
                formatter,
                "{kind} secret slot provenance does not match credential {credential_id:?}"
            ),
            Self::SecretSlotReplayed {
                credential_id,
                kind,
            } => write!(
                formatter,
                "{kind} secret slot for credential {credential_id:?} was already used"
            ),
            Self::SecretSlotExpired {
                credential_id,
                kind,
            } => write!(
                formatter,
                "{kind} secret slot for credential {credential_id:?} has expired"
            ),
            Self::HandleInvalid {
                credential_id,
                kind,
            } => write!(
                formatter,
                "{kind} handle for credential {credential_id:?} is not host-owned"
            ),
            Self::HandleExpired {
                credential_id,
                kind,
            } => write!(
                formatter,
                "{kind} handle for credential {credential_id:?} has expired"
            ),
            Self::HandleProvenance {
                credential_id,
                kind,
            } => write!(
                formatter,
                "{kind} handle provenance does not match credential {credential_id:?}"
            ),
            Self::HandleReplayed {
                credential_id,
                kind,
            } => write!(
                formatter,
                "{kind} handle for credential {credential_id:?} was already used"
            ),
            Self::HandleRevoked {
                credential_id,
                kind,
            } => write!(
                formatter,
                "{kind} handle for credential {credential_id:?} was revoked"
            ),
            Self::Serialization { message } => {
                write!(formatter, "cannot serialize auth document: {message}")
            }
        }
    }
}

impl std::error::Error for AuthStoreError {}

/// A persistent authentication store bound to one resolved agent home.
#[derive(Clone)]
pub struct AuthStore {
    inner: Arc<StoreInner>,
}

impl fmt::Debug for AuthStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthStore")
            .field("paths", &self.inner.paths)
            .finish()
    }
}

/// Generic storage boundary. It carries structural metadata and opaque slots,
/// without provider/runtime policy.
pub trait CredentialStore {
    fn load(&self) -> Result<AuthConfig, AuthStoreError>;
    fn load_metadata(&self, credential_id: &str) -> Result<AuthMetadata, AuthStoreError>;
    fn save_if_generation(
        &self,
        request: SaveCredentialRequest,
    ) -> Result<SaveOutcome, AuthStoreError>;
    fn delete(&self, credential_id: &str) -> Result<AuthMetadata, AuthStoreError>;
}

struct StoreInner {
    paths: AgentPaths,
    process_lock: Mutex<()>,
    /// In-process issued-handle table. Lock order: `process_lock`, then the
    /// filesystem advisory lock, then `handle_registry`. Never hold
    /// `handle_registry` across filesystem I/O. This table can only govern
    /// handles issued by this host; store generation remains the authority.
    handle_registry: Mutex<HandleRegistry>,
    #[cfg(unix)]
    home: std::os::fd::OwnedFd,
}

#[derive(Default)]
struct IssuedHandleSet {
    access: Vec<Arc<IssuedHandleInner>>,
    refresh: Option<Arc<IssuedHandleInner>>,
}

#[derive(Default)]
struct HandleRegistry {
    by_credential: HashMap<String, IssuedHandleSet>,
}

impl HandleRegistry {
    fn sweep_expired(&mut self) {
        self.by_credential.retain(|_, entry| {
            for handle in &entry.access {
                if handle.is_time_expired() {
                    handle.mark_expired();
                }
            }
            entry.access.retain(|handle| handle.is_inflight());
            if let Some(handle) = &entry.refresh {
                if handle.is_time_expired() {
                    handle.mark_expired();
                }
                if !handle.is_inflight() {
                    entry.refresh = None;
                }
            }
            !entry.access.is_empty() || entry.refresh.is_some()
        });
    }

    fn register(&mut self, handle: Arc<IssuedHandleInner>) -> Result<(), AuthStoreError> {
        self.sweep_expired();
        match handle.kind {
            SecretSlotKind::Access => {
                self.by_credential
                    .entry(handle.credential_id.clone())
                    .or_default()
                    .access
                    .push(handle);
                Ok(())
            }
            SecretSlotKind::Refresh => {
                let entry = self
                    .by_credential
                    .entry(handle.credential_id.clone())
                    .or_default();
                if let Some(existing) = &entry.refresh
                    && existing.is_inflight()
                    && existing.matches_refresh_flight(&handle)
                {
                    return Err(existing.replayed_error());
                }
                entry.refresh = Some(handle);
                Ok(())
            }
        }
    }

    fn unregister(&mut self, handle: &IssuedHandleInner) {
        let Some(entry) = self.by_credential.get_mut(&handle.credential_id) else {
            return;
        };
        match handle.kind {
            SecretSlotKind::Access => {
                entry
                    .access
                    .retain(|candidate| !std::ptr::eq(candidate.as_ref(), handle));
            }
            SecretSlotKind::Refresh => {
                if entry
                    .refresh
                    .as_ref()
                    .is_some_and(|candidate| std::ptr::eq(candidate.as_ref(), handle))
                {
                    entry.refresh = None;
                }
            }
        }
        if entry.access.is_empty() && entry.refresh.is_none() {
            self.by_credential.remove(&handle.credential_id);
        }
    }

    fn revoke_credential(&mut self, credential_id: &str) -> IssuedHandleSet {
        self.by_credential.remove(credential_id).unwrap_or_default()
    }
}

impl AuthStore {
    /// Opens a confined store and creates the home directory and lock file when
    /// they do not exist. A missing `auth.yaml` is a fresh empty document.
    pub fn open(paths: AgentPaths) -> Result<Self, AuthStoreError> {
        validate_paths(&paths)?;
        #[cfg(unix)]
        {
            let home = unix::open_home(&paths.home)?;
            unix::ensure_lock_file(&home, &paths.auth_lock)?;
            if let Some(auth_file) = unix::open_auth_file(&home, &paths.auth)? {
                drop(auth_file);
            }
            Ok(Self {
                inner: Arc::new(StoreInner {
                    paths,
                    process_lock: Mutex::new(()),
                    handle_registry: Mutex::new(HandleRegistry::default()),
                    home,
                }),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = paths;
            Err(AuthStoreError::BackendUnavailable {
                operation: "open".to_string(),
                message: "confined no-follow storage requires Unix primitives".to_string(),
            })
        }
    }

    /// Compatibility constructor for callers that use `new` for resources.
    pub fn new(paths: AgentPaths) -> Result<Self, AuthStoreError> {
        Self::open(paths)
    }

    /// Resolves an explicit home directory and opens the store below it.
    pub fn from_home(home: impl AsRef<Path>) -> Result<Self, AuthStoreError> {
        let paths = AgentPaths::from_home(home).map_err(|error| AuthStoreError::InvalidPath {
            path: PathBuf::from("<agent home>"),
            reason: error.to_string(),
        })?;
        Self::open(paths)
    }

    /// Returns the paths selected when the store was opened.
    pub fn paths(&self) -> &AgentPaths {
        &self.inner.paths
    }

    /// Loads the sanitized public projection. The underlying YAML secret slots
    /// are zeroized private values and are never returned.
    pub fn load(&self) -> Result<AuthConfig, AuthStoreError> {
        self.with_lock(|store| {
            let document = store.load_locked()?;
            document
                .public_projection(&store.inner.paths.auth)
                .map_err(|error| AuthStoreError::from_auth_config(error, &store.inner.paths.auth))
        })
    }

    pub fn load_metadata(&self, credential_id: &str) -> Result<AuthMetadata, AuthStoreError> {
        let credential_id = checked_credential_id(credential_id)?;
        self.with_lock(|store| {
            let document = store.load_locked()?;
            let credential = document
                .credentials
                .get(credential_id.as_str())
                .ok_or_else(|| AuthStoreError::CredentialNotFound {
                    credential_id: credential_id.to_string(),
                })?;
            Ok(AuthMetadata::from_stored(
                credential_id.as_str(),
                credential,
            ))
        })
    }

    pub fn load_all_metadata(&self) -> Result<Vec<AuthMetadata>, AuthStoreError> {
        self.with_lock(|store| {
            let document = store.load_locked()?;
            Ok(document
                .credentials
                .iter()
                .map(|(id, credential)| AuthMetadata::from_stored(id, credential))
                .collect())
        })
    }

    /// Performs a generic structural CAS update. RSS has already selected the
    /// status and refresh action; this method only validates, persists, and
    /// advances the generation.
    pub fn save_if_generation(
        &self,
        request: SaveCredentialRequest,
    ) -> Result<SaveOutcome, AuthStoreError> {
        request.validate()?;
        let credential_id = request.credential_id.to_string();
        let result = self.with_process_lock(|store| {
            let outcome = store.with_file_lock(|store| {
                let mut document = store.load_locked()?;
                let current = document.credentials.get(&credential_id);
                let actual_generation = current.map_or(0, |credential| credential.generation);
                if actual_generation > request.expected_generation {
                    let current =
                        current.expect("generation is present when greater than expected");
                    return Ok(SaveOutcome::Adopted {
                        metadata: AuthMetadata::from_stored(&credential_id, current),
                    });
                }
                if actual_generation < request.expected_generation {
                    return Err(AuthStoreError::GenerationConflict {
                        credential_id: credential_id.clone(),
                        expected: request.expected_generation,
                        actual: actual_generation,
                    });
                }
                let next_generation =
                    request.expected_generation.checked_add(1).ok_or_else(|| {
                        AuthStoreError::GenerationOverflow {
                            credential_id: credential_id.clone(),
                        }
                    })?;
                let access = request.access_slot.snapshot_text(
                    SecretSlotKind::Access,
                    &credential_id,
                    request.expected_generation,
                    request.policy_generation,
                    &request.run_id,
                )?;
                let refresh = match &request.refresh {
                    RefreshSecretAction::Preserve => {
                        current.and_then(|value| value.refresh_token.clone())
                    }
                    RefreshSecretAction::Replace(slot) => Some(slot.snapshot_text(
                        SecretSlotKind::Refresh,
                        &credential_id,
                        request.expected_generation,
                        request.policy_generation,
                        &request.run_id,
                    )?),
                    RefreshSecretAction::Clear => None,
                };
                let updated = StoredCredentialConfig {
                    provider: request.metadata.provider.clone(),
                    kind: request.metadata.kind.clone(),
                    source: request.metadata.source.clone(),
                    token_type: request.metadata.token_type.clone(),
                    access_token: access,
                    refresh_token: refresh,
                    expires_at_ms: request.metadata.expires_at_ms,
                    scopes: request.metadata.scopes.clone(),
                    account_id: request.metadata.account_id.clone(),
                    generation: next_generation,
                    status: request.metadata.status.clone(),
                    last_refresh_at_ms: request.metadata.last_refresh_at_ms,
                };
                document.credentials.insert(credential_id.clone(), updated);
                store.save_locked(&document)?;
                let saved = document
                    .credentials
                    .get(&credential_id)
                    .expect("saved credential is present");
                let metadata = AuthMetadata::from_stored(&credential_id, saved);
                request.access_slot.consume()?;
                if let RefreshSecretAction::Replace(slot) = &request.refresh {
                    slot.consume()?;
                }
                Ok(SaveOutcome::Committed { metadata })
            })?;
            if matches!(&outcome, SaveOutcome::Committed { .. }) {
                store.revoke_issued_handles(&credential_id);
            }
            Ok(outcome)
        });
        if matches!(
            result,
            Err(AuthStoreError::GenerationConflict { .. }) | Ok(SaveOutcome::Adopted { .. })
        ) {
            request.revoke_slots();
        }
        result
    }

    /// Removes one named credential after host policy checks and preserves all
    /// other entries in the YAML document.
    pub fn delete(&self, credential_id: &str) -> Result<AuthMetadata, AuthStoreError> {
        let credential_id = checked_credential_id(credential_id)?;
        self.with_process_lock(|store| {
            let metadata = store.with_file_lock(|store| {
                let mut document = store.load_locked()?;
                let Some(removed) = document.credentials.remove(credential_id.as_str()) else {
                    return Err(AuthStoreError::CredentialNotFound {
                        credential_id: credential_id.to_string(),
                    });
                };
                store.save_locked(&document)?;
                Ok(AuthMetadata::from_stored(credential_id.as_str(), &removed))
            })?;
            store.revoke_issued_handles(credential_id.as_str());
            Ok(metadata)
        })
    }

    /// Issues a one-shot access handle bound to this credential generation.
    pub fn issue_access_handle(
        &self,
        credential_id: &str,
        generation: u64,
        policy_generation: u64,
        run_id: &str,
    ) -> Result<OpaqueAccessHandle, AuthStoreError> {
        self.issue_access_handle_until(
            credential_id,
            generation,
            policy_generation,
            run_id,
            Instant::now() + ACCESS_HANDLE_TTL,
        )
    }

    /// Issues an access handle whose lifetime is also capped by `request_deadline`.
    pub fn issue_access_handle_until(
        &self,
        credential_id: &str,
        generation: u64,
        policy_generation: u64,
        run_id: &str,
        request_deadline: Instant,
    ) -> Result<OpaqueAccessHandle, AuthStoreError> {
        self.issue_handle(
            credential_id,
            generation,
            policy_generation,
            run_id,
            SecretSlotKind::Access,
            request_deadline,
        )
        .map(OpaqueAccessHandle::from_inner)
    }

    /// Issues a one-shot refresh handle bound to this credential generation.
    pub fn issue_refresh_handle(
        &self,
        credential_id: &str,
        generation: u64,
        policy_generation: u64,
        run_id: &str,
    ) -> Result<OpaqueRefreshHandle, AuthStoreError> {
        self.issue_refresh_handle_until(
            credential_id,
            generation,
            policy_generation,
            run_id,
            Instant::now() + REFRESH_HANDLE_TTL,
        )
    }

    /// Issues a refresh handle whose lifetime is also capped by `request_deadline`.
    pub fn issue_refresh_handle_until(
        &self,
        credential_id: &str,
        generation: u64,
        policy_generation: u64,
        run_id: &str,
        request_deadline: Instant,
    ) -> Result<OpaqueRefreshHandle, AuthStoreError> {
        self.issue_handle(
            credential_id,
            generation,
            policy_generation,
            run_id,
            SecretSlotKind::Refresh,
            request_deadline,
        )
        .map(OpaqueRefreshHandle::from_inner)
    }

    fn issue_handle(
        &self,
        credential_id: &str,
        generation: u64,
        policy_generation: u64,
        run_id: &str,
        kind: SecretSlotKind,
        request_deadline: Instant,
    ) -> Result<Arc<IssuedHandleInner>, AuthStoreError> {
        let credential_id = checked_credential_id(credential_id)?;
        self.with_process_lock(|store| {
            let (expires_at_ms, secret) = store.with_file_lock(|store| {
                let document = store.load_locked()?;
                let credential = document
                    .credentials
                    .get(credential_id.as_str())
                    .ok_or_else(|| AuthStoreError::CredentialNotFound {
                        credential_id: credential_id.to_string(),
                    })?;
                if credential.generation != generation {
                    return Err(AuthStoreError::GenerationConflict {
                        credential_id: credential_id.to_string(),
                        expected: generation,
                        actual: credential.generation,
                    });
                }
                let secret = match kind {
                    SecretSlotKind::Access => credential.access_token.clone(),
                    SecretSlotKind::Refresh => {
                        credential.refresh_token.clone().ok_or_else(|| {
                            AuthStoreError::InvalidMetadata {
                                credential_id: credential_id.to_string(),
                                field: "refresh_token".to_string(),
                                reason: "refresh slot is absent".to_string(),
                            }
                        })?
                    }
                };
                Ok((credential.expires_at_ms, secret))
            })?;
            let expires_at = handle_deadline(kind, expires_at_ms, request_deadline);
            if Instant::now() >= expires_at {
                return Err(AuthStoreError::HandleExpired {
                    credential_id: credential_id.to_string(),
                    kind: kind.as_str().to_string(),
                });
            }
            let slot = OpaqueSecretSlot::from_host_secret_until(
                kind,
                credential_id.as_str(),
                generation,
                policy_generation,
                run_id,
                secret.into_bytes(),
                expires_at,
            )?;
            let inner = Arc::new(IssuedHandleInner {
                kind,
                credential_id: credential_id.to_string(),
                generation,
                policy_generation,
                run_id: run_id.to_string(),
                expires_at,
                state: AtomicU8::new(HANDLE_LIVE),
                slot,
                store: Arc::downgrade(&store.inner),
            });
            store.register_issued(Arc::clone(&inner))?;
            Ok(inner)
        })
    }

    fn save_locked(&self, document: &StoredAuthConfig) -> Result<(), AuthStoreError> {
        document
            .validate(&self.inner.paths.auth)
            .map_err(|error| AuthStoreError::from_auth_config(error, &self.inner.paths.auth))?;
        let yaml = serde_yaml::to_string(document).map_err(|_| AuthStoreError::Serialization {
            message: "auth document serialization failed".to_string(),
        })?;
        let bytes = Zeroizing::new(yaml.into_bytes());
        if bytes.len() > MAX_AUTH_STORE_BYTES {
            return Err(AuthStoreError::FileTooLarge {
                path: self.inner.paths.auth.clone(),
                max_bytes: MAX_AUTH_STORE_BYTES,
            });
        }
        #[cfg(unix)]
        {
            unix::atomic_write(&self.inner.home, &self.inner.paths.auth, &bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = bytes;
            Err(AuthStoreError::BackendUnavailable {
                operation: "save".to_string(),
                message: "confined no-follow storage requires Unix primitives".to_string(),
            })
        }
    }

    fn load_locked(&self) -> Result<StoredAuthConfig, AuthStoreError> {
        #[cfg(unix)]
        {
            let Some(file) = unix::open_auth_file(&self.inner.home, &self.inner.paths.auth)? else {
                return Ok(StoredAuthConfig::empty());
            };
            let bytes = Zeroizing::new(unix::read_bounded(
                file,
                &self.inner.paths.auth,
                MAX_AUTH_STORE_BYTES,
            )?);
            match parse_stored_yaml(&self.inner.paths.auth, &bytes) {
                Ok(document) => Ok(document),
                Err(error) => {
                    let artifact =
                        unix::preserve_corrupt(&self.inner.home, &self.inner.paths.home, &bytes);
                    Err(AuthStoreError::CorruptFile {
                        path: self.inner.paths.auth.clone(),
                        artifact,
                        reason: error.to_string(),
                    })
                }
            }
        }
        #[cfg(not(unix))]
        {
            Err(AuthStoreError::BackendUnavailable {
                operation: "load".to_string(),
                message: "confined no-follow storage requires Unix primitives".to_string(),
            })
        }
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce(&Self) -> Result<T, AuthStoreError>,
    ) -> Result<T, AuthStoreError> {
        self.with_process_lock(|store| store.with_file_lock(operation))
    }

    fn with_process_lock<T>(
        &self,
        operation: impl FnOnce(&Self) -> Result<T, AuthStoreError>,
    ) -> Result<T, AuthStoreError> {
        let process_guard = self
            .inner
            .process_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result = operation(self);
        drop(process_guard);
        result
    }

    fn with_file_lock<T>(
        &self,
        operation: impl FnOnce(&Self) -> Result<T, AuthStoreError>,
    ) -> Result<T, AuthStoreError> {
        #[cfg(unix)]
        let file_guard = unix::lock_file(&self.inner.home, &self.inner.paths.auth_lock)?;
        let result = operation(self);
        #[cfg(unix)]
        drop(file_guard);
        result
    }

    fn registry_lock(&self) -> std::sync::MutexGuard<'_, HandleRegistry> {
        self.inner
            .handle_registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn register_issued(&self, handle: Arc<IssuedHandleInner>) -> Result<(), AuthStoreError> {
        self.registry_lock().register(handle)
    }

    fn unregister_issued(&self, handle: &IssuedHandleInner) {
        self.registry_lock().unregister(handle);
    }

    fn revoke_issued_handles(&self, credential_id: &str) {
        let revoked = self.registry_lock().revoke_credential(credential_id);
        for handle in revoked.access {
            handle.mark_revoked();
        }
        if let Some(handle) = revoked.refresh {
            handle.mark_revoked();
        }
    }

    fn live_store_generation(&self, handle: &IssuedHandleInner) -> Result<u64, AuthStoreError> {
        let document = self.load_locked()?;
        let credential = document
            .credentials
            .get(&handle.credential_id)
            .ok_or_else(|| handle.revoked_error())?;
        Ok(credential.generation)
    }

    fn fail_stale_handle(
        &self,
        handle: &IssuedHandleInner,
        error: AuthStoreError,
    ) -> AuthStoreError {
        handle.mark_revoked();
        self.unregister_issued(handle);
        error
    }

    fn revalidate_issued(&self, handle: &IssuedHandleInner) -> Result<(), AuthStoreError> {
        handle.check_live()?;
        self.with_process_lock(|store| {
            handle.check_live()?;
            match store.with_file_lock(|store| store.live_store_generation(handle)) {
                Ok(actual) if actual == handle.generation => Ok(()),
                Ok(actual) => Err(store.fail_stale_handle(
                    handle,
                    AuthStoreError::GenerationConflict {
                        credential_id: handle.credential_id.clone(),
                        expected: handle.generation,
                        actual,
                    },
                )),
                Err(error @ AuthStoreError::HandleRevoked { .. }) => {
                    Err(store.fail_stale_handle(handle, error))
                }
                Err(error) => Err(error),
            }
        })
    }

    fn consume_issued(&self, handle: &IssuedHandleInner) -> Result<(), AuthStoreError> {
        handle.check_live()?;
        self.with_process_lock(|store| {
            handle.check_live()?;
            match store.with_file_lock(|store| store.live_store_generation(handle)) {
                Ok(actual) if actual == handle.generation => {
                    handle.consume_live()?;
                    store.unregister_issued(handle);
                    Ok(())
                }
                Ok(actual) => Err(store.fail_stale_handle(
                    handle,
                    AuthStoreError::GenerationConflict {
                        credential_id: handle.credential_id.clone(),
                        expected: handle.generation,
                        actual,
                    },
                )),
                Err(error @ AuthStoreError::HandleRevoked { .. }) => {
                    Err(store.fail_stale_handle(handle, error))
                }
                Err(error) => Err(error),
            }
        })
    }
}

impl CredentialStore for AuthStore {
    fn load(&self) -> Result<AuthConfig, AuthStoreError> {
        AuthStore::load(self)
    }

    fn load_metadata(&self, credential_id: &str) -> Result<AuthMetadata, AuthStoreError> {
        AuthStore::load_metadata(self, credential_id)
    }

    fn save_if_generation(
        &self,
        request: SaveCredentialRequest,
    ) -> Result<SaveOutcome, AuthStoreError> {
        AuthStore::save_if_generation(self, request)
    }

    fn delete(&self, credential_id: &str) -> Result<AuthMetadata, AuthStoreError> {
        AuthStore::delete(self, credential_id)
    }
}

fn validate_slot_provenance(
    credential_id: &str,
    _expected_generation: u64,
    policy_generation: u64,
    run_id: &str,
) -> Result<(), AuthStoreError> {
    if CredentialId::new(credential_id.to_string()).is_err() {
        return Err(AuthStoreError::InvalidCredential {
            credential_id: credential_id.to_string(),
            reason: "credential ID is invalid".to_string(),
        });
    }
    if policy_generation == 0 || run_id.is_empty() || run_id.len() > 128 {
        return Err(AuthStoreError::SecretSlotInvalid {
            credential_id: credential_id.to_string(),
            kind: "unknown".to_string(),
            reason: "policy and run provenance are invalid".to_string(),
        });
    }
    if run_id
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(AuthStoreError::SecretSlotInvalid {
            credential_id: credential_id.to_string(),
            kind: "unknown".to_string(),
            reason: "run provenance is not a visible identifier".to_string(),
        });
    }
    Ok(())
}

fn validate_metadata(
    credential_id: &CredentialId,
    metadata: &CredentialConfig,
) -> Result<(), AuthStoreError> {
    for (field, value) in [
        ("provider", metadata.provider.as_str()),
        ("kind", metadata.kind.as_str()),
        ("source", metadata.source.as_str()),
        ("token_type", metadata.token_type.as_str()),
        ("status", metadata.status.as_str()),
    ] {
        if value.is_empty()
            || value.len() > 512
            || value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(AuthStoreError::InvalidMetadata {
                credential_id: credential_id.to_string(),
                field: field.to_string(),
                reason: "must be a bounded visible identifier".to_string(),
            });
        }
    }
    if metadata.expires_at_ms == 0 {
        return Err(AuthStoreError::InvalidMetadata {
            credential_id: credential_id.to_string(),
            field: "expires_at_ms".to_string(),
            reason: "must be nonzero".to_string(),
        });
    }
    for (index, scope) in metadata.scopes.iter().enumerate() {
        if scope.is_empty()
            || scope.len() > 256
            || scope
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(AuthStoreError::InvalidMetadata {
                credential_id: credential_id.to_string(),
                field: format!("scopes[{index}]"),
                reason: "must be a bounded visible identifier".to_string(),
            });
        }
    }
    if let Some(account_id) = metadata.account_id.as_deref()
        && (account_id.is_empty()
            || account_id.len() > 256
            || account_id
                .chars()
                .any(|character| character.is_control() || character.is_whitespace()))
    {
        return Err(AuthStoreError::InvalidMetadata {
            credential_id: credential_id.to_string(),
            field: "account_id".to_string(),
            reason: "must be a bounded visible identifier".to_string(),
        });
    }
    Ok(())
}

fn checked_credential_id(value: &str) -> Result<CredentialId, AuthStoreError> {
    CredentialId::new(value.to_string()).map_err(|error| AuthStoreError::InvalidCredential {
        credential_id: value.to_string(),
        reason: error.to_string(),
    })
}

fn validate_paths(paths: &AgentPaths) -> Result<(), AuthStoreError> {
    if !paths.home.is_absolute() {
        return Err(AuthStoreError::InvalidPath {
            path: paths.home.clone(),
            reason: "agent home must be absolute".to_string(),
        });
    }
    if paths
        .home
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(AuthStoreError::InvalidPath {
            path: paths.home.clone(),
            reason: "agent home contains dot or parent components".to_string(),
        });
    }
    if paths.auth != paths.home.join(AUTH_FILE_NAME)
        || paths.auth_lock != paths.home.join(AUTH_LOCK_FILE_NAME)
    {
        return Err(AuthStoreError::InvalidPath {
            path: paths.auth.clone(),
            reason: "auth and lock paths must be direct children of the selected home".to_string(),
        });
    }
    Ok(())
}

#[cfg(unix)]
mod unix {
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{AuthStoreError, MAX_AUTH_STORE_BYTES};

    pub(super) fn open_home(path: &Path) -> Result<OwnedFd, AuthStoreError> {
        let root = CString::new("/").expect("root has no NUL");
        let fd = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io_error("open home root", path, io::Error::last_os_error()));
        }
        let mut current = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut saw_component = false;
        for component in path.components() {
            let std::path::Component::Normal(component) = component else {
                continue;
            };
            saw_component = true;
            let bytes = component.as_bytes();
            let name = CString::new(bytes).map_err(|_| AuthStoreError::InvalidPath {
                path: path.to_path_buf(),
                reason: "path contains a NUL byte".to_string(),
            })?;
            if is_symlink_at(current.as_raw_fd(), bytes) {
                return Err(AuthStoreError::SymlinkRejected {
                    path: path.to_path_buf(),
                });
            }
            let next = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if next >= 0 {
                current = unsafe { OwnedFd::from_raw_fd(next) };
                continue;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOENT) {
                return Err(map_path_error(path, error));
            }
            let created = unsafe {
                libc::mkdirat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::S_IRWXU as libc::mode_t,
                )
            };
            if created < 0 {
                let create_error = io::Error::last_os_error();
                if create_error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(io_error("create home directory", path, create_error));
                }
            }
            let next = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if next < 0 {
                return Err(map_path_error(path, io::Error::last_os_error()));
            }
            current = unsafe { OwnedFd::from_raw_fd(next) };
        }
        if !saw_component {
            return Err(AuthStoreError::InvalidPath {
                path: path.to_path_buf(),
                reason: "agent home must name a directory below the filesystem root".to_string(),
            });
        }
        let stat = fstat(current.as_raw_fd(), path)?;
        let mode = stat.st_mode as libc::mode_t;
        if mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(AuthStoreError::NonRegularFile {
                path: path.to_path_buf(),
            });
        }
        if stat.st_uid != unsafe { libc::geteuid() } {
            return Err(AuthStoreError::OwnerMismatch {
                path: path.to_path_buf(),
            });
        }
        if mode & 0o077 != 0 || mode & 0o700 != 0o700 {
            return Err(AuthStoreError::InsecurePermissions {
                path: path.to_path_buf(),
                mode: (mode & 0o777) as u32,
            });
        }
        Ok(current)
    }

    pub(super) fn ensure_lock_file(home: &OwnedFd, path: &Path) -> Result<(), AuthStoreError> {
        let name = CString::new(super::AUTH_LOCK_FILE_NAME).expect("constant has no NUL");
        if is_symlink_at(home.as_raw_fd(), super::AUTH_LOCK_FILE_NAME.as_bytes()) {
            return Err(AuthStoreError::SymlinkRejected {
                path: path.to_path_buf(),
            });
        }
        let fd = unsafe {
            libc::openat(
                home.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK,
                libc::S_IRUSR | libc::S_IWUSR,
            )
        };
        if fd < 0 {
            return Err(map_path_error(path, io::Error::last_os_error()));
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        validate_regular(&owned, path, true)
    }

    pub(super) fn open_auth_file(
        home: &OwnedFd,
        path: &Path,
    ) -> Result<Option<OwnedFd>, AuthStoreError> {
        let name = CString::new(super::AUTH_FILE_NAME).expect("constant has no NUL");
        if is_symlink_at(home.as_raw_fd(), super::AUTH_FILE_NAME.as_bytes()) {
            return Err(AuthStoreError::SymlinkRejected {
                path: path.to_path_buf(),
            });
        }
        let fd = unsafe {
            libc::openat(
                home.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(map_path_error(path, error));
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        validate_regular(&owned, path, false)?;
        Ok(Some(owned))
    }

    pub(super) fn lock_file(home: &OwnedFd, path: &Path) -> Result<File, AuthStoreError> {
        let name = CString::new(super::AUTH_LOCK_FILE_NAME).expect("constant has no NUL");
        if is_symlink_at(home.as_raw_fd(), super::AUTH_LOCK_FILE_NAME.as_bytes()) {
            return Err(AuthStoreError::SymlinkRejected {
                path: path.to_path_buf(),
            });
        }
        let fd = unsafe {
            libc::openat(
                home.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(AuthStoreError::Lock {
                path: path.to_path_buf(),
                message: io::Error::last_os_error().to_string(),
            });
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        validate_regular(&owned, path, true)?;
        let raw = owned.as_raw_fd();
        if unsafe { libc::flock(raw, libc::LOCK_EX) } < 0 {
            return Err(AuthStoreError::Lock {
                path: path.to_path_buf(),
                message: io::Error::last_os_error().to_string(),
            });
        }
        Ok(File::from(owned))
    }

    pub(super) fn read_bounded(
        fd: OwnedFd,
        path: &Path,
        max_bytes: usize,
    ) -> Result<Vec<u8>, AuthStoreError> {
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("read auth file", path, error))?;
        if bytes.len() > max_bytes {
            return Err(AuthStoreError::FileTooLarge {
                path: path.to_path_buf(),
                max_bytes,
            });
        }
        Ok(bytes)
    }

    pub(super) fn preserve_corrupt(
        home: &OwnedFd,
        home_path: &Path,
        bytes: &[u8],
    ) -> Option<PathBuf> {
        static CORRUPT_COUNTER: AtomicU64 = AtomicU64::new(0);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        for _ in 0..128 {
            let counter = CORRUPT_COUNTER.fetch_add(1, Ordering::Relaxed);
            let name = format!(
                "{}.corrupt-{}-{}-{}",
                super::AUTH_FILE_NAME,
                timestamp,
                std::process::id(),
                counter
            );
            let c_name = CString::new(name.as_bytes()).expect("generated name has no NUL");
            let fd = unsafe {
                libc::openat(
                    home.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    libc::S_IRUSR | libc::S_IWUSR,
                )
            };
            if fd < 0 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                return None;
            }
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            let mut file = File::from(owned);
            if file.write_all(bytes).is_err() || file.sync_all().is_err() {
                drop(file);
                unlink(home, &name);
                return None;
            }
            drop(file);
            let _ = unsafe { libc::fsync(home.as_raw_fd()) };
            return Some(home_path.join(name));
        }
        None
    }

    pub(super) fn atomic_write(
        home: &OwnedFd,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), AuthStoreError> {
        static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut temporary_name = String::new();
        let mut temporary_fd = None;
        for _ in 0..128 {
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            temporary_name = format!(".auth.yaml.tmp.{}.{}", std::process::id(), counter);
            let name = CString::new(temporary_name.as_bytes()).expect("generated name has no NUL");
            let fd = unsafe {
                libc::openat(
                    home.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    libc::S_IRUSR | libc::S_IWUSR,
                )
            };
            if fd >= 0 {
                temporary_fd = Some(unsafe { OwnedFd::from_raw_fd(fd) });
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(io_error("create auth replacement", path, error));
            }
        }
        let Some(temporary_fd) = temporary_fd else {
            return Err(io_error(
                "create auth replacement",
                path,
                io::Error::from_raw_os_error(libc::EEXIST),
            ));
        };
        let temporary_path = Path::new(&temporary_name);
        let mut temporary_file = File::from(temporary_fd);
        if let Err(error) = temporary_file.write_all(bytes) {
            drop(temporary_file);
            unlink(home, &temporary_name);
            return Err(io_error("write auth replacement", path, error));
        }
        if let Err(error) = temporary_file.sync_all() {
            drop(temporary_file);
            unlink(home, &temporary_name);
            return Err(io_error("fsync auth replacement", path, error));
        }
        if let Err(error) = validate_regular_raw(temporary_file.as_raw_fd(), path, false) {
            drop(temporary_file);
            unlink(home, &temporary_name);
            return Err(error);
        }
        drop(temporary_file);
        match open_auth_file(home, path) {
            Ok(Some(existing)) => drop(existing),
            Ok(None) => {}
            Err(error) => {
                unlink(home, &temporary_name);
                return Err(error);
            }
        }
        let source =
            CString::new(temporary_path.as_os_str().as_bytes()).expect("generated name has no NUL");
        let destination = CString::new(super::AUTH_FILE_NAME).expect("constant has no NUL");
        if unsafe {
            libc::renameat(
                home.as_raw_fd(),
                source.as_ptr(),
                home.as_raw_fd(),
                destination.as_ptr(),
            )
        } < 0
        {
            let error = io::Error::last_os_error();
            unlink(home, &temporary_name);
            return Err(io_error("publish auth replacement", path, error));
        }
        if unsafe { libc::fsync(home.as_raw_fd()) } < 0 {
            return Err(io_error(
                "fsync auth directory",
                path,
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    fn unlink(home: &OwnedFd, name: &str) {
        let Ok(name) = CString::new(name.as_bytes()) else {
            return;
        };
        unsafe {
            libc::unlinkat(home.as_raw_fd(), name.as_ptr(), 0);
        }
    }

    fn validate_regular(fd: &OwnedFd, path: &Path, lock: bool) -> Result<(), AuthStoreError> {
        validate_regular_raw(fd.as_raw_fd(), path, lock)
    }

    fn validate_regular_raw(raw: RawFd, path: &Path, lock: bool) -> Result<(), AuthStoreError> {
        let stat = fstat(raw, path)?;
        let mode = stat.st_mode as libc::mode_t;
        if mode & libc::S_IFMT == libc::S_IFLNK {
            return Err(AuthStoreError::SymlinkRejected {
                path: path.to_path_buf(),
            });
        }
        if mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 1 {
            return Err(AuthStoreError::NonRegularFile {
                path: path.to_path_buf(),
            });
        }
        if stat.st_uid != unsafe { libc::geteuid() } {
            return Err(AuthStoreError::OwnerMismatch {
                path: path.to_path_buf(),
            });
        }
        let mode = mode & 0o777;
        if mode != 0o600 || (lock && mode & 0o077 != 0) {
            return Err(AuthStoreError::InsecurePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
        Ok(())
    }

    fn fstat(fd: RawFd, path: &Path) -> Result<libc::stat, AuthStoreError> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        let result = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
        if result < 0 {
            return Err(io_error("stat auth path", path, io::Error::last_os_error()));
        }
        Ok(unsafe { stat.assume_init() })
    }

    fn is_symlink_at(parent: RawFd, name: &[u8]) -> bool {
        let Ok(name) = CString::new(name) else {
            return false;
        };
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                parent,
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result < 0 {
            return false;
        }
        let stat = unsafe { stat.assume_init() };
        (stat.st_mode as libc::mode_t) & libc::S_IFMT == libc::S_IFLNK
    }

    fn map_path_error(path: &Path, error: io::Error) -> AuthStoreError {
        match error.raw_os_error() {
            Some(libc::ELOOP) => AuthStoreError::SymlinkRejected {
                path: path.to_path_buf(),
            },
            _ => io_error("open auth path", path, error),
        }
    }

    fn io_error(operation: &str, path: &Path, error: io::Error) -> AuthStoreError {
        AuthStoreError::Io {
            operation: operation.to_string(),
            path: path.to_path_buf(),
            message: error.to_string(),
        }
    }

    const _: usize = MAX_AUTH_STORE_BYTES;
}

impl From<TokenError> for AuthStoreError {
    fn from(error: TokenError) -> Self {
        Self::InvalidCredential {
            credential_id: "<invalid>".to_string(),
            reason: error.to_string(),
        }
    }
}

impl AuthStore {
    #[cfg(any(test, feature = "config-fixture"))]
    pub(crate) fn fixture_secret_slot(
        &self,
        kind: SecretSlotKind,
        credential_id: &str,
        expected_generation: u64,
        policy_generation: u64,
        run_id: &str,
        secret: &str,
    ) -> Result<OpaqueSecretSlot, AuthStoreError> {
        OpaqueSecretSlot::from_host_secret(
            kind,
            credential_id,
            expected_generation,
            policy_generation,
            run_id,
            Zeroizing::new(secret.as_bytes().to_vec()),
        )
    }

    /// Host-only test helper: mint an access secret slot without exposing bytes.
    #[cfg(any(test, feature = "config-fixture"))]
    pub fn fixture_access_slot(
        &self,
        credential_id: &str,
        expected_generation: u64,
        policy_generation: u64,
        run_id: &str,
        secret: &str,
    ) -> Result<OpaqueSecretSlot, AuthStoreError> {
        self.fixture_secret_slot(
            SecretSlotKind::Access,
            credential_id,
            expected_generation,
            policy_generation,
            run_id,
            secret,
        )
    }

    /// Host-only test helper: mint an access secret slot with an explicit deadline.
    #[cfg(any(test, feature = "config-fixture"))]
    #[allow(clippy::too_many_arguments)]
    pub fn fixture_access_slot_until(
        &self,
        credential_id: &str,
        expected_generation: u64,
        policy_generation: u64,
        run_id: &str,
        secret: &str,
        expires_at: Instant,
    ) -> Result<OpaqueSecretSlot, AuthStoreError> {
        OpaqueSecretSlot::from_host_secret_until(
            SecretSlotKind::Access,
            credential_id,
            expected_generation,
            policy_generation,
            run_id,
            Zeroizing::new(secret.as_bytes().to_vec()),
            expires_at,
        )
    }

    /// Host-only test helper: mint a refresh secret slot without exposing bytes.
    #[cfg(any(test, feature = "config-fixture"))]
    pub fn fixture_refresh_slot(
        &self,
        credential_id: &str,
        expected_generation: u64,
        policy_generation: u64,
        run_id: &str,
        secret: &str,
    ) -> Result<OpaqueSecretSlot, AuthStoreError> {
        self.fixture_secret_slot(
            SecretSlotKind::Refresh,
            credential_id,
            expected_generation,
            policy_generation,
            run_id,
            secret,
        )
    }
}
