//! Typed values for the Native filesystem effect.
//!
//! These types carry owner capability, epoch, and quota. They do not open a
//! database, talk to a plugin host, or snapshot remote effects.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::Mutex;
use uuid::Uuid;
use zeroize::Zeroize;

pub const MAX_TREE_ENTRIES: u64 = 1_000_000;
pub const MAX_TREE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_TREE_DEPTH: u32 = 32;
pub(crate) const MAX_COMPONENT_BYTES: usize = 255;
pub(crate) const MAX_RELATIVE_BYTES: usize = 4096;
pub(crate) const MAX_LINEAGE: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectErrorKind {
    AuthorityRequired,
    OwnerMismatch,
    Revoked,
    StaleEpoch,
    Conflict,
    Busy,
    CheckpointBusy,
    NotFound,
    RejectedPath,
    UnsupportedEntry,
    UnsupportedPlatform,
    QuotaExceeded,
    InvalidConfiguration,
    InconsistentSource,
    Cancelled,
    DeadlineExceeded,
    SchemaRejected,
    Io,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectError {
    kind: EffectErrorKind,
    message: String,
}

impl EffectError {
    pub fn kind(&self) -> EffectErrorKind {
        self.kind
    }

    pub(crate) fn new(kind: EffectErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for EffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for EffectError {}

#[derive(Debug)]
pub struct EffectFailure<T> {
    pub error: EffectError,
    pub recovered: T,
}

impl<T> EffectFailure<T> {
    pub(crate) fn new(error: EffectError, recovered: T) -> Self {
        Self { error, recovered }
    }
}

macro_rules! id_newtype {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Debug, Eq, PartialEq, Hash)]
        pub struct $name(String);

        impl $name {
            pub(crate) fn fresh() -> Self {
                Self(format!("{}-{}", $prefix, Uuid::new_v4().simple()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub(crate) fn parse(value: &str) -> Result<Self, EffectError> {
                parse_id($prefix, value).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

id_newtype!(WorkspaceId, "ws");
id_newtype!(OwnerId, "own");
id_newtype!(BranchId, "br");
id_newtype!(TreeId, "tree");
id_newtype!(CheckpointId, "ckpt");

impl WorkspaceId {
    pub fn parse_public(value: &str) -> Result<Self, EffectError> {
        Self::parse(value)
    }
}

fn parse_id(prefix: &str, value: &str) -> Result<String, EffectError> {
    let Some(rest) = value.strip_prefix(prefix) else {
        return Err(EffectError::new(
            EffectErrorKind::SchemaRejected,
            "identifier prefix is not valid",
        ));
    };
    let Some(hex) = rest.strip_prefix('-') else {
        return Err(EffectError::new(
            EffectErrorKind::SchemaRejected,
            "identifier is missing its separator",
        ));
    };
    if hex.len() == 32
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(value.to_string())
    } else {
        Err(EffectError::new(
            EffectErrorKind::SchemaRejected,
            "identifier is not 32 lowercase hex characters",
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct BranchEpoch(u64);

impl BranchEpoch {
    pub fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn initial() -> Self {
        Self(1)
    }

    pub(crate) fn from_raw(value: u64) -> Result<Self, EffectError> {
        if value == 0 {
            Err(EffectError::new(
                EffectErrorKind::SchemaRejected,
                "epoch must be at least 1",
            ))
        } else {
            Ok(Self(value))
        }
    }

    pub(crate) fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportConsistency {
    OrdinaryCopy,
}

impl ImportConsistency {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::OrdinaryCopy => "ordinary_copy",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, EffectError> {
        match value {
            "ordinary_copy" => Ok(Self::OrdinaryCopy),
            _ => Err(EffectError::new(
                EffectErrorKind::SchemaRejected,
                "import consistency is not ordinary_copy",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceQuota {
    pub(crate) max_entries: u64,
    pub(crate) max_bytes: u64,
    pub(crate) max_depth: u32,
}

impl ResourceQuota {
    pub fn new(max_entries: u64, max_bytes: u64, max_depth: u32) -> Result<Self, EffectError> {
        if max_entries == 0
            || max_entries > MAX_TREE_ENTRIES
            || max_bytes == 0
            || max_bytes > MAX_TREE_BYTES
            || max_depth == 0
            || max_depth > MAX_TREE_DEPTH
        {
            return Err(EffectError::new(
                EffectErrorKind::InvalidConfiguration,
                "quota is zero or above the hard ceiling",
            ));
        }
        Ok(Self {
            max_entries,
            max_bytes,
            max_depth,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EffectDeadline {
    at: Instant,
}

impl EffectDeadline {
    pub fn at(absolute: Instant) -> Self {
        Self { at: absolute }
    }

    pub(crate) fn check(self) -> Result<(), EffectError> {
        if Instant::now() >= self.at {
            Err(EffectError::new(
                EffectErrorKind::DeadlineExceeded,
                "deadline already passed",
            ))
        } else {
            Ok(())
        }
    }
}

type CheckHook = Arc<dyn Fn(u64) + Send + Sync>;

#[derive(Clone)]
pub struct EffectCancellation {
    inner: Arc<CancelInner>,
}

struct CancelInner {
    native_check: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    flag: AtomicBool,
    cancel_at: AtomicU64,
    checks: AtomicU64,
    hook: Mutex<Option<CheckHook>>,
}

impl fmt::Debug for EffectCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectCancellation")
            .field("cancelled", &self.inner.flag.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl EffectCancellation {
    pub fn new() -> Self {
        Self::with_native_check(None)
    }

    pub(crate) fn linked(check: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self::with_native_check(Some(Arc::new(check)))
    }

    fn with_native_check(native_check: Option<Arc<dyn Fn() -> bool + Send + Sync>>) -> Self {
        Self {
            inner: Arc::new(CancelInner {
                native_check,
                flag: AtomicBool::new(false),
                cancel_at: AtomicU64::new(u64::MAX),
                checks: AtomicU64::new(0),
                hook: Mutex::new(None),
            }),
        }
    }

    pub fn cancel(&self) {
        self.inner.flag.store(true, Ordering::SeqCst);
    }

    pub fn cancel_at_check(&self, check: u64) {
        self.inner.cancel_at.store(check, Ordering::SeqCst);
    }

    pub fn set_before_check_hook(&self, hook: impl Fn(u64) + Send + Sync + 'static) {
        *self.inner.hook.lock() = Some(Arc::new(hook));
    }

    /// Numbered check used at copy boundaries. Scan does not consume these.
    pub(crate) fn poll(&self) -> Result<(), EffectError> {
        let check = self.inner.checks.fetch_add(1, Ordering::SeqCst) + 1;
        let cancel_at = self.inner.cancel_at.load(Ordering::SeqCst);
        if check >= cancel_at {
            self.inner.flag.store(true, Ordering::SeqCst);
        }
        let hook = self.inner.hook.lock().clone();
        if let Some(hook) = hook {
            hook(check);
        }
        self.poll_quiet()
    }

    pub(crate) fn poll_quiet(&self) -> Result<(), EffectError> {
        if self.inner.flag.load(Ordering::SeqCst)
            || self
                .inner
                .native_check
                .as_ref()
                .is_some_and(|check| check())
        {
            Err(EffectError::new(
                EffectErrorKind::Cancelled,
                "cancellation requested",
            ))
        } else {
            Ok(())
        }
    }
}

impl Default for EffectCancellation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub(crate) struct CapabilitySecret([u8; 32]);

impl CapabilitySecret {
    pub(crate) fn fresh() -> Self {
        let mut bytes = [0_u8; 32];
        bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        Self(bytes)
    }
}

impl PartialEq for CapabilitySecret {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for CapabilitySecret {}

impl fmt::Debug for CapabilitySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapabilitySecret([redacted])")
    }
}

impl Drop for CapabilitySecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug)]
pub struct ImportWorkspace {
    pub source: std::path::PathBuf,
    pub quota: ResourceQuota,
    pub cancellation: EffectCancellation,
    pub deadline: EffectDeadline,
}

#[derive(Clone, Debug)]
pub struct OpenViewRequest {
    pub expected_head: TreeId,
    pub expected_epoch: BranchEpoch,
    pub cancellation: EffectCancellation,
    pub deadline: EffectDeadline,
}

#[derive(Clone, Debug)]
pub struct PublishRequest {
    pub expected_head: TreeId,
    pub expected_epoch: BranchEpoch,
    pub cancellation: EffectCancellation,
    pub deadline: EffectDeadline,
}

#[derive(Clone, Debug)]
pub struct CheckpointRequest {
    pub cancellation: EffectCancellation,
    pub deadline: EffectDeadline,
}

#[derive(Clone, Debug)]
pub struct RestoreRequest {
    pub checkpoint_id: CheckpointId,
    pub expected_head: TreeId,
    pub expected_epoch: BranchEpoch,
    pub cancellation: EffectCancellation,
    pub deadline: EffectDeadline,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicWorkspaceRef {
    pub workspace_id: WorkspaceId,
    pub branch_id: BranchId,
    pub head: TreeId,
    pub epoch: BranchEpoch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicCheckpointRef {
    pub workspace_id: WorkspaceId,
    pub checkpoint_id: CheckpointId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publication {
    pub head: TreeId,
    pub epoch: BranchEpoch,
    pub previous_head: TreeId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalKind {
    Imported,
    Published,
    Discarded,
    Checkpoint,
    Restored,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalEntry {
    pub kind: JournalKind,
    pub branch_id: BranchId,
    pub head: TreeId,
    pub epoch: BranchEpoch,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEffectNotice {
    kind: String,
    reference: String,
}
