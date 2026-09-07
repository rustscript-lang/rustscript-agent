//! Generic Rust capabilities: lifecycle tokens, confined IO, and host adapters.

pub mod artifacts;
pub mod filesystem;
pub mod host;
pub mod lifecycle;
pub mod process;
pub mod types;

mod confined_io;
mod hash;

pub use artifacts::{ArtifactCapability, ArtifactLimits, ArtifactRef};
pub use filesystem::{
    FilesystemCapability, FilesystemLimits, FsDirEntry, FsList, FsMetadata, FsRead, FsWrite,
};
pub use host::{
    capability_error_envelope, error_envelope, parse_prepare_metadata, tool_commit, tool_prepare,
};
pub use lifecycle::{
    AllowAllApproval, ApprovalGate, CancellationFlag, CapabilityLifecycle,
    CapabilityLifecycleBuilder, DurableToolLifecycle, ExecutionLease, LifecycleClock,
    NeverCancelled, SystemClock, TokenIssuer, UuidIssuer,
};
pub use process::{ProcessCapability, ProcessLimits, ProcessSnapshot, ProcessSpawn};
pub use types::{
    CapabilityError, CapabilityOwner, CapabilityRisk, CommitOutcome, DurableStarted,
    LifecycleError, LifecycleLimits, PrepareMetadata, PrepareOutcome, TokenClaims,
};
