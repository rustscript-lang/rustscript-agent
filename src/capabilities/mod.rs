//! Generic Rust capabilities: lifecycle tokens and host adapters.

pub mod host;
pub mod lifecycle;
pub mod types;

pub use host::{error_envelope, parse_prepare_metadata, tool_commit, tool_prepare};
pub use lifecycle::{
    AllowAllApproval, ApprovalGate, CancellationFlag, CapabilityLifecycle,
    CapabilityLifecycleBuilder, DurableToolLifecycle, ExecutionLease, LifecycleClock,
    NeverCancelled, SystemClock, TokenIssuer, UuidIssuer,
};
pub use types::{
    CapabilityOwner, CapabilityRisk, CommitOutcome, DurableStarted, LifecycleError,
    LifecycleLimits, PrepareMetadata, PrepareOutcome, TokenClaims,
};
