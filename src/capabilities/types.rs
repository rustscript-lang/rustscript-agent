//! Generic capability types. Public tool names are opaque metadata.

use std::path::PathBuf;
use std::time::Instant;

use serde_json::Value;

/// Validated profile/session/run identity bound to a lifecycle engine.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapabilityOwner {
    profile: String,
    session: String,
    run: String,
}

impl CapabilityOwner {
    /// Parse a profile/session/run triple.
    pub fn new(
        profile: impl Into<String>,
        session: impl Into<String>,
        run: impl Into<String>,
    ) -> Result<Self, String> {
        Ok(Self {
            profile: validate_label(profile.into(), "profile")?,
            session: validate_label(session.into(), "session")?,
            run: validate_label(run.into(), "run")?,
        })
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn run(&self) -> &str {
        &self.run
    }

    pub fn key(&self) -> String {
        format!("{}/{}/{}", self.profile, self.session, self.run)
    }

    pub fn with_run(&self, run_id: &str) -> String {
        format!("{}/{}/{}", self.profile, self.session, run_id)
    }
}

fn validate_label(value: String, name: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    if value.contains('\0') {
        return Err(format!("{name} is invalid"));
    }
    if value.len() > 128 {
        return Err(format!("{name} exceeds the configured bound"));
    }
    Ok(value)
}

/// Native capability risk ceiling. Ordering is the approval lattice.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CapabilityRisk {
    Read,
    Write,
    Execute,
}

impl CapabilityRisk {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
        }
    }

    pub fn parse(value: &str) -> Result<Self, LifecycleError> {
        match value {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "execute" => Ok(Self::Execute),
            _ => Err(LifecycleError::InvalidMetadata(
                "unsupported risk class".to_string(),
            )),
        }
    }
}

/// RSS-supplied prepare metadata. `tool_name` is opaque.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareMetadata {
    pub run_id: String,
    pub call_id: String,
    pub tool_name: String,
    pub argument_digest: String,
    pub registry_identity: String,
    pub risk_class: CapabilityRisk,
    pub summary: String,
}

/// Durable started record committed before a token is issued.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableStarted {
    pub run_id: String,
    pub call_id: String,
    pub tool_name: String,
    pub argument_digest: String,
    pub registry_identity: String,
    pub risk_class: CapabilityRisk,
    pub summary: String,
    pub generation: u64,
}

/// Successful prepare result.
#[derive(Clone, Debug, PartialEq)]
pub enum PrepareOutcome {
    Execute {
        execution_token: String,
        deadline_ms: u64,
    },
    Replay {
        result: Value,
    },
}

/// Successful commit result.
#[derive(Clone, Debug, PartialEq)]
pub struct CommitOutcome {
    pub envelope: Value,
}

/// Run/tool-call ceilings applied by prepare/commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleLimits {
    pub max_tool_calls: u64,
    pub max_output_bytes: usize,
    pub max_summary_bytes: usize,
}

/// Typed lifecycle failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    OwnerMismatch {
        expected: String,
        actual: String,
    },
    InactiveRun,
    MissingParent,
    ApprovalDenied {
        reason: String,
    },
    ApprovalCeiling {
        requested: CapabilityRisk,
        ceiling: CapabilityRisk,
    },
    DeadlineElapsed,
    Cancelled,
    DuplicateClose,
    TokenUnknown,
    LimitExceeded,
    StartedCommitFailed(String),
    ResultCommitFailed(String),
    ResultTooLarge,
    Interrupted,
    RegistryMismatch,
    InvalidMetadata(String),
}

impl LifecycleError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::OwnerMismatch { .. } => "owner_mismatch",
            Self::InactiveRun => "inactive_run",
            Self::MissingParent => "missing_parent",
            Self::ApprovalDenied { .. } => "approval_denied",
            Self::ApprovalCeiling { .. } => "approval_ceiling",
            Self::DeadlineElapsed => "deadline_elapsed",
            Self::Cancelled => "cancelled",
            Self::DuplicateClose => "duplicate_close",
            Self::TokenUnknown => "token_unknown",
            Self::LimitExceeded => "max_tool_calls",
            Self::StartedCommitFailed(_) => "started_commit_failed",
            Self::ResultCommitFailed(_) => "result_commit_failed",
            Self::ResultTooLarge => "result_too_large",
            Self::Interrupted => "interrupted",
            Self::RegistryMismatch => "registry_mismatch",
            Self::InvalidMetadata(_) => "invalid_metadata",
        }
    }
}

/// Frozen claims bound to one unforgeable execution token.
#[derive(Clone, Debug)]
pub struct TokenClaims {
    pub owner: CapabilityOwner,
    pub call_id: String,
    pub tool_name: String,
    pub argument_digest: String,
    pub registry_identity: String,
    pub risk_ceiling: CapabilityRisk,
    pub output_budget: usize,
    pub generation: u64,
    pub deadline: Instant,
    pub deadline_ms: u64,
    pub workspace: PathBuf,
}
