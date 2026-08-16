//! RSS run execution and the agent runtime.

pub mod approval_bridge;
pub(crate) mod delivery;
pub mod rss_runner;
pub mod subagent_supervisor;

pub use rss_runner::{
    AgentConfig, AgentError, AgentRunner, MAX_AGENT_SOURCE_BYTES, RUN_EPOCH_CHECK_INTERVAL,
    RUN_EPOCH_DEADLINE_TICKS, Result, RunCancellation, RunDeliveryError, RunError, RunEventSink,
};

pub use approval_bridge::{
    ApprovalBridge, ApprovalDecision, ApprovalError, ApprovalMode, NativeDenyPolicy,
    PendingApproval, Resolution, RiskClass,
};
pub use subagent_supervisor::{
    ChildExecutor, ChildOutcome, ChildSpec, SupervisionMode, SupervisorCancel, supervise_batch,
    supervise_batch_bounded,
};
