//! RSS run execution and the agent runtime.

pub(crate) mod delivery;
pub mod rss_runner;

pub use rss_runner::{
    AgentConfig, AgentError, AgentRunner, MAX_AGENT_SOURCE_BYTES, RUN_EPOCH_CHECK_INTERVAL,
    RUN_EPOCH_DEADLINE_TICKS, Result, RunCancellation, RunDeliveryError, RunError, RunEventSink,
};
