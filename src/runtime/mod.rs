//! RSS run execution and the agent runtime.

pub(crate) mod agent_host;
pub(crate) mod delivery;
pub mod rss_runner;

pub use agent_host::{AgentHostBridges, AgentProviderHost, ScriptedProvider, agent_host_catalog};
pub use rss_runner::{
    AgentConfig, AgentError, AgentRunner, MAX_AGENT_SOURCE_BYTES, RUN_EPOCH_CHECK_INTERVAL,
    RUN_EPOCH_DEADLINE_TICKS, Result, RunCancellation, RunDeliveryError, RunError, RunEventSink,
    RunnerPrepareFault,
};
