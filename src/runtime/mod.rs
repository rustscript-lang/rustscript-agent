//! RSS run execution and the agent runtime.

pub(crate) mod agent_host;
pub mod auth_runner;
pub(crate) mod cancellation;
pub(crate) mod closed_bundle;
pub(crate) mod delivery;
pub(crate) mod host_compose;
pub(crate) mod host_types;
pub(crate) mod host_wait;
pub(crate) mod module_snapshot;
pub mod rss_runner;

pub use agent_host::{
    AgentHostBridges, AgentProviderHost, ControlCheckHook, ScriptedProvider, agent_host_catalog,
};
pub use auth_runner::{AuthCommandInput, AuthEntryError, AuthEntryRunner};
pub use rss_runner::{
    AgentConfig, AgentError, AgentRunner, MAX_AGENT_SOURCE_BYTES, RUN_EPOCH_CHECK_INTERVAL,
    RUN_EPOCH_DEADLINE_TICKS, Result, RunCancellation, RunDeliveryError, RunError, RunEventSink,
    RunnerPrepareFault, set_after_snapshot_hook,
};
