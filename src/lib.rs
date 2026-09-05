//! RustScript agent runner and Hermes-compatible gateway.
//!
//! The agent runner invokes an exported RSS `run(context)` callable and
//! consumes the core invocation item stream: zero or more `Event(Value)`
//! items, then exactly one `Complete(Value)` or typed error, then a fused end
//! of stream. The structured run context is the sole callable argument; the
//! script-visible event builtin is `stream::emit(value)`.

pub mod capabilities;
pub mod config;
pub mod domain;
pub mod events;
pub mod gateway;
pub mod metrics;
pub mod prompt;
pub mod registry;
pub mod runtime;
pub mod service;
pub mod tool_result;
pub mod tool_schema;

mod durable_provider;

pub use config::{AgentGatewayConfig, TelegramConfig};
pub use domain::{
    AgentEventEnvelope, InboundEnvelope, LlmContentBlock, LlmEvent, LlmMessage, LlmRequest,
    LlmResponse, ProviderError, RunContext, Sampling, ToolCall, Usage, decode_message_blocks,
    decode_message_content, encode_message_content, provider_pending_may_retry,
    truncate_utf8_chars,
};
pub use events::{DurableEventCommitter, EventCommitError};
pub use gateway::store::GatewayPersistence;
pub use gateway::{AgentGatewayState, build_agent_gateway_app};
pub use registry::{
    SchemaValidationError, SchemaValidationErrorKind, ToolRegistry, ToolRegistryEntry,
    ToolRegistryError, ToolRegistrySnapshot, validate_json_schema,
};
pub use runtime::rss_runner::{
    AgentConfig, AgentError, AgentRunner, MAX_AGENT_SOURCE_BYTES, RUN_EPOCH_CHECK_INTERVAL,
    RUN_EPOCH_DEADLINE_TICKS, Result, RunCancellation, RunDeliveryError, RunError, RunEventSink,
    RunnerPrepareFault, bundled_dispatch_runner, bundled_tool_entries, bundled_tool_registry,
};
pub use runtime::{
    AgentHostBridges, AgentProviderHost, ControlCheckHook, ScriptedProvider, agent_host_catalog,
};
pub use service::{
    AdmitError, AdmitRunRequest, AdmittedRun, AgentService, CleanupOutcome, ProviderCommit,
    ProviderCommitOutcome, ProviderPendingDecision, RunHandle,
};
pub use tool_result::{ToolError, ToolOwner, ToolResult};
pub use tool_schema::{
    RiskClass, ToolDescriptor, Toolset, UnsupportedRiskClass, UnsupportedToolset,
};
