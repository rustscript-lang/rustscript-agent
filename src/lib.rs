//! RustScript agent runner and Hermes-compatible gateway.
//!
//! The agent runner invokes an exported RSS `run(context)` callable and
//! consumes the core invocation item stream: zero or more `Event(Value)`
//! items, then exactly one `Complete(Value)` or typed error, then a fused end
//! of stream. The structured run context is the sole callable argument; the
//! script-visible event builtin is `stream::emit(value)`.

pub mod config;
pub mod domain;
pub mod events;
pub mod gateway;
pub mod metrics;
pub mod prompt;
pub mod runtime;
pub mod service;
pub mod tools;

pub use config::{AgentGatewayConfig, TelegramConfig};
pub use domain::{
    AgentEventEnvelope, InboundEnvelope, LlmContentBlock, LlmEvent, LlmMessage, LlmRequest,
    LlmResponse, ProviderError, RunContext, Sampling, ToolCall, Usage,
};
pub use gateway::store::GatewayPersistence;
pub use gateway::{AgentGatewayState, build_agent_gateway_app};
pub use runtime::rss_runner::{
    AgentConfig, AgentError, AgentRunner, MAX_AGENT_SOURCE_BYTES, RUN_EPOCH_CHECK_INTERVAL,
    RUN_EPOCH_DEADLINE_TICKS, Result, RunCancellation, RunDeliveryError, RunError, RunEventSink,
};
pub use runtime::{AgentHostBridges, AgentProviderHost, ScriptedProvider};
pub use service::{AdmitError, AdmitRunRequest, AdmittedRun, AgentService, RunHandle};
pub use tools::{
    NativeExecutorContract, NativeToolExecutor, RiskClass, SchemaValidationError,
    SchemaValidationErrorKind, ToolDescriptor, ToolRegistry, ToolRegistryEntry, ToolRegistryError,
    ToolRegistrySnapshot, Toolset, UnsupportedRiskClass, UnsupportedToolset, builtin_entries,
    builtin_tool_registry, default_tool_registry, validate_json_schema,
};
