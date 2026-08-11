//! RustScript agent runner and Hermes-compatible gateway.
//!
//! The agent runner invokes an exported RSS `run(context)` callable and
//! consumes the core invocation item stream: zero or more `Event(Value)`
//! items, then exactly one `Complete(Value)` or typed error, then a fused end
//! of stream. The structured run context is the sole callable argument; the
//! script-visible event builtin is `stream::emit(value)`.

pub mod gateway;
pub mod runtime;

pub use gateway::{AgentGatewayConfig, AgentGatewayState, build_agent_gateway_app};
pub use runtime::rss_runner::{
    AgentConfig, AgentError, AgentRunner, MAX_AGENT_SOURCE_BYTES, RUN_EPOCH_CHECK_INTERVAL,
    RUN_EPOCH_DEADLINE_TICKS, Result, RunCancellation, RunDeliveryError, RunError, RunEventSink,
};
