pub mod process;
pub mod registry;
pub mod terminal;
pub mod types;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use process::{
    ProcessAction, ProcessArtifactSink, ProcessExecutor, ProcessOwner, ProcessRequest, ProcessTable,
};
pub use registry::{
    SchemaValidationError, SchemaValidationErrorKind, ToolRegistry, ToolRegistryEntry,
    ToolRegistryError, ToolRegistrySnapshot, builtin_entries, builtin_tool_registry,
    default_tool_registry, validate_json_schema,
};
pub use terminal::{TerminalExecutor, TerminalRequest};
pub use types::{
    NativeExecutorContract, NativeToolExecutor, RiskClass, ToolDescriptor, Toolset,
    UnsupportedRiskClass, UnsupportedToolset,
};

/// Common bounded envelope returned by native tool executors.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    pub ok: bool,
    pub content: String,
    pub data: Value,
    pub error: Option<ToolError>,
    pub truncated: bool,
    pub artifacts: Vec<String>,
}

/// Typed failure carried in [`ToolResult::error`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolError {
    pub code: String,
    pub message: String,
}

impl ToolResult {
    pub fn success(content: impl Into<String>, data: Value) -> Self {
        Self {
            ok: true,
            content: content.into(),
            data,
            error: None,
            truncated: false,
            artifacts: Vec::new(),
        }
    }

    pub fn failure(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            content: String::new(),
            data: Value::Object(serde_json::Map::new()),
            error: Some(ToolError {
                code: code.into(),
                message: message.into(),
            }),
            truncated: false,
            artifacts: Vec::new(),
        }
    }

    pub fn failure_with(
        code: impl Into<String>,
        message: impl Into<String>,
        content: impl Into<String>,
        data: Value,
        truncated: bool,
    ) -> Self {
        Self {
            ok: false,
            content: content.into(),
            data,
            error: Some(ToolError {
                code: code.into(),
                message: message.into(),
            }),
            truncated,
            artifacts: Vec::new(),
        }
    }
}

pub(crate) fn builtin_descriptor(name: &str) -> ToolDescriptor {
    builtin_entries()
        .into_iter()
        .find(|entry| entry.descriptor.name == name)
        .expect("builtin registry must contain the native tool")
        .descriptor
}
