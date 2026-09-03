pub mod artifacts;
pub mod dispatch;
pub mod files;
pub mod process;
pub mod registry;
pub mod terminal;
pub mod types;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use artifacts::{ArtifactError, ArtifactOwner, ArtifactStore, StoredArtifact};
pub use dispatch::{
    DispatchContext, DispatchLimits, DurableEventCommitter, EventCommitError, NativeExecutionDeps,
    ToolExecutorBoundary,
};
pub use files::{FileTools, ReadFileRequest, SearchFilesRequest};
pub use process::{
    ProcessAction, ProcessArtifactSink, ProcessExecutor, ProcessOwner, ProcessRequest, ProcessTable,
};
pub(crate) use registry::sha256_hex;
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

/// Maximum UTF-8 bytes accepted in one owner label.
pub const MAX_OWNER_LABEL_BYTES: usize = 128;

/// Validated owner identity shared by artifact and process contracts.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ToolOwner {
    profile: String,
    session: String,
    run: String,
}

impl ToolOwner {
    /// Parse a profile/session/run triple with the shared owner contract.
    pub fn new(
        profile: impl Into<String>,
        session: impl Into<String>,
        run: impl Into<String>,
    ) -> Result<Self, String> {
        Ok(Self {
            profile: validate_owner_label(profile.into(), "profile")?,
            session: validate_owner_label(session.into(), "session")?,
            run: validate_owner_label(run.into(), "run")?,
        })
    }

    /// Profile label.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Session label.
    pub fn session(&self) -> &str {
        &self.session
    }

    /// Run label.
    pub fn run(&self) -> &str {
        &self.run
    }
}

pub(crate) fn validate_owner_label(value: String, name: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    if value.contains('\0') {
        return Err(format!("{name} is invalid"));
    }
    if value.len() > MAX_OWNER_LABEL_BYTES {
        return Err(format!("{name} exceeds the configured bound"));
    }
    Ok(value)
}

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

/// Serialized JSON size of a `ToolResult` envelope, or `usize::MAX` if encoding fails.
pub(crate) fn serialized_tool_result_len(result: &ToolResult) -> usize {
    match serde_json::to_vec(result) {
        Ok(bytes) => bytes.len(),
        Err(_) => usize::MAX,
    }
}

/// Guarantee the encoded envelope is at most `cap` bytes.
///
/// Payload slots (`content`, `data.stdout`, `data.stderr`) may shrink. If the
/// metadata-only skeleton still exceeds the cap, the result fails closed as
/// `output_truncated`.
pub(crate) fn enforce_serialized_tool_result_cap(result: &mut ToolResult, cap: usize) {
    if serialized_tool_result_len(result) <= cap {
        return;
    }
    result.truncated = true;
    shrink_envelope_to_cap(result, cap);
}

fn shrink_envelope_to_cap(result: &mut ToolResult, cap: usize) {
    let original_content = result.content.clone();
    let original_stdout = stream_string(result, "stdout");
    let original_stderr = stream_string(result, "stderr");

    let mut skeleton = result.clone();
    skeleton.content.clear();
    clear_stream_strings(&mut skeleton);
    let skeleton_len = serialized_tool_result_len(&skeleton);
    if skeleton_len == usize::MAX || skeleton_len > cap {
        *result = minimal_bounded_error(cap);
        return;
    }

    let mut budget = cap.saturating_sub(skeleton_len);
    loop {
        let (content_budget, stdout_budget, stderr_budget) = allocate_payload_budget(
            budget,
            &original_content,
            &original_stdout,
            &original_stderr,
        );
        result.content = truncate_to_bytes(&original_content, content_budget);
        let stdout = truncate_to_bytes(&original_stdout, stdout_budget);
        let stderr = truncate_to_bytes(&original_stderr, stderr_budget);
        if stdout.len() < original_stdout.len()
            && let Value::Object(data) = &mut result.data
        {
            data.insert("stdout_truncated".into(), json!(true));
        }
        if stderr.len() < original_stderr.len()
            && let Value::Object(data) = &mut result.data
        {
            data.insert("stderr_truncated".into(), json!(true));
        }
        set_stream_string(result, "stdout", stdout);
        set_stream_string(result, "stderr", stderr);
        result.truncated = true;
        if serialized_tool_result_len(result) <= cap {
            return;
        }
        if budget == 0 {
            *result = minimal_bounded_error(cap);
            return;
        }
        budget /= 2;
    }
}

fn allocate_payload_budget(
    budget: usize,
    content: &str,
    stdout: &str,
    stderr: &str,
) -> (usize, usize, usize) {
    let mut shares = 0usize;
    if !content.is_empty() {
        shares = shares.saturating_add(1);
    }
    if !stdout.is_empty() {
        shares = shares.saturating_add(1);
    }
    if !stderr.is_empty() {
        shares = shares.saturating_add(1);
    }
    let shares = shares.max(1);
    let each = budget / shares;
    let mut content_budget = if content.is_empty() {
        0
    } else {
        each.min(content.len())
    };
    let mut stdout_budget = if stdout.is_empty() {
        0
    } else {
        each.min(stdout.len())
    };
    let mut stderr_budget = if stderr.is_empty() {
        0
    } else {
        each.min(stderr.len())
    };
    let mut leftover = budget
        .saturating_sub(content_budget)
        .saturating_sub(stdout_budget)
        .saturating_sub(stderr_budget);
    for (slot, source) in [
        (&mut content_budget, content),
        (&mut stdout_budget, stdout),
        (&mut stderr_budget, stderr),
    ] {
        let extra = source.len().saturating_sub(*slot).min(leftover);
        *slot = slot.saturating_add(extra);
        leftover = leftover.saturating_sub(extra);
    }
    (content_budget, stdout_budget, stderr_budget)
}

fn stream_string(result: &ToolResult, key: &str) -> String {
    result
        .data
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn set_stream_string(result: &mut ToolResult, key: &str, value: String) {
    if let Value::Object(data) = &mut result.data
        && data.get(key).and_then(Value::as_str).is_some()
    {
        data.insert(key.to_string(), json!(value));
    }
}

fn clear_stream_strings(result: &mut ToolResult) {
    set_stream_string(result, "stdout", String::new());
    set_stream_string(result, "stderr", String::new());
}

fn truncate_to_bytes(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

fn minimal_bounded_error(cap: usize) -> ToolResult {
    for message in ["tool result exceeds the configured bound", "bounded", ""] {
        let candidate =
            ToolResult::failure_with("output_truncated", message, String::new(), json!({}), true);
        if serialized_tool_result_len(&candidate) <= cap {
            return candidate;
        }
    }
    ToolResult::failure_with("output_truncated", "", String::new(), json!({}), true)
}
