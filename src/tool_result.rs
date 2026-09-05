use serde::{Deserialize, Serialize};
use serde_json::Value;

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

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn session(&self) -> &str {
        &self.session
    }

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

/// Common bounded envelope returned by tool execution.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    pub ok: bool,
    pub content: String,
    pub data: Value,
    pub error: Option<ToolError>,
    pub truncated: bool,
    pub artifacts: Vec<String>,
    /// Set when a durable canonical result was replayed without an effect.
    #[serde(skip)]
    pub(crate) replayed: bool,
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
            replayed: false,
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
            replayed: false,
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
            replayed: false,
        }
    }
}
