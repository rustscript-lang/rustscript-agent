use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;

/// Version of the effect-free executor contract included in registry identity.
pub const NATIVE_EXECUTOR_CONTRACT_VERSION: &str = "native-tool-executor-v1";
const MAX_POLICY_ERROR_BYTES: usize = 128;

/// The public, provider-facing description of one native tool.
///
/// This type intentionally contains no executor or operating-system state. It
/// is the stable descriptor used by provider adapters and domain contracts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub name: String,
    pub description: String,
    pub toolset: String,
    pub risk_class: String,
    pub schema: Value,
}

impl ToolDescriptor {
    /// Builds a descriptor using the same field order as its serialized
    /// contract: name, description, toolset, risk class, and schema.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        toolset: impl Into<String>,
        risk_class: impl Into<String>,
        schema: Value,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            toolset: toolset.into(),
            risk_class: risk_class.into(),
            schema,
        }
    }
}

/// The only toolsets enabled by the first native registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Toolset {
    Coding,
    Process,
}

impl Toolset {
    pub const CODING: &'static str = "coding";
    pub const PROCESS: &'static str = "process";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Coding => Self::CODING,
            Self::Process => Self::PROCESS,
        }
    }
}

impl std::fmt::Display for Toolset {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for Toolset {
    type Error = UnsupportedToolset;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            Self::CODING => Ok(Self::Coding),
            Self::PROCESS => Ok(Self::Process),
            _ => Err(UnsupportedToolset {
                value: bounded_policy_value(value),
            }),
        }
    }
}

impl TryFrom<String> for Toolset {
    type Error = UnsupportedToolset;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl From<Toolset> for String {
    fn from(value: Toolset) -> Self {
        value.as_str().to_string()
    }
}

/// A toolset that is not part of the initial native registry policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedToolset {
    pub value: String,
}

impl std::fmt::Display for UnsupportedToolset {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "unsupported toolset ({} bytes)",
            self.value.len()
        )
    }
}

impl std::error::Error for UnsupportedToolset {}

/// Risk labels carried by the initial descriptors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Read,
    Write,
    Execute,
}

/// A risk label that is not part of the registry policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedRiskClass {
    pub value: String,
}

impl std::fmt::Display for UnsupportedRiskClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "unsupported risk class ({} bytes)",
            self.value.len()
        )
    }
}

impl std::error::Error for UnsupportedRiskClass {}

impl RiskClass {
    pub const READ: &'static str = "read";
    pub const WRITE: &'static str = "write";
    pub const EXECUTE: &'static str = "execute";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => Self::READ,
            Self::Write => Self::WRITE,
            Self::Execute => Self::EXECUTE,
        }
    }

    pub fn parse(value: &str) -> Result<Self, UnsupportedRiskClass> {
        Self::try_from(value)
    }
}

impl std::fmt::Display for RiskClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for RiskClass {
    type Error = UnsupportedRiskClass;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            Self::READ => Ok(Self::Read),
            Self::WRITE => Ok(Self::Write),
            Self::EXECUTE => Ok(Self::Execute),
            _ => Err(UnsupportedRiskClass {
                value: bounded_policy_value(value),
            }),
        }
    }
}

impl TryFrom<String> for RiskClass {
    type Error = UnsupportedRiskClass;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl From<RiskClass> for String {
    fn from(value: RiskClass) -> Self {
        value.as_str().to_string()
    }
}

impl<'de> Deserialize<'de> for RiskClass {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value.as_str()).map_err(D::Error::custom)
    }
}

fn bounded_policy_value(value: &str) -> String {
    if value.len() <= MAX_POLICY_ERROR_BYTES {
        return value.to_string();
    }
    let mut end = MAX_POLICY_ERROR_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// Native execution slots reserved for the registry.
///
/// These variants are contracts only. They deliberately do not contain
/// closures, process handles, or filesystem capabilities; effects are added by
/// the later dispatch tasks. The enum is non-exhaustive so adding a real
/// executor slot does not break downstream matches.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeToolExecutor {
    ReadFile,
    SearchFiles,
    WriteFile,
    Patch,
    Terminal,
    Process,
    Placeholder(String),
}

impl NativeToolExecutor {
    /// Returns the no-effects executor slot for a tool name.
    pub fn placeholder(name: impl Into<String>) -> Self {
        let name = name.into();
        match name.as_str() {
            "read_file" => Self::ReadFile,
            "search_files" => Self::SearchFiles,
            "write_file" => Self::WriteFile,
            "patch" => Self::Patch,
            "terminal" => Self::Terminal,
            "process" => Self::Process,
            _ => Self::Placeholder(name),
        }
    }

    /// Returns the descriptor name represented by this executor slot.
    pub fn tool_name(&self) -> &str {
        match self {
            Self::ReadFile => "read_file",
            Self::SearchFiles => "search_files",
            Self::WriteFile => "write_file",
            Self::Patch => "patch",
            Self::Terminal => "terminal",
            Self::Process => "process",
            Self::Placeholder(name) => name,
        }
    }

    /// Returns the stable, effect-free contract for this executor slot.
    ///
    /// The contract identifies the native implementation slot and its policy
    /// labels. It is metadata for dispatch and resume identity, not an
    /// authentication or authorization decision; those checks remain owned by
    /// the service and native policy layers.
    pub fn contract(&self) -> NativeExecutorContract {
        match self {
            Self::ReadFile => NativeExecutorContract::known("read_file", "coding", "read"),
            Self::SearchFiles => NativeExecutorContract::known("search_files", "coding", "read"),
            Self::WriteFile => NativeExecutorContract::known("write_file", "coding", "write"),
            Self::Patch => NativeExecutorContract::known("patch", "coding", "write"),
            Self::Terminal => NativeExecutorContract::known("terminal", "process", "execute"),
            Self::Process => NativeExecutorContract::known("process", "process", "execute"),
            Self::Placeholder(name) => NativeExecutorContract {
                tool_name: name.clone(),
                toolset: None,
                risk_class: None,
                version: NATIVE_EXECUTOR_CONTRACT_VERSION,
            },
        }
    }
}

/// Effect-free metadata for a future native executor implementation.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeExecutorContract {
    pub tool_name: String,
    pub toolset: Option<&'static str>,
    pub risk_class: Option<&'static str>,
    pub version: &'static str,
}

impl NativeExecutorContract {
    fn known(tool_name: &'static str, toolset: &'static str, risk_class: &'static str) -> Self {
        Self {
            tool_name: tool_name.to_string(),
            toolset: Some(toolset),
            risk_class: Some(risk_class),
            version: NATIVE_EXECUTOR_CONTRACT_VERSION,
        }
    }
}
