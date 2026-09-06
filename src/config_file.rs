//! Versioned, secret-free runtime configuration and persistent path resolution.
//!
//! This module owns the YAML boundary for `config.yaml`. Authentication
//! material is deliberately kept in [`crate::auth::config`]; the two schemas
//! are parsed and validated independently before their references are joined.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use url::Url;
use yaml_rust2::parser::{Event, Parser, Tag};

use crate::auth::config::{AuthConfig, AuthConfigError};

/// Persistent home directory name used when no override is configured.
pub const DEFAULT_AGENT_HOME_DIR: &str = ".rustscript-agent";
/// Name of the non-secret runtime configuration file.
pub const CONFIG_FILE_NAME: &str = "config.yaml";
/// Name of the credential and token lifecycle file.
pub const AUTH_FILE_NAME: &str = "auth.yaml";
/// Name of the cross-process auth lock file reserved by the auth store.
pub const AUTH_LOCK_FILE_NAME: &str = "auth.yaml.lock";
/// Name of the durable agent state database.
pub const STATE_FILE_NAME: &str = "state.db";

/// Maximum bytes read from `config.yaml` before parsing is attempted.
pub const MAX_CONFIG_YAML_BYTES: usize = 256 * 1024;
/// Maximum YAML nesting depth accepted by either version-one document.
pub const MAX_YAML_DEPTH: usize = 16;
/// Maximum number of YAML scalar and collection nodes accepted by a document.
pub const MAX_YAML_NODES: usize = 4096;
/// Internal finite cap on estimated expanded `serde_yaml::Value` allocation bytes.
///
/// This shared cap is enforced before `serde_yaml::Value` construction for both
/// `config.yaml` and `auth.yaml`; aliases charge the complete anchored summary.
pub(crate) const MAX_YAML_EXPANDED_BYTES: usize = 8 * 1024 * 1024;

const YAML_VALUE_BYTES: usize = std::mem::size_of::<Value>();
const YAML_SEQUENCE_CONTAINER_BYTES: usize = YAML_VALUE_BYTES + std::mem::size_of::<Vec<Value>>();
const YAML_MAPPING_CONTAINER_BYTES: usize = YAML_VALUE_BYTES + std::mem::size_of::<Mapping>();
const YAML_SEQUENCE_ELEMENT_BYTES: usize = YAML_VALUE_BYTES;
const YAML_TAGGED_VALUE_BYTES: usize = YAML_VALUE_BYTES;

/// Resolved persistent paths for one agent home.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentPaths {
    pub home: PathBuf,
    pub config: PathBuf,
    pub auth: PathBuf,
    pub auth_lock: PathBuf,
    pub state: PathBuf,
}

/// Compatibility name for callers that describe this as a path set.
pub type ConfigPaths = AgentPaths;

impl AgentPaths {
    /// Resolves `RUSTSCRIPT_AGENT_HOME`, or `$HOME/.rustscript-agent` when it
    /// is absent. The override applies to the complete home, never to an
    /// individual token, endpoint, or credential field.
    pub fn resolve() -> Result<Self, ConfigFileError> {
        let home = match std::env::var_os("RUSTSCRIPT_AGENT_HOME") {
            Some(value) if !value.is_empty() => PathBuf::from(value),
            Some(_) => {
                return Err(ConfigFileError::HomeInvalid {
                    reason: "RUSTSCRIPT_AGENT_HOME must not be empty".to_string(),
                });
            }
            None => default_home_from_environment()?,
        };
        Self::from_home(home)
    }

    /// Builds all persistent paths below an explicitly selected home.
    pub fn from_home(home: impl AsRef<Path>) -> Result<Self, ConfigFileError> {
        let home = home.as_ref();
        validate_home_path(home)?;
        let home = home.to_path_buf();
        Ok(Self {
            config: home.join(CONFIG_FILE_NAME),
            auth: home.join(AUTH_FILE_NAME),
            auth_lock: home.join(AUTH_LOCK_FILE_NAME),
            state: home.join(STATE_FILE_NAME),
            home,
        })
    }

    pub fn config_path(&self) -> &Path {
        &self.config
    }

    pub fn auth_path(&self) -> &Path {
        &self.auth
    }
}

fn default_home_from_environment() -> Result<PathBuf, ConfigFileError> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| ConfigFileError::HomeUnavailable {
            variable: "HOME/USERPROFILE".to_string(),
        })?;
    if home.is_empty() {
        return Err(ConfigFileError::HomeInvalid {
            reason: "HOME/USERPROFILE must not be empty".to_string(),
        });
    }
    Ok(PathBuf::from(home).join(DEFAULT_AGENT_HOME_DIR))
}

fn validate_home_path(home: &Path) -> Result<(), ConfigFileError> {
    if home.as_os_str().is_empty() {
        return Err(ConfigFileError::HomeInvalid {
            reason: "agent home must not be empty".to_string(),
        });
    }
    if home.is_relative() {
        return Err(ConfigFileError::HomeInvalid {
            reason: "agent home must be an absolute path".to_string(),
        });
    }
    if home
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ConfigFileError::HomeInvalid {
            reason: "agent home must not contain parent-directory components".to_string(),
        });
    }
    Ok(())
}

/// Version-one `config.yaml` document.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub version: u32,
    #[serde(default)]
    pub agent: AgentSettings,
    #[serde(default)]
    pub model: ModelSettings,
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderSettings>,
    #[serde(default)]
    pub workspaces: WorkspaceSettings,
    #[serde(default)]
    pub approvals: ApprovalSettings,
    #[serde(default)]
    pub compaction: CompactionSettings,
}

/// Compatibility name for the persisted non-secret document.
pub type RuntimeConfig = ConfigFile;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct AgentSettings {
    pub source: String,
    pub max_turns: u64,
    pub max_tool_calls: u64,
    pub max_tool_output_bytes: usize,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            source: "bundled:coding".to_string(),
            max_turns: 64,
            max_tool_calls: 128,
            max_tool_output_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct ModelSettings {
    pub provider: String,
    pub model: String,
}

impl Default for ModelSettings {
    fn default() -> Self {
        Self {
            provider: "local-agent".to_string(),
            model: "local-agent".to_string(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct ProviderSettings {
    pub protocol: String,
    pub base_url: String,
    /// A named credential reference. The token itself cannot be represented
    /// by this field because it is a string ID validated against auth.yaml.
    pub auth: Option<String>,
    pub oauth: Option<OAuthSettings>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct OAuthSettings {
    pub flow: Option<String>,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub device_user_code_path: Option<String>,
    pub device_poll_path: Option<String>,
    pub authorization_path: Option<String>,
    pub token_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    pub refresh_skew_seconds: u64,
}

impl Default for OAuthSettings {
    fn default() -> Self {
        Self {
            flow: None,
            issuer: None,
            client_id: None,
            device_user_code_path: None,
            device_poll_path: None,
            authorization_path: None,
            token_endpoint: None,
            redirect_uri: None,
            refresh_skew_seconds: 120,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct WorkspaceSettings {
    pub allowed_roots: Vec<PathBuf>,
    pub default: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct ApprovalSettings {
    pub read: String,
    pub write: String,
    pub process: String,
}

impl Default for ApprovalSettings {
    fn default() -> Self {
        Self {
            read: "allow".to_string(),
            write: "ask".to_string(),
            process: "ask".to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct CompactionSettings {
    pub enabled: bool,
    pub max_context_messages: usize,
    pub retained_tail: usize,
}

impl Default for CompactionSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            max_context_messages: 120,
            retained_tail: 32,
        }
    }
}

/// Config and auth after both documents have passed their independent schema
/// checks and every provider credential reference has been resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedConfig {
    pub paths: AgentPaths,
    pub config: ConfigFile,
    pub auth: AuthConfig,
}

impl ConfigFile {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigFileError> {
        let path = path.as_ref();
        let bytes = read_bounded_bytes(path, MAX_CONFIG_YAML_BYTES)
            .map_err(ConfigFileError::from_bounded_read)?;
        Self::from_yaml_bytes(path, &bytes)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(source: &str) -> Result<Self, ConfigFileError> {
        if source.len() > MAX_CONFIG_YAML_BYTES {
            return Err(ConfigFileError::FileTooLarge {
                path: PathBuf::from("<inline config.yaml>"),
                max_bytes: MAX_CONFIG_YAML_BYTES,
            });
        }
        Self::from_yaml_bytes(Path::new("<inline config.yaml>"), source.as_bytes())
    }

    pub fn load_from_home() -> Result<Self, ConfigFileError> {
        let paths = AgentPaths::resolve()?;
        Self::load(paths.config_path())
    }

    pub fn load_pair(paths: &AgentPaths) -> Result<LoadedConfig, ConfigFileError> {
        let config = Self::load(paths.config_path())?;
        let auth = AuthConfig::load(paths.auth_path()).map_err(ConfigFileError::Auth)?;
        config.validate_auth_references(&auth)?;
        Ok(LoadedConfig {
            paths: paths.clone(),
            config,
            auth,
        })
    }

    pub fn load_pair_from_home() -> Result<LoadedConfig, ConfigFileError> {
        let paths = AgentPaths::resolve()?;
        Self::load_pair(&paths)
    }

    pub fn validate_auth_references(&self, auth: &AuthConfig) -> Result<(), ConfigFileError> {
        for (provider_name, provider) in &self.providers {
            if let Some(credential_id) = provider.auth.as_deref() {
                let path = format!("providers.{provider_name}.auth");
                if !auth.credentials.contains_key(credential_id) {
                    return Err(ConfigFileError::InvalidAuthReference {
                        path,
                        credential_id: credential_id.to_string(),
                        reason: "credential ID is not present in auth.yaml".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    fn from_yaml_bytes(path: &Path, bytes: &[u8]) -> Result<Self, ConfigFileError> {
        preflight_yaml(bytes).map_err(|error| ConfigFileError::from_yaml_preflight(path, error))?;
        let value: Value = parse_yaml_value(bytes).map_err(|_| ConfigFileError::MalformedYaml {
            path: path.to_path_buf(),
            message: "invalid YAML syntax".to_string(),
        })?;
        reject_secret_keys_recursive(path, &value, "root")?;
        validate_config_shape(path, &value)?;
        let config: Self =
            serde_yaml::from_value(value).map_err(|_| ConfigFileError::InvalidValue {
                path: path.to_path_buf(),
                field: "document".to_string(),
                message: "document does not match the config schema".to_string(),
            })?;
        config.validate(path)?;
        Ok(config)
    }

    fn validate(&self, source: &Path) -> Result<(), ConfigFileError> {
        if self.version != 1 {
            return Err(ConfigFileError::InvalidVersion {
                path: source.to_path_buf(),
                version: self.version,
            });
        }
        if self.agent.source.trim().is_empty() {
            return Err(ConfigFileError::InvalidValue {
                path: source.to_path_buf(),
                field: "agent.source".to_string(),
                message: "must not be blank".to_string(),
            });
        }
        if self.agent.max_turns == 0 || self.agent.max_turns > 1_000_000 {
            return Err(invalid_value(
                source,
                "agent.max_turns",
                "must be between 1 and 1000000",
            ));
        }
        if self.agent.max_tool_calls == 0 || self.agent.max_tool_calls > 10_000_000 {
            return Err(invalid_value(
                source,
                "agent.max_tool_calls",
                "must be between 1 and 10000000",
            ));
        }
        if self.agent.max_tool_output_bytes == 0
            || self.agent.max_tool_output_bytes > 64 * 1024 * 1024
        {
            return Err(invalid_value(
                source,
                "agent.max_tool_output_bytes",
                "must be between 1 and 67108864",
            ));
        }
        validate_visible(&self.model.provider, source, "model.provider")?;
        validate_visible(&self.model.model, source, "model.model")?;
        for (provider_name, provider) in &self.providers {
            validate_visible(provider_name, source, &format!("providers.{provider_name}"))?;
            validate_visible(
                &provider.protocol,
                source,
                &format!("providers.{provider_name}.protocol"),
            )?;
            if provider.base_url.trim().is_empty() {
                return Err(invalid_value(
                    source,
                    &format!("providers.{provider_name}.base_url"),
                    "must not be blank",
                ));
            }
            validate_provider_url(
                &provider.base_url,
                source,
                &format!("providers.{provider_name}.base_url"),
                false,
            )?;
            if let Some(auth) = provider.auth.as_deref() {
                validate_visible(auth, source, &format!("providers.{provider_name}.auth"))?;
            }
            if let Some(oauth) = provider.oauth.as_ref() {
                validate_oauth(source, provider_name, oauth)?;
            }
        }
        for (index, root) in self.workspaces.allowed_roots.iter().enumerate() {
            validate_absolute_workspace(
                root,
                source,
                &format!("workspaces.allowed_roots[{index}]"),
            )?;
        }
        if let Some(default) = self.workspaces.default.as_ref() {
            validate_absolute_workspace(default, source, "workspaces.default")?;
            if !self
                .workspaces
                .allowed_roots
                .iter()
                .any(|root| default.starts_with(root))
            {
                return Err(invalid_value(
                    source,
                    "workspaces.default",
                    "must be below one of workspaces.allowed_roots",
                ));
            }
        }
        for (field, value) in [
            ("approvals.read", self.approvals.read.as_str()),
            ("approvals.write", self.approvals.write.as_str()),
            ("approvals.process", self.approvals.process.as_str()),
        ] {
            if !matches!(value, "allow" | "ask" | "deny") {
                return Err(invalid_value(
                    source,
                    field,
                    "must be one of allow, ask, or deny",
                ));
            }
        }
        if self.compaction.max_context_messages == 0 {
            return Err(invalid_value(
                source,
                "compaction.max_context_messages",
                "must be positive",
            ));
        }
        if self.compaction.retained_tail > self.compaction.max_context_messages {
            return Err(invalid_value(
                source,
                "compaction.retained_tail",
                "must not exceed max_context_messages",
            ));
        }
        Ok(())
    }
}

impl std::str::FromStr for ConfigFile {
    type Err = ConfigFileError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        ConfigFile::from_str(source)
    }
}

fn validate_oauth(
    source: &Path,
    provider_name: &str,
    oauth: &OAuthSettings,
) -> Result<(), ConfigFileError> {
    let prefix = format!("providers.{provider_name}.oauth");
    if let Some(flow) = oauth.flow.as_deref() {
        validate_visible(flow, source, &format!("{prefix}.flow"))?;
    }
    if let Some(client_id) = oauth.client_id.as_deref() {
        validate_visible(client_id, source, &format!("{prefix}.client_id"))?;
    }
    for (field, value) in [
        ("issuer", oauth.issuer.as_deref()),
        ("token_endpoint", oauth.token_endpoint.as_deref()),
    ] {
        if let Some(value) = value {
            validate_provider_url(value, source, &format!("{prefix}.{field}"), false)?;
        }
    }
    if let Some(redirect_uri) = oauth.redirect_uri.as_deref() {
        validate_provider_url(
            redirect_uri,
            source,
            &format!("{prefix}.redirect_uri"),
            true,
        )?;
    }
    for (field, value) in [
        (
            "device_user_code_path",
            oauth.device_user_code_path.as_deref(),
        ),
        ("device_poll_path", oauth.device_poll_path.as_deref()),
        ("authorization_path", oauth.authorization_path.as_deref()),
    ] {
        if let Some(value) = value {
            validate_relative_endpoint(value, source, &format!("{prefix}.{field}"))?;
        }
    }
    if oauth.refresh_skew_seconds > 86_400 {
        return Err(invalid_value(
            source,
            &format!("{prefix}.refresh_skew_seconds"),
            "must be at most 86400",
        ));
    }
    Ok(())
}

fn validate_provider_url(
    value: &str,
    source: &Path,
    field: &str,
    allow_loopback_http: bool,
) -> Result<(), ConfigFileError> {
    let url = Url::parse(value).map_err(|_| invalid_value(source, field, "invalid URL"))?;
    if url.username() != "" || url.password().is_some() {
        return Err(invalid_value(
            source,
            field,
            "URL must not contain user information",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid_value(
            source,
            field,
            "URL must not contain a query or fragment",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| invalid_value(source, field, "URL must contain a host"))?;
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]");
    if url.scheme() == "http" && allow_loopback_http && loopback {
        if url.port().is_none_or(|port| port == 0) {
            return Err(invalid_value(
                source,
                field,
                "loopback callback must specify a nonzero listener port",
            ));
        }
        return Ok(());
    }
    if url.scheme() != "https" {
        return Err(ConfigFileError::HttpsRequired {
            path: field.to_string(),
            scheme: url.scheme().to_string(),
        });
    }
    if url.port_or_known_default().is_none() {
        return Err(invalid_value(
            source,
            field,
            "URL must use a known HTTPS port",
        ));
    }
    Ok(())
}

fn validate_relative_endpoint(
    value: &str,
    source: &Path,
    field: &str,
) -> Result<(), ConfigFileError> {
    let invalid = || invalid_value(source, field, "must be a strict relative endpoint path");
    if value.is_empty()
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value.contains("//")
        || value
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
        || has_forbidden_percent_escape(value)
    {
        return Err(invalid());
    }
    validate_visible(value, source, field).map_err(|_| invalid())?;
    let base = Url::parse("https://endpoint.invalid/").map_err(|_| invalid())?;
    let joined = base.join(value).map_err(|_| invalid())?;
    if joined.host_str() != Some("endpoint.invalid")
        || joined.query().is_some()
        || joined.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(())
}

fn has_forbidden_percent_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return true;
        }
        let Some(high) = (bytes[index + 1] as char).to_digit(16) else {
            return true;
        };
        let Some(low) = (bytes[index + 2] as char).to_digit(16) else {
            return true;
        };
        if matches!((high * 16 + low) as u8, b'.' | b'/' | b'\\' | b'?' | b'#') {
            return true;
        }
        index += 3;
    }
    false
}

fn validate_absolute_workspace(
    value: &Path,
    source: &Path,
    field: &str,
) -> Result<(), ConfigFileError> {
    if value.as_os_str().is_empty() || value.is_relative() {
        return Err(invalid_value(source, field, "must be an absolute path"));
    }
    if value
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(invalid_value(
            source,
            field,
            "must not contain parent-directory components",
        ));
    }
    Ok(())
}

fn validate_visible(value: &str, source: &Path, field: &str) -> Result<(), ConfigFileError> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid_value(
            source,
            field,
            "must be a visible non-whitespace, non-control string",
        ));
    }
    Ok(())
}

fn invalid_value(source: &Path, field: &str, message: &str) -> ConfigFileError {
    ConfigFileError::InvalidValue {
        path: source.to_path_buf(),
        field: field.to_string(),
        message: message.to_string(),
    }
}

fn validate_config_shape(source: &Path, value: &Value) -> Result<(), ConfigFileError> {
    let root = value
        .as_mapping()
        .ok_or_else(|| ConfigFileError::InvalidRoot {
            path: source.to_path_buf(),
        })?;
    validate_known_keys(
        source,
        "root",
        root,
        &[
            "version",
            "agent",
            "model",
            "providers",
            "workspaces",
            "approvals",
            "compaction",
        ],
    )?;
    if let Some(agent) = root.get(Value::String("agent".to_string())) {
        validate_known_mapping(
            source,
            "agent",
            agent,
            &[
                "source",
                "max_turns",
                "max_tool_calls",
                "max_tool_output_bytes",
            ],
        )?;
    }
    if let Some(model) = root.get(Value::String("model".to_string())) {
        validate_known_mapping(source, "model", model, &["provider", "model"])?;
    }
    if let Some(providers) = root.get(Value::String("providers".to_string())) {
        let providers = as_mapping(providers, source, "providers")?;
        for (name, provider) in providers {
            let name = yaml_key(source, "providers", name)?;
            reject_secret_key(source, &format!("providers.{name}"), &name)?;
            let path = format!("providers.{name}");
            validate_known_mapping(
                source,
                &path,
                provider,
                &["protocol", "base_url", "auth", "oauth"],
            )?;
            if let Some(oauth) = as_mapping_optional(provider, "oauth")? {
                validate_known_keys(
                    source,
                    &format!("{path}.oauth"),
                    oauth,
                    &[
                        "flow",
                        "issuer",
                        "client_id",
                        "device_user_code_path",
                        "device_poll_path",
                        "authorization_path",
                        "token_endpoint",
                        "redirect_uri",
                        "refresh_skew_seconds",
                    ],
                )?;
            }
        }
    }
    if let Some(workspaces) = root.get(Value::String("workspaces".to_string())) {
        validate_known_mapping(
            source,
            "workspaces",
            workspaces,
            &["allowed_roots", "default"],
        )?;
    }
    if let Some(approvals) = root.get(Value::String("approvals".to_string())) {
        validate_known_mapping(
            source,
            "approvals",
            approvals,
            &["read", "write", "process"],
        )?;
    }
    if let Some(compaction) = root.get(Value::String("compaction".to_string())) {
        validate_known_mapping(
            source,
            "compaction",
            compaction,
            &["enabled", "max_context_messages", "retained_tail"],
        )?;
    }
    Ok(())
}

fn reject_secret_keys_recursive(
    source: &Path,
    value: &Value,
    path: &str,
) -> Result<(), ConfigFileError> {
    match value {
        Value::Mapping(mapping) => {
            for (key, value) in mapping {
                let key = yaml_key(source, path, key)?;
                let key_path = if path == "root" {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                reject_secret_key(source, &key_path, &key)?;
                reject_secret_keys_recursive(source, value, &key_path)?;
            }
        }
        Value::Sequence(sequence) => {
            for (index, value) in sequence.iter().enumerate() {
                reject_secret_keys_recursive(source, value, &format!("{path}[{index}]"))?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        _ => {}
    }
    Ok(())
}

fn validate_known_mapping(
    source: &Path,
    path: &str,
    value: &Value,
    allowed: &[&str],
) -> Result<(), ConfigFileError> {
    let mapping = as_mapping(value, source, path)?;
    validate_known_keys(source, path, mapping, allowed)
}

fn validate_known_keys(
    source: &Path,
    path: &str,
    mapping: &Mapping,
    allowed: &[&str],
) -> Result<(), ConfigFileError> {
    for key in mapping.keys() {
        let key = yaml_key(source, path, key)?;
        let key_path = if path == "root" {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        reject_secret_key(source, &key_path, &key)?;
        if !allowed.contains(&key.as_str()) {
            return Err(ConfigFileError::UnknownKey {
                path: key_path,
                key,
            });
        }
    }
    Ok(())
}

fn reject_secret_key(source: &Path, path: &str, key: &str) -> Result<(), ConfigFileError> {
    if is_secret_key(key) {
        return Err(ConfigFileError::SecretKey {
            path: path.to_string(),
            key: key.to_string(),
        });
    }
    let _ = source;
    Ok(())
}

pub(crate) fn is_secret_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
        "access_token"
            | "refresh_token"
            | "id_token"
            | "api_key"
            | "authorization"
            | "cookie"
            | "password"
            | "client_secret"
            | "secret"
            | "secret_key"
            | "private_key"
            | "signing_key"
            | "headers"
            | "bearer_token"
            | "token"
            | "token_value"
            | "credential"
            | "credentials"
    ) || normalized.contains("secret")
        || normalized.contains("password")
        || normalized.ends_with("_token")
}

fn as_mapping<'a>(
    value: &'a Value,
    source: &Path,
    path: &str,
) -> Result<&'a Mapping, ConfigFileError> {
    value
        .as_mapping()
        .ok_or_else(|| invalid_value(source, path, "must be a mapping"))
}

fn as_mapping_optional<'a>(
    mapping_value: &'a Value,
    key: &str,
) -> Result<Option<&'a Mapping>, ConfigFileError> {
    let Some(mapping) = mapping_value.as_mapping() else {
        return Ok(None);
    };
    let Some(value) = mapping.get(Value::String(key.to_string())) else {
        return Ok(None);
    };
    Ok(value.as_mapping())
}

fn yaml_key(source: &Path, path: &str, key: &Value) -> Result<String, ConfigFileError> {
    key.as_str()
        .map(str::to_string)
        .ok_or_else(|| invalid_value(source, path, "mapping keys must be strings"))
}

/// A bounded file read error shared with the auth schema loader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BoundedReadError {
    Missing { path: PathBuf },
    Io { path: PathBuf, message: String },
    FileTooLarge { path: PathBuf, max_bytes: usize },
}

pub(crate) fn read_bounded_bytes(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, BoundedReadError> {
    let file = File::open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            BoundedReadError::Missing {
                path: path.to_path_buf(),
            }
        } else {
            BoundedReadError::Io {
                path: path.to_path_buf(),
                message: error.to_string(),
            }
        }
    })?;
    let mut limited = file.take(max_bytes as u64 + 1);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| BoundedReadError::Io {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    if bytes.len() > max_bytes {
        return Err(BoundedReadError::FileTooLarge {
            path: path.to_path_buf(),
            max_bytes,
        });
    }
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum YamlBoundsError {
    TooDeep {
        path: String,
        depth: usize,
        max_depth: usize,
    },
    TooManyNodes {
        path: String,
        max_nodes: usize,
    },
    ExpandedBytes {
        path: String,
        max_bytes: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum YamlPreflightError {
    Malformed,
    MultipleDocuments,
    Bounds(YamlBoundsError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct YamlSummary {
    nodes: usize,
    max_depth: usize,
    expanded_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum YamlContainer {
    Sequence,
    Mapping,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum YamlAnchor {
    Open,
    Complete(YamlSummary),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct YamlFrame {
    container: YamlContainer,
    anchor: usize,
    tagged: bool,
    mapping_expects_value: bool,
    summary: YamlSummary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct YamlPreflightLimits {
    max_depth: usize,
    max_nodes: usize,
    max_expanded_bytes: usize,
}

impl Default for YamlPreflightLimits {
    fn default() -> Self {
        Self {
            max_depth: MAX_YAML_DEPTH,
            max_nodes: MAX_YAML_NODES,
            max_expanded_bytes: MAX_YAML_EXPANDED_BYTES,
        }
    }
}

struct YamlEventBudget {
    documents: usize,
    in_document: bool,
    root: Option<YamlSummary>,
    frames: Vec<YamlFrame>,
    anchors: HashMap<usize, YamlAnchor>,
    nodes: usize,
    expanded_bytes: usize,
    limits: YamlPreflightLimits,
}

impl YamlEventBudget {
    fn with_limits(limits: YamlPreflightLimits) -> Self {
        Self {
            documents: 0,
            in_document: false,
            root: None,
            frames: Vec::new(),
            anchors: HashMap::new(),
            nodes: 0,
            expanded_bytes: 0,
            limits,
        }
    }

    fn observe(&mut self, event: Event) -> Result<(), YamlPreflightError> {
        match event {
            Event::StreamStart => {
                if self.documents != 0 || self.in_document || self.root.is_some() {
                    return Err(YamlPreflightError::Malformed);
                }
            }
            Event::DocumentStart => {
                if self.in_document {
                    return Err(YamlPreflightError::Malformed);
                }
                if self.documents != 0 {
                    return Err(YamlPreflightError::MultipleDocuments);
                }
                self.documents = 1;
                self.in_document = true;
                self.root = None;
                self.frames.clear();
                self.anchors.clear();
            }
            Event::DocumentEnd => {
                if !self.in_document || !self.frames.is_empty() || self.root.is_none() {
                    return Err(YamlPreflightError::Malformed);
                }
                self.in_document = false;
            }
            Event::StreamEnd => {
                if self.in_document || !self.frames.is_empty() || self.documents != 1 {
                    return Err(YamlPreflightError::Malformed);
                }
            }
            Event::Scalar(value, _, anchor, tag) => {
                self.ensure_in_document()?;
                let summary = self.scalar_summary(&value, tag.as_ref())?;
                self.reserve(summary)?;
                self.ensure_depth(summary.max_depth)?;
                self.complete_node(summary)?;
                if anchor != 0 {
                    self.anchors.insert(anchor, YamlAnchor::Complete(summary));
                }
            }
            Event::Alias(anchor) => {
                self.ensure_in_document()?;
                let summary = match self.anchors.get(&anchor).copied() {
                    Some(YamlAnchor::Complete(summary)) => summary,
                    Some(YamlAnchor::Open) => return Err(YamlPreflightError::Malformed),
                    None => return Err(YamlPreflightError::Malformed),
                };
                self.reserve(summary)?;
                self.ensure_depth(summary.max_depth)?;
                self.complete_node(summary)?;
            }
            Event::SequenceStart(anchor, tag) => {
                self.start_container(YamlContainer::Sequence, anchor, tag.as_ref())?;
            }
            Event::MappingStart(anchor, tag) => {
                self.start_container(YamlContainer::Mapping, anchor, tag.as_ref())?;
            }
            Event::SequenceEnd => self.end_container(YamlContainer::Sequence)?,
            Event::MappingEnd => self.end_container(YamlContainer::Mapping)?,
            Event::Nothing => return Err(YamlPreflightError::Malformed),
        }
        Ok(())
    }

    fn finish(self) -> Result<(), YamlPreflightError> {
        if self.in_document || !self.frames.is_empty() || self.documents != 1 {
            return Err(YamlPreflightError::Malformed);
        }
        Ok(())
    }

    fn ensure_in_document(&self) -> Result<(), YamlPreflightError> {
        if self.in_document {
            Ok(())
        } else {
            Err(YamlPreflightError::Malformed)
        }
    }

    fn start_container(
        &mut self,
        container: YamlContainer,
        anchor: usize,
        tag: Option<&Tag>,
    ) -> Result<(), YamlPreflightError> {
        self.ensure_in_document()?;
        self.ensure_depth(usize::from(tag.is_some()))?;
        let summary = YamlSummary {
            nodes: if tag.is_some() { 2 } else { 1 },
            max_depth: 0,
            expanded_bytes: self.container_bytes(container, tag)?,
        };
        self.reserve(summary)?;
        self.frames.push(YamlFrame {
            container,
            anchor,
            tagged: tag.is_some(),
            mapping_expects_value: false,
            summary,
        });
        if anchor != 0 {
            self.anchors.insert(anchor, YamlAnchor::Open);
        }
        Ok(())
    }

    fn end_container(&mut self, expected: YamlContainer) -> Result<(), YamlPreflightError> {
        self.ensure_in_document()?;
        let frame = self.frames.pop().ok_or(YamlPreflightError::Malformed)?;
        if frame.container != expected
            || (frame.container == YamlContainer::Mapping && frame.mapping_expects_value)
        {
            return Err(YamlPreflightError::Malformed);
        }
        let summary = if frame.tagged {
            YamlSummary {
                max_depth: frame
                    .summary
                    .max_depth
                    .checked_add(1)
                    .ok_or_else(|| self.too_deep())?,
                ..frame.summary
            }
        } else {
            frame.summary
        };
        self.ensure_depth(summary.max_depth)?;
        if frame.anchor != 0 {
            self.anchors
                .insert(frame.anchor, YamlAnchor::Complete(summary));
        }
        self.complete_node(summary)
    }

    fn complete_node(&mut self, summary: YamlSummary) -> Result<(), YamlPreflightError> {
        let Some(frame) = self.frames.last() else {
            if self.root.replace(summary).is_some() {
                return Err(YamlPreflightError::Malformed);
            }
            return Ok(());
        };

        let edge_bytes = match frame.container {
            YamlContainer::Sequence => YAML_SEQUENCE_ELEMENT_BYTES,
            YamlContainer::Mapping if frame.mapping_expects_value => self.mapping_entry_bytes()?,
            YamlContainer::Mapping => 0,
        };
        let nodes = frame
            .summary
            .nodes
            .checked_add(summary.nodes)
            .ok_or_else(|| self.too_many_nodes())?;
        let child_depth = summary
            .max_depth
            .checked_add(1)
            .ok_or_else(|| self.too_deep())?;
        let max_depth = frame.summary.max_depth.max(child_depth);
        if max_depth > self.limits.max_depth {
            return Err(self.too_deep());
        }
        let expanded_bytes = frame
            .summary
            .expanded_bytes
            .checked_add(summary.expanded_bytes)
            .ok_or_else(|| self.too_many_bytes())?
            .checked_add(edge_bytes)
            .ok_or_else(|| self.too_many_bytes())?;
        let total_expanded_bytes = self
            .expanded_bytes
            .checked_add(edge_bytes)
            .ok_or_else(|| self.too_many_bytes())?;
        if total_expanded_bytes > self.limits.max_expanded_bytes {
            return Err(self.too_many_bytes());
        }
        let Some(frame) = self.frames.last_mut() else {
            return Err(YamlPreflightError::Malformed);
        };
        frame.summary = YamlSummary {
            nodes,
            max_depth,
            expanded_bytes,
        };
        if frame.container == YamlContainer::Mapping {
            frame.mapping_expects_value = !frame.mapping_expects_value;
        }
        self.expanded_bytes = total_expanded_bytes;
        Ok(())
    }

    fn reserve(&mut self, summary: YamlSummary) -> Result<(), YamlPreflightError> {
        let nodes = self
            .nodes
            .checked_add(summary.nodes)
            .ok_or_else(|| self.too_many_nodes())?;
        if nodes > self.limits.max_nodes {
            return Err(self.too_many_nodes());
        }
        let expanded_bytes = self
            .expanded_bytes
            .checked_add(summary.expanded_bytes)
            .ok_or_else(|| self.too_many_bytes())?;
        if expanded_bytes > self.limits.max_expanded_bytes {
            return Err(self.too_many_bytes());
        }
        self.nodes = nodes;
        self.expanded_bytes = expanded_bytes;
        Ok(())
    }

    fn ensure_depth(&self, relative_depth: usize) -> Result<(), YamlPreflightError> {
        let depth = self
            .frames
            .len()
            .checked_add(relative_depth)
            .ok_or_else(|| self.too_deep())?;
        if depth > self.limits.max_depth {
            return Err(self.too_deep_at(depth));
        }
        Ok(())
    }

    fn scalar_summary(
        &self,
        value: &str,
        tag: Option<&Tag>,
    ) -> Result<YamlSummary, YamlPreflightError> {
        let mut expanded_bytes = YAML_VALUE_BYTES
            .checked_add(value.len())
            .ok_or_else(|| self.too_many_bytes())?;
        if let Some(tag) = tag {
            expanded_bytes = expanded_bytes
                .checked_add(self.tag_bytes(tag)?)
                .ok_or_else(|| self.too_many_bytes())?;
        }
        Ok(YamlSummary {
            nodes: if tag.is_some() { 2 } else { 1 },
            max_depth: usize::from(tag.is_some()),
            expanded_bytes,
        })
    }

    fn container_bytes(
        &self,
        container: YamlContainer,
        tag: Option<&Tag>,
    ) -> Result<usize, YamlPreflightError> {
        let base = match container {
            YamlContainer::Sequence => YAML_SEQUENCE_CONTAINER_BYTES,
            YamlContainer::Mapping => YAML_MAPPING_CONTAINER_BYTES,
        };
        match tag {
            Some(tag) => base
                .checked_add(self.tag_bytes(tag)?)
                .ok_or_else(|| self.too_many_bytes()),
            None => Ok(base),
        }
    }

    fn tag_bytes(&self, tag: &Tag) -> Result<usize, YamlPreflightError> {
        let tag_text = tag
            .handle
            .len()
            .checked_add(tag.suffix.len())
            .ok_or_else(|| self.too_many_bytes())?;
        tag_text
            .checked_add(YAML_TAGGED_VALUE_BYTES)
            .ok_or_else(|| self.too_many_bytes())
    }

    fn mapping_entry_bytes(&self) -> Result<usize, YamlPreflightError> {
        let values = YAML_VALUE_BYTES
            .checked_mul(2)
            .ok_or_else(|| self.too_many_bytes())?;
        let metadata = std::mem::size_of::<usize>()
            .checked_mul(2)
            .ok_or_else(|| self.too_many_bytes())?;
        values
            .checked_add(metadata)
            .ok_or_else(|| self.too_many_bytes())
    }

    fn too_many_nodes(&self) -> YamlPreflightError {
        YamlPreflightError::Bounds(YamlBoundsError::TooManyNodes {
            path: "root".to_string(),
            max_nodes: self.limits.max_nodes,
        })
    }

    fn too_many_bytes(&self) -> YamlPreflightError {
        YamlPreflightError::Bounds(YamlBoundsError::ExpandedBytes {
            path: "root".to_string(),
            max_bytes: self.limits.max_expanded_bytes,
        })
    }

    fn too_deep(&self) -> YamlPreflightError {
        self.too_deep_at(self.frames.len())
    }

    fn too_deep_at(&self, depth: usize) -> YamlPreflightError {
        YamlPreflightError::Bounds(YamlBoundsError::TooDeep {
            path: "root".to_string(),
            depth,
            max_depth: self.limits.max_depth,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct YamlValueParseError;

pub(crate) fn parse_yaml_value(bytes: &[u8]) -> Result<Value, YamlValueParseError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        serde_yaml::from_slice::<Value>(bytes)
    }))
    .map_err(|_| YamlValueParseError)?
    .map_err(|_| YamlValueParseError)
}

pub(crate) fn preflight_yaml(bytes: &[u8]) -> Result<(), YamlPreflightError> {
    preflight_yaml_with_limits(bytes, YamlPreflightLimits::default())
}

fn preflight_yaml_with_limits(
    bytes: &[u8],
    limits: YamlPreflightLimits,
) -> Result<(), YamlPreflightError> {
    let source = std::str::from_utf8(bytes).map_err(|_| YamlPreflightError::Malformed)?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut parser = Parser::new_from_str(source);
        let mut budget = YamlEventBudget::with_limits(limits);
        loop {
            let (event, _) = parser
                .next_token()
                .map_err(|_| YamlPreflightError::Malformed)?;
            let stream_end = matches!(event, Event::StreamEnd);
            budget.observe(event)?;
            if stream_end {
                return budget.finish();
            }
        }
    }))
    .unwrap_or(Err(YamlPreflightError::Malformed))
}

#[cfg(test)]
mod yaml_preflight_tests {
    use super::*;

    #[test]
    fn injected_expanded_budget_rejects_transitive_container_aliases() {
        let source = b"base: &base [x]\nnested: &nested [*base, *base]\ncopy: [*nested, *base]\n";
        let limits = YamlPreflightLimits {
            max_expanded_bytes: 1_000,
            ..YamlPreflightLimits::default()
        };

        let error = preflight_yaml_with_limits(source, limits)
            .expect_err("transitive aliases must charge their complete container summaries");
        assert!(matches!(
            error,
            YamlPreflightError::Bounds(YamlBoundsError::ExpandedBytes {
                max_bytes: 1_000,
                ..
            })
        ));
    }

    #[test]
    fn expanded_byte_arithmetic_overflow_fails_closed() {
        let limits = YamlPreflightLimits {
            max_depth: MAX_YAML_DEPTH,
            max_nodes: MAX_YAML_NODES,
            max_expanded_bytes: usize::MAX,
        };
        let mut budget = YamlEventBudget::with_limits(limits);
        budget.expanded_bytes = usize::MAX;

        let error = budget
            .reserve(YamlSummary {
                nodes: 1,
                max_depth: 0,
                expanded_bytes: 1,
            })
            .expect_err("expanded byte addition must not wrap");
        assert!(matches!(
            error,
            YamlPreflightError::Bounds(YamlBoundsError::ExpandedBytes {
                max_bytes: usize::MAX,
                ..
            })
        ));
    }

    #[test]
    fn recursive_alias_is_rejected_without_recursing_in_preflight() {
        assert!(matches!(
            preflight_yaml(b"&root [*root]\n"),
            Err(YamlPreflightError::Malformed)
        ));
    }
}

/// A successful pair load is the only operation in this task that combines
/// the two schemas; it never copies token strings into the runtime config.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigFileError {
    MissingFile {
        path: PathBuf,
    },
    FileRead {
        path: PathBuf,
        message: String,
    },
    FileTooLarge {
        path: PathBuf,
        max_bytes: usize,
    },
    MalformedYaml {
        path: PathBuf,
        message: String,
    },
    YamlTooDeep {
        path: String,
        depth: usize,
        max_depth: usize,
    },
    YamlTooComplex {
        path: String,
        max_nodes: usize,
    },
    YamlTooLarge {
        path: String,
        max_bytes: usize,
    },
    MultipleDocuments {
        path: PathBuf,
    },
    InvalidRoot {
        path: PathBuf,
    },
    InvalidVersion {
        path: PathBuf,
        version: u32,
    },
    UnknownKey {
        path: String,
        key: String,
    },
    SecretKey {
        path: String,
        key: String,
    },
    InvalidValue {
        path: PathBuf,
        field: String,
        message: String,
    },
    HttpsRequired {
        path: String,
        scheme: String,
    },
    InvalidAuthReference {
        path: String,
        credential_id: String,
        reason: String,
    },
    PolicyHandleInvalid,
    PolicyStaleGeneration {
        expected: u64,
        actual: u64,
    },
    PolicyExpired,
    PolicyOverreach {
        operation: String,
    },
    HomeUnavailable {
        variable: String,
    },
    HomeInvalid {
        reason: String,
    },
    Auth(AuthConfigError),
}

impl ConfigFileError {
    fn from_bounded_read(error: BoundedReadError) -> Self {
        match error {
            BoundedReadError::Missing { path } => Self::MissingFile { path },
            BoundedReadError::Io { path, message } => Self::FileRead { path, message },
            BoundedReadError::FileTooLarge { path, max_bytes } => {
                Self::FileTooLarge { path, max_bytes }
            }
        }
    }

    fn from_yaml_preflight(path: &Path, error: YamlPreflightError) -> Self {
        match error {
            YamlPreflightError::Malformed => Self::MalformedYaml {
                path: path.to_path_buf(),
                message: "invalid YAML syntax".to_string(),
            },
            YamlPreflightError::MultipleDocuments => Self::MultipleDocuments {
                path: path.to_path_buf(),
            },
            YamlPreflightError::Bounds(error) => Self::from_yaml_bounds(path, error),
        }
    }

    fn from_yaml_bounds(path: &Path, error: YamlBoundsError) -> Self {
        match error {
            YamlBoundsError::TooDeep {
                path: yaml_path,
                depth,
                max_depth,
            } => Self::YamlTooDeep {
                path: format!("{}:{yaml_path}", path.display()),
                depth,
                max_depth,
            },
            YamlBoundsError::TooManyNodes {
                path: yaml_path,
                max_nodes,
            } => Self::YamlTooComplex {
                path: format!("{}:{yaml_path}", path.display()),
                max_nodes,
            },
            YamlBoundsError::ExpandedBytes {
                path: yaml_path,
                max_bytes,
            } => Self::YamlTooLarge {
                path: format!("{}:{yaml_path}", path.display()),
                max_bytes,
            },
        }
    }
}

impl fmt::Display for ConfigFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFile { path } => {
                write!(formatter, "config file is missing: {}", path.display())
            }
            Self::FileRead { path, message } => write!(
                formatter,
                "cannot read config file {}: {message}",
                path.display()
            ),
            Self::FileTooLarge { path, max_bytes } => write!(
                formatter,
                "config file {} exceeds the {max_bytes}-byte limit",
                path.display()
            ),
            Self::MalformedYaml { path, message } => {
                write!(formatter, "malformed YAML in {}: {message}", path.display())
            }
            Self::YamlTooDeep {
                path,
                depth,
                max_depth,
            } => write!(
                formatter,
                "YAML path {path} has depth {depth}, exceeding {max_depth}"
            ),
            Self::YamlTooComplex { path, max_nodes } => write!(
                formatter,
                "YAML path {path} exceeds the {max_nodes}-node limit"
            ),
            Self::YamlTooLarge { path, max_bytes } => write!(
                formatter,
                "YAML path {path} exceeds the {max_bytes}-byte expanded allocation limit"
            ),
            Self::MultipleDocuments { path } => write!(
                formatter,
                "config file {} contains multiple YAML documents",
                path.display()
            ),
            Self::InvalidRoot { path } => write!(
                formatter,
                "config document root must be a mapping: {}",
                path.display()
            ),
            Self::InvalidVersion { path, version } => write!(
                formatter,
                "unsupported config version {version} in {}",
                path.display()
            ),
            Self::UnknownKey { path, key } => {
                write!(formatter, "unknown config key {path} ({key:?})")
            }
            Self::SecretKey { path, key } => write!(
                formatter,
                "credential-bearing config key {path} ({key:?}) is not allowed"
            ),
            Self::InvalidValue {
                path,
                field,
                message,
            } => write!(
                formatter,
                "invalid config field {field} in {}: {message}",
                path.display()
            ),
            Self::HttpsRequired { path, scheme } => {
                write!(formatter, "config URL {path} must use HTTPS (got {scheme})")
            }
            Self::InvalidAuthReference {
                path,
                credential_id,
                reason,
            } => write!(
                formatter,
                "invalid auth reference {path} -> {credential_id:?}: {reason}"
            ),
            Self::PolicyHandleInvalid => {
                write!(formatter, "policy handle is missing, forged, or unusable")
            }
            Self::PolicyStaleGeneration { expected, actual } => write!(
                formatter,
                "policy generation {actual} is stale; expected {expected}"
            ),
            Self::PolicyExpired => write!(formatter, "policy handle has expired"),
            Self::PolicyOverreach { operation } => write!(
                formatter,
                "RSS cannot expand trusted policy via {operation}"
            ),
            Self::HomeUnavailable { variable } => write!(
                formatter,
                "cannot resolve agent home; {variable} is unavailable"
            ),
            Self::HomeInvalid { reason } => write!(formatter, "invalid agent home: {reason}"),
            Self::Auth(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ConfigFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Auth(error) => Some(error),
            _ => None,
        }
    }
}

impl ConfigFileError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::PolicyHandleInvalid => "policy_handle_invalid",
            Self::PolicyStaleGeneration { .. } => "policy_stale_generation",
            Self::PolicyExpired => "policy_expired",
            Self::PolicyOverreach { .. } => "policy_overreach",
            Self::InvalidAuthReference { .. } => "invalid_auth_reference",
            Self::HttpsRequired { .. } => "https_required",
            Self::HomeUnavailable { .. } | Self::HomeInvalid { .. } => "home_invalid",
            _ => "config_invalid",
        }
    }

    pub fn path(&self) -> Option<String> {
        match self {
            Self::MissingFile { path }
            | Self::FileRead { path, .. }
            | Self::FileTooLarge { path, .. }
            | Self::MalformedYaml { path, .. }
            | Self::MultipleDocuments { path }
            | Self::InvalidRoot { path }
            | Self::InvalidVersion { path, .. }
            | Self::InvalidValue { path, .. } => Some(path.display().to_string()),
            Self::YamlTooDeep { path, .. }
            | Self::YamlTooComplex { path, .. }
            | Self::YamlTooLarge { path, .. }
            | Self::UnknownKey { path, .. }
            | Self::SecretKey { path, .. }
            | Self::HttpsRequired { path, .. }
            | Self::InvalidAuthReference { path, .. } => Some(path.clone()),
            Self::Auth(error) => Some(error.to_string()),
            _ => None,
        }
    }
}

const POLICY_HANDLE_CLASS: &str = "OpaquePolicyHandle";
const POLICY_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Host-minted policy capability. RSS may copy it but cannot construct, forge,
/// stringify, or expand a trusted policy from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaquePolicyHandle {
    id: String,
}

impl OpaquePolicyHandle {
    pub fn class(&self) -> &'static str {
        POLICY_HANDLE_CLASS
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn from_id(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

/// Sanitized, RSS-visible policy summary. It never includes tokens, raw
/// authorities that RSS could replay, or handle internals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SanitizedPolicySummary {
    pub providers: Vec<String>,
    pub workspace_root_count: usize,
    pub approval_read: String,
    pub approval_write: String,
    pub approval_process: String,
    pub policy_generation: u64,
    pub max_turns: u64,
    pub max_tool_calls: u64,
    pub max_tool_output_bytes: usize,
}

/// Canonical Stage A snapshot envelope returned by [`load_snapshot`].
#[derive(Clone, Debug)]
pub struct ConfigSnapshotEnvelope {
    pub public_config: ConfigFile,
    pub credential_refs: Vec<String>,
    pub policy_handle: OpaquePolicyHandle,
    pub policy_generation: u64,
    pub policy_summary: SanitizedPolicySummary,
}

/// Fixture/host policy probe intent. Production workspace/OAuth surfaces later
/// replace these operations; Stage A only proves the handle cannot expand.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyIntent {
    pub op: String,
    pub path: Option<String>,
    pub write: Option<String>,
    pub name: Option<String>,
    pub policy_generation: Option<u64>,
}

/// Successful policy probe result.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyProbe {
    pub ok: bool,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct TrustedPolicySnapshot {
    home: PathBuf,
    generation: u64,
    expires_at: Instant,
    revoked: bool,
    expired: bool,
    providers: Vec<String>,
    workspace_root_count: usize,
    approval_read: String,
    approval_write: String,
    approval_process: String,
    max_turns: u64,
    max_tool_calls: u64,
    max_tool_output_bytes: usize,
}

#[derive(Default)]
struct PolicyTable {
    entries: HashMap<String, TrustedPolicySnapshot>,
    generations: HashMap<PathBuf, u64>,
}

fn policy_table() -> &'static Mutex<PolicyTable> {
    static TABLE: OnceLock<Mutex<PolicyTable>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(PolicyTable::default()))
}

fn lock_policy_table() -> std::sync::MutexGuard<'static, PolicyTable> {
    policy_table()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Loads `config.yaml` + `auth.yaml` for a host-resolved home and injects a
/// trusted policy handle. Raw tokens stay host-side.
pub fn load_snapshot(
    host_home: impl AsRef<Path>,
) -> Result<ConfigSnapshotEnvelope, ConfigFileError> {
    let paths = AgentPaths::from_home(host_home)?;
    let loaded = ConfigFile::load_pair(&paths)?;
    let credential_refs = loaded.auth.credentials.keys().cloned().collect::<Vec<_>>();
    let mut table = lock_policy_table();
    let generation = table
        .generations
        .get(&paths.home)
        .copied()
        .unwrap_or(0)
        .saturating_add(1);
    table.generations.insert(paths.home.clone(), generation);
    for entry in table.entries.values_mut() {
        if entry.home == paths.home {
            entry.revoked = true;
        }
    }
    let summary = SanitizedPolicySummary {
        providers: loaded.config.providers.keys().cloned().collect(),
        workspace_root_count: loaded.config.workspaces.allowed_roots.len(),
        approval_read: loaded.config.approvals.read.clone(),
        approval_write: loaded.config.approvals.write.clone(),
        approval_process: loaded.config.approvals.process.clone(),
        policy_generation: generation,
        max_turns: loaded.config.agent.max_turns,
        max_tool_calls: loaded.config.agent.max_tool_calls,
        max_tool_output_bytes: loaded.config.agent.max_tool_output_bytes,
    };
    let handle = OpaquePolicyHandle::from_id(format!("oph_{}", uuid::Uuid::new_v4().simple()));
    table.entries.insert(
        handle.id().to_string(),
        TrustedPolicySnapshot {
            home: paths.home,
            generation,
            expires_at: Instant::now() + POLICY_TTL,
            revoked: false,
            expired: false,
            providers: summary.providers.clone(),
            workspace_root_count: summary.workspace_root_count,
            approval_read: summary.approval_read.clone(),
            approval_write: summary.approval_write.clone(),
            approval_process: summary.approval_process.clone(),
            max_turns: summary.max_turns,
            max_tool_calls: summary.max_tool_calls,
            max_tool_output_bytes: summary.max_tool_output_bytes,
        },
    );
    Ok(ConfigSnapshotEnvelope {
        public_config: loaded.config,
        credential_refs,
        policy_handle: handle,
        policy_generation: generation,
        policy_summary: summary,
    })
}

/// Fixture host probe: copies alias the same entry; forged, stale, expired, or
/// expanding intents fail closed.
pub fn check_policy(
    handle: &OpaquePolicyHandle,
    intent: &PolicyIntent,
) -> Result<PolicyProbe, ConfigFileError> {
    let mut table = lock_policy_table();
    let entry = table
        .entries
        .get_mut(handle.id())
        .ok_or(ConfigFileError::PolicyHandleInvalid)?;
    if entry.revoked {
        return Err(ConfigFileError::PolicyStaleGeneration {
            expected: entry.generation,
            actual: intent.policy_generation.unwrap_or(0),
        });
    }
    if entry.expired || Instant::now() >= entry.expires_at {
        return Err(ConfigFileError::PolicyExpired);
    }
    if let Some(claimed) = intent.policy_generation
        && claimed != entry.generation
    {
        return Err(ConfigFileError::PolicyStaleGeneration {
            expected: entry.generation,
            actual: claimed,
        });
    }
    match intent.op.as_str() {
        "inspect" => Ok(PolicyProbe { ok: true }),
        "expire" => {
            entry.expired = true;
            entry.expires_at = Instant::now();
            Ok(PolicyProbe { ok: true })
        }
        "add_workspace_root" | "raise_approval" | "add_header" => {
            Err(ConfigFileError::PolicyOverreach {
                operation: intent.op.clone(),
            })
        }
        _ => Err(ConfigFileError::PolicyHandleInvalid),
    }
}

/// Convenience function for callers that do not need the associated method.
pub fn load_config(path: impl AsRef<Path>) -> Result<ConfigFile, ConfigFileError> {
    ConfigFile::load(path)
}
