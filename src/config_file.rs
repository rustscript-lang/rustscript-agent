//! Versioned, secret-free runtime configuration and persistent path resolution.
//!
//! This module owns the YAML boundary for `config.yaml`. Authentication
//! material is deliberately kept in [`crate::auth::config`]; the two schemas
//! are parsed and validated independently before their references are joined.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use url::Url;

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
        if !self.providers.is_empty() && !self.providers.contains_key(&self.model.provider) {
            return Err(ConfigFileError::InvalidProviderReference {
                path: "model.provider".to_string(),
                provider: self.model.provider.clone(),
            });
        }
        for (provider_name, provider) in &self.providers {
            if let Some(credential_id) = provider.auth.as_deref() {
                let path = format!("providers.{provider_name}.auth");
                let credential = auth.credentials.get(credential_id).ok_or_else(|| {
                    ConfigFileError::InvalidAuthReference {
                        path: path.clone(),
                        credential_id: credential_id.to_string(),
                        reason: "credential ID is not present in auth.yaml".to_string(),
                    }
                })?;
                if credential.provider != *provider_name {
                    return Err(ConfigFileError::InvalidAuthReference {
                        path,
                        credential_id: credential_id.to_string(),
                        reason: format!(
                            "credential belongs to provider {:?}, not {:?}",
                            credential.provider, provider_name
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    fn from_yaml_bytes(path: &Path, bytes: &[u8]) -> Result<Self, ConfigFileError> {
        let value: Value =
            serde_yaml::from_slice(bytes).map_err(|error| ConfigFileError::MalformedYaml {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
        validate_yaml_bounds(&value)
            .map_err(|error| ConfigFileError::from_yaml_bounds(path, error))?;
        reject_secret_keys_recursive(path, &value, "root")?;
        validate_config_shape(path, &value)?;
        let config: Self =
            serde_yaml::from_value(value).map_err(|error| ConfigFileError::InvalidValue {
                path: path.to_path_buf(),
                field: "document".to_string(),
                message: error.to_string(),
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
            validate_https_url(
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
            validate_https_url(value, source, &format!("{prefix}.{field}"), false)?;
        }
    }
    if let Some(redirect_uri) = oauth.redirect_uri.as_deref() {
        validate_https_url(
            redirect_uri,
            source,
            &format!("{prefix}.redirect_uri"),
            true,
        )?;
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

fn validate_https_url(
    value: &str,
    source: &Path,
    field: &str,
    allow_loopback_http: bool,
) -> Result<(), ConfigFileError> {
    let url = Url::parse(value).map_err(|error| ConfigFileError::InvalidValue {
        path: source.to_path_buf(),
        field: field.to_string(),
        message: format!("invalid URL: {error}"),
    })?;
    let loopback = url
        .host_str()
        .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]"));
    let http_allowed = allow_loopback_http && url.scheme() == "http" && loopback;
    if url.scheme() != "https" && !http_allowed {
        return Err(ConfigFileError::HttpsRequired {
            path: field.to_string(),
            scheme: url.scheme().to_string(),
        });
    }
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
    if url.host_str().is_none() {
        return Err(invalid_value(source, field, "URL must contain a host"));
    }
    Ok(())
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
}

pub(crate) fn validate_yaml_bounds(value: &Value) -> Result<(), YamlBoundsError> {
    let mut nodes = 0;
    visit_yaml(value, "root", 0, &mut nodes)
}

fn visit_yaml(
    value: &Value,
    path: &str,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), YamlBoundsError> {
    if depth > MAX_YAML_DEPTH {
        return Err(YamlBoundsError::TooDeep {
            path: path.to_string(),
            depth,
            max_depth: MAX_YAML_DEPTH,
        });
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_YAML_NODES {
        return Err(YamlBoundsError::TooManyNodes {
            path: path.to_string(),
            max_nodes: MAX_YAML_NODES,
        });
    }
    match value {
        Value::Mapping(mapping) => {
            for (key, value) in mapping {
                visit_yaml(key, path, depth + 1, nodes)?;
                let key = key.as_str().unwrap_or("<non-string-key>");
                visit_yaml(value, &format!("{path}.{key}"), depth + 1, nodes)?;
            }
        }
        Value::Sequence(sequence) => {
            for (index, value) in sequence.iter().enumerate() {
                visit_yaml(value, &format!("{path}[{index}]"), depth + 1, nodes)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        _ => {}
    }
    Ok(())
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
    InvalidProviderReference {
        path: String,
        provider: String,
    },
    InvalidAuthReference {
        path: String,
        credential_id: String,
        reason: String,
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
            Self::InvalidProviderReference { path, provider } => write!(
                formatter,
                "config field {path} references unknown provider {provider:?}"
            ),
            Self::InvalidAuthReference {
                path,
                credential_id,
                reason,
            } => write!(
                formatter,
                "invalid auth reference {path} -> {credential_id:?}: {reason}"
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

/// Convenience function for callers that do not need the associated method.
pub fn load_config(path: impl AsRef<Path>) -> Result<ConfigFile, ConfigFileError> {
    ConfigFile::load(path)
}
