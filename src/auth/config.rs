//! Strict `auth.yaml` schema for named credentials and token lifecycle state.
//!
//! This module intentionally contains no network, refresh, locking, or atomic
//! persistence code. It only parses the bounded file format used by the later
//! auth-store task and keeps token values out of `Debug` output.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

use crate::config_file::{
    BoundedReadError, YamlBoundsError, read_bounded_bytes, validate_yaml_bounds,
};

/// Maximum bytes read from `auth.yaml` before parsing is attempted.
pub const MAX_AUTH_YAML_BYTES: usize = 256 * 1024;

/// Version-one credential and token lifecycle document.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub version: u32,
    #[serde(default)]
    pub credentials: BTreeMap<String, CredentialConfig>,
}

/// Compatibility name for a persisted credential entry.
pub type Credential = CredentialConfig;

/// A named credential entry. Token fields are intentionally opaque to callers
/// and are redacted by the custom `Debug` implementation below.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialConfig {
    pub provider: String,
    pub kind: String,
    pub source: String,
    pub token_type: String,
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub expires_at_ms: u64,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub generation: u64,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub last_refresh_at_ms: Option<u64>,
}

fn default_status() -> String {
    "active".to_string()
}

impl fmt::Debug for CredentialConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialConfig")
            .field("provider", &self.provider)
            .field("kind", &self.kind)
            .field("source", &self.source)
            .field("token_type", &self.token_type)
            .field("access_token", &"REDACTED")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "REDACTED"),
            )
            .field("expires_at_ms", &self.expires_at_ms)
            .field("scopes", &self.scopes)
            .field("account_id", &self.account_id)
            .field("generation", &self.generation)
            .field("status", &self.status)
            .field("last_refresh_at_ms", &self.last_refresh_at_ms)
            .finish()
    }
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthConfig")
            .field("version", &self.version)
            .field("credentials", &self.credentials)
            .finish()
    }
}

impl AuthConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, AuthConfigError> {
        let path = path.as_ref();
        let bytes = read_bounded_bytes(path, MAX_AUTH_YAML_BYTES)
            .map_err(AuthConfigError::from_bounded_read)?;
        Self::from_yaml_bytes(path, &bytes)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(source: &str) -> Result<Self, AuthConfigError> {
        if source.len() > MAX_AUTH_YAML_BYTES {
            return Err(AuthConfigError::FileTooLarge {
                path: PathBuf::from("<inline auth.yaml>"),
                max_bytes: MAX_AUTH_YAML_BYTES,
            });
        }
        Self::from_yaml_bytes(Path::new("<inline auth.yaml>"), source.as_bytes())
    }

    pub fn load_from_home() -> Result<Self, AuthConfigError> {
        let paths = crate::config_file::AgentPaths::resolve()
            .map_err(|error| AuthConfigError::HomeResolution(error.to_string()))?;
        Self::load(&paths.auth)
    }

    fn from_yaml_bytes(path: &Path, bytes: &[u8]) -> Result<Self, AuthConfigError> {
        let value: Value =
            serde_yaml::from_slice(bytes).map_err(|error| AuthConfigError::MalformedYaml {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
        validate_yaml_bounds(&value)
            .map_err(|error| AuthConfigError::from_yaml_bounds(path, error))?;
        validate_auth_shape(path, &value)?;
        let config: Self =
            serde_yaml::from_value(value).map_err(|error| AuthConfigError::InvalidValue {
                path: path.to_path_buf(),
                field: "document".to_string(),
                message: error.to_string(),
            })?;
        config.validate(path)?;
        Ok(config)
    }

    fn validate(&self, source: &Path) -> Result<(), AuthConfigError> {
        if self.version != 1 {
            return Err(AuthConfigError::InvalidVersion {
                path: source.to_path_buf(),
                version: self.version,
            });
        }
        for (credential_id, credential) in &self.credentials {
            validate_visible(
                credential_id,
                source,
                &format!("credentials.{credential_id}"),
            )?;
            validate_visible(
                &credential.provider,
                source,
                &format!("credentials.{credential_id}.provider"),
            )?;
            validate_visible(
                &credential.kind,
                source,
                &format!("credentials.{credential_id}.kind"),
            )?;
            validate_visible(
                &credential.source,
                source,
                &format!("credentials.{credential_id}.source"),
            )?;
            validate_visible(
                &credential.token_type,
                source,
                &format!("credentials.{credential_id}.token_type"),
            )?;
            if credential.access_token.is_empty() {
                return Err(invalid_value(
                    source,
                    &format!("credentials.{credential_id}.access_token"),
                    "must not be blank",
                ));
            }
            if !matches!(
                credential.status.as_str(),
                "active" | "reauth_required" | "disabled"
            ) {
                return Err(invalid_value(
                    source,
                    &format!("credentials.{credential_id}.status"),
                    "must be active, reauth_required, or disabled",
                ));
            }
            for (index, scope) in credential.scopes.iter().enumerate() {
                validate_visible(
                    scope,
                    source,
                    &format!("credentials.{credential_id}.scopes[{index}]"),
                )?;
            }
            if let Some(account_id) = credential.account_id.as_deref() {
                validate_visible(
                    account_id,
                    source,
                    &format!("credentials.{credential_id}.account_id"),
                )?;
            }
        }
        Ok(())
    }
}

impl std::str::FromStr for AuthConfig {
    type Err = AuthConfigError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        AuthConfig::from_str(source)
    }
}

fn validate_auth_shape(source: &Path, value: &Value) -> Result<(), AuthConfigError> {
    let root = value
        .as_mapping()
        .ok_or_else(|| AuthConfigError::InvalidRoot {
            path: source.to_path_buf(),
        })?;
    validate_known_keys(source, "root", root, &["version", "credentials"])?;
    if let Some(credentials) = root.get(Value::String("credentials".to_string())) {
        let credentials = as_mapping(credentials, source, "credentials")?;
        for (credential_id, credential) in credentials {
            let credential_id = yaml_key(source, "credentials", credential_id)?;
            let path = format!("credentials.{credential_id}");
            let credential = as_mapping(credential, source, &path)?;
            validate_known_keys(
                source,
                &path,
                credential,
                &[
                    "provider",
                    "kind",
                    "source",
                    "token_type",
                    "access_token",
                    "refresh_token",
                    "expires_at_ms",
                    "scopes",
                    "account_id",
                    "generation",
                    "status",
                    "last_refresh_at_ms",
                ],
            )?;
        }
    }
    Ok(())
}

fn validate_known_keys(
    source: &Path,
    path: &str,
    mapping: &Mapping,
    allowed: &[&str],
) -> Result<(), AuthConfigError> {
    for key in mapping.keys() {
        let key = yaml_key(source, path, key)?;
        let key_path = if path == "root" {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        if is_behavior_key(&key) {
            return Err(AuthConfigError::BehaviorKey {
                path: key_path,
                key,
            });
        }
        if !allowed.contains(&key.as_str()) {
            return Err(AuthConfigError::UnknownKey {
                path: key_path,
                key,
            });
        }
    }
    Ok(())
}

fn is_behavior_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
        "model"
            | "models"
            | "base_url"
            | "workspace"
            | "workspaces"
            | "allowed_roots"
            | "default"
            | "timeout"
            | "timeout_ms"
            | "max_turns"
            | "max_tool_calls"
            | "max_tool_output_bytes"
            | "protocol"
            | "oauth"
            | "issuer"
            | "client_id"
            | "client_secret"
            | "token_endpoint"
            | "redirect_uri"
            | "headers"
            | "approval"
            | "approvals"
            | "compaction"
            | "agent"
            | "provider_options"
    )
}

fn validate_visible(value: &str, source: &Path, field: &str) -> Result<(), AuthConfigError> {
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

fn invalid_value(source: &Path, field: &str, message: &str) -> AuthConfigError {
    AuthConfigError::InvalidValue {
        path: source.to_path_buf(),
        field: field.to_string(),
        message: message.to_string(),
    }
}

fn as_mapping<'a>(
    value: &'a Value,
    source: &Path,
    path: &str,
) -> Result<&'a Mapping, AuthConfigError> {
    value
        .as_mapping()
        .ok_or_else(|| invalid_value(source, path, "must be a mapping"))
}

fn yaml_key(source: &Path, path: &str, key: &Value) -> Result<String, AuthConfigError> {
    key.as_str()
        .map(str::to_string)
        .ok_or_else(|| invalid_value(source, path, "mapping keys must be strings"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthConfigError {
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
    BehaviorKey {
        path: String,
        key: String,
    },
    InvalidValue {
        path: PathBuf,
        field: String,
        message: String,
    },
    HomeResolution(String),
}

impl AuthConfigError {
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

impl fmt::Display for AuthConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFile { path } => {
                write!(formatter, "auth file is missing: {}", path.display())
            }
            Self::FileRead { path, message } => write!(
                formatter,
                "cannot read auth file {}: {message}",
                path.display()
            ),
            Self::FileTooLarge { path, max_bytes } => write!(
                formatter,
                "auth file {} exceeds the {max_bytes}-byte limit",
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
            Self::InvalidRoot { path } => {
                write!(
                    formatter,
                    "auth document root must be a mapping: {}",
                    path.display()
                )
            }
            Self::InvalidVersion { path, version } => write!(
                formatter,
                "unsupported auth version {version} in {}",
                path.display()
            ),
            Self::UnknownKey { path, key } => {
                write!(formatter, "unknown auth key {path} ({key:?})")
            }
            Self::BehaviorKey { path, key } => write!(
                formatter,
                "behavior-bearing auth key {path} ({key:?}) is not allowed"
            ),
            Self::InvalidValue {
                path,
                field,
                message,
            } => write!(
                formatter,
                "invalid auth field {field} in {}: {message}",
                path.display()
            ),
            Self::HomeResolution(message) => {
                write!(formatter, "cannot resolve auth home: {message}")
            }
        }
    }
}

impl std::error::Error for AuthConfigError {}
