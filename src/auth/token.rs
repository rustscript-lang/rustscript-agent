//! Credential identifiers and structural status labels.
//!
//! Secret values intentionally have no public Rust representation in this
//! module. Hosts create opaque secret slots inside the store boundary; RSS only
//! receives opaque handles and sanitized metadata.

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

/// A named credential reference. It never contains a secret value.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CredentialId(String);

impl CredentialId {
    /// Validates and constructs a credential identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, TokenError> {
        let value = value.into();
        validate_credential_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CredentialId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for CredentialId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CredentialId {
    type Err = TokenError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<&str> for CredentialId {
    type Error = TokenError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for CredentialId {
    type Error = TokenError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A structural status label. Transition decisions belong to RSS policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthStatus {
    Active,
    ReauthRequired,
    Disabled,
}

impl AuthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::ReauthRequired => "reauth_required",
            Self::Disabled => "disabled",
        }
    }
}

impl FromStr for AuthStatus {
    type Err = TokenError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "reauth_required" => Ok(Self::ReauthRequired),
            "disabled" => Ok(Self::Disabled),
            _ => Err(TokenError::InvalidStatus),
        }
    }
}

/// Redaction-safe failures used by identifier and structural-label parsers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenError {
    InvalidCredentialId,
    InvalidStatus,
}

impl fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCredentialId => write!(formatter, "credential ID is invalid"),
            Self::InvalidStatus => write!(formatter, "credential status is invalid"),
        }
    }
}

impl std::error::Error for TokenError {}

fn validate_credential_id(value: &str) -> Result<(), TokenError> {
    if value.is_empty()
        || value.len() > 128
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || value.contains('/')
        || value.contains('\\')
    {
        return Err(TokenError::InvalidCredentialId);
    }
    Ok(())
}
