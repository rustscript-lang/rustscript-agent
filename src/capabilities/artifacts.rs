//! Generic bounded artifact put/get/reference primitives.
//!
//! Ownership and quotas are bound to the authorizing token's owner, run, and
//! generation. This module does not format agent-facing artifact payloads.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;

use super::hash::content_hash;
use super::lifecycle::CapabilityLifecycle;
use super::types::{CapabilityError, CapabilityOwner, CapabilityRisk, TokenClaims};

/// Store-wide artifact ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactLimits {
    pub max_object_bytes: usize,
    pub max_total_bytes: usize,
    pub max_objects: usize,
}

impl Default for ArtifactLimits {
    fn default() -> Self {
        Self {
            max_object_bytes: 8 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_objects: 1_024,
        }
    }
}

/// Opaque artifact identity plus bounded metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRef {
    pub id: String,
    pub len: usize,
    pub hash: String,
    pub metadata: Value,
}

struct ArtifactRecord {
    owner_key: String,
    generation: u64,
    bytes: Vec<u8>,
    hash: String,
    metadata: Value,
}

struct ArtifactInner {
    lifecycle: CapabilityLifecycle,
    owner: CapabilityOwner,
    limits: ArtifactLimits,
    objects: Mutex<HashMap<String, ArtifactRecord>>,
    total_bytes: Mutex<usize>,
}

/// In-memory run-scoped artifact store.
#[derive(Clone)]
pub struct ArtifactCapability {
    inner: Arc<ArtifactInner>,
}

impl ArtifactCapability {
    /// Constructs an empty store with the supplied quotas.
    pub fn new(
        lifecycle: CapabilityLifecycle,
        owner: CapabilityOwner,
        limits: ArtifactLimits,
    ) -> Result<Self, CapabilityError> {
        if limits.max_object_bytes == 0 || limits.max_total_bytes == 0 || limits.max_objects == 0 {
            return Err(CapabilityError::new(
                "invalid_configuration",
                "artifact limits must be positive",
            ));
        }
        Ok(Self {
            inner: Arc::new(ArtifactInner {
                lifecycle,
                owner,
                limits,
                objects: Mutex::new(HashMap::new()),
                total_bytes: Mutex::new(0),
            }),
        })
    }

    /// Stores bytes under a new opaque id.
    pub fn put(
        &self,
        token: &str,
        bytes: &[u8],
        metadata: &Value,
    ) -> Result<ArtifactRef, CapabilityError> {
        let claims = self.authorize(token, CapabilityRisk::Write)?;
        if bytes.len() > self.inner.limits.max_object_bytes {
            return Err(CapabilityError::new(
                "artifact_too_large",
                "artifact exceeds the per-object bound",
            ));
        }
        let mut objects = self
            .inner
            .objects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut total = self
            .inner
            .total_bytes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if objects.len() >= self.inner.limits.max_objects
            || total.saturating_add(bytes.len()) > self.inner.limits.max_total_bytes
        {
            return Err(CapabilityError::new(
                "artifact_store_exhausted",
                "artifact store quota is exhausted",
            ));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let hash = content_hash(bytes);
        objects.insert(
            id.clone(),
            ArtifactRecord {
                owner_key: claims.owner.key(),
                generation: claims.generation,
                bytes: bytes.to_vec(),
                hash: hash.clone(),
                metadata: metadata.clone(),
            },
        );
        *total = total.saturating_add(bytes.len());
        Ok(ArtifactRef {
            id,
            len: bytes.len(),
            hash,
            metadata: metadata.clone(),
        })
    }

    /// Returns stored bytes for an owned artifact.
    pub fn get(&self, token: &str, id: &str) -> Result<Vec<u8>, CapabilityError> {
        Ok(self.lookup(token, id, CapabilityRisk::Read)?.bytes)
    }

    /// Returns identity metadata without payload bytes.
    pub fn reference(&self, token: &str, id: &str) -> Result<ArtifactRef, CapabilityError> {
        let record = self.lookup(token, id, CapabilityRisk::Read)?;
        Ok(ArtifactRef {
            id: id.to_string(),
            len: record.bytes.len(),
            hash: record.hash,
            metadata: record.metadata,
        })
    }

    fn authorize(&self, token: &str, risk: CapabilityRisk) -> Result<TokenClaims, CapabilityError> {
        self.inner
            .lifecycle
            .authorize(&self.inner.owner, token, risk)
            .map_err(CapabilityError::from)
    }

    fn lookup(
        &self,
        token: &str,
        id: &str,
        risk: CapabilityRisk,
    ) -> Result<ArtifactRecord, CapabilityError> {
        let claims = self.authorize(token, risk)?;
        let objects = self
            .inner
            .objects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let record = objects
            .get(id)
            .ok_or_else(|| CapabilityError::new("artifact_not_found", "artifact is unknown"))?;
        if record.owner_key != claims.owner.key() || record.generation != claims.generation {
            return Err(CapabilityError::new(
                "artifact_not_found",
                "artifact is unknown",
            ));
        }
        Ok(ArtifactRecord {
            owner_key: record.owner_key.clone(),
            generation: record.generation,
            bytes: record.bytes.clone(),
            hash: record.hash.clone(),
            metadata: record.metadata.clone(),
        })
    }
}
