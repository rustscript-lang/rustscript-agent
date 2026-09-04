//! Generic bounded artifact put/get/reference primitives.
//!
//! Ownership and quotas are bound to the authorizing token's owner, run, and
//! generation. This module does not format agent-facing artifact payloads.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

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
    result_calls: Mutex<HashSet<String>>,
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
                result_calls: Mutex::new(HashSet::new()),
            }),
        })
    }

    /// Stores bytes under a new opaque id.
    ///
    /// Workspace-mutating callers must still present a Write token. Read-only
    /// tools publish oversized envelopes through [`Self::put_result`].
    pub fn put(
        &self,
        token: &str,
        bytes: &[u8],
        metadata: &Value,
    ) -> Result<ArtifactRef, CapabilityError> {
        self.put_with_risk(token, bytes, metadata, CapabilityRisk::Write)
    }

    /// Publishes at most one result blob for the authorizing token/call.
    ///
    /// Metadata is allowlisted and rebound to the token's call/run/owner. This
    /// primitive does not grant filesystem write or arbitrary multi-object
    /// storage; generic [`Self::put`] remains Write-only.
    pub fn put_result(
        &self,
        token: &str,
        bytes: &[u8],
        metadata: &Value,
    ) -> Result<ArtifactRef, CapabilityError> {
        let claims = self.authorize(token, CapabilityRisk::Read)?;
        let bound = bind_result_metadata(metadata, &claims)?;
        let call_key = result_call_key(&claims);
        {
            let mut published = self
                .inner
                .result_calls
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !published.insert(call_key.clone()) {
                return Err(CapabilityError::new(
                    "artifact_already_published",
                    "a result artifact was already published for this call",
                ));
            }
        }
        match self.store_bytes(&claims, bytes, &bound) {
            Ok(refer) => Ok(refer),
            Err(error) => {
                self.inner
                    .result_calls
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&call_key);
                Err(error)
            }
        }
    }

    fn put_with_risk(
        &self,
        token: &str,
        bytes: &[u8],
        metadata: &Value,
        risk: CapabilityRisk,
    ) -> Result<ArtifactRef, CapabilityError> {
        let claims = self.authorize(token, risk)?;
        self.store_bytes(&claims, bytes, metadata)
    }

    fn store_bytes(
        &self,
        claims: &TokenClaims,
        bytes: &[u8],
        metadata: &Value,
    ) -> Result<ArtifactRef, CapabilityError> {
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

    /// Inspect stored bytes and bound metadata after the execution token closes.
    pub fn stored(&self, id: &str) -> Option<(Vec<u8>, Value)> {
        let objects = self
            .inner
            .objects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        objects
            .get(id)
            .map(|record| (record.bytes.clone(), record.metadata.clone()))
    }
}

const MAX_RESULT_METADATA_BYTES: usize = 256;
const MAX_RESULT_METADATA_STRING: usize = 128;

fn result_call_key(claims: &TokenClaims) -> String {
    format!("{}:{}", claims.generation, claims.call_id)
}

fn bind_result_metadata(metadata: &Value, claims: &TokenClaims) -> Result<Value, CapabilityError> {
    let Some(map) = metadata.as_object() else {
        return Err(CapabilityError::new(
            "invalid_request",
            "result metadata must be an object",
        ));
    };
    let encoded = serde_json::to_vec(metadata).unwrap_or_default();
    if encoded.len() > MAX_RESULT_METADATA_BYTES {
        return Err(CapabilityError::new(
            "invalid_request",
            "result metadata exceeds the allowlisted size",
        ));
    }
    for (key, value) in map {
        match key.as_str() {
            "call_id" => {
                let Some(call_id) = value.as_str() else {
                    return Err(CapabilityError::new(
                        "invalid_request",
                        "result metadata call_id must be a string",
                    ));
                };
                if call_id.len() > MAX_RESULT_METADATA_STRING {
                    return Err(CapabilityError::new(
                        "invalid_request",
                        "result metadata call_id exceeds the allowlisted size",
                    ));
                }
                if call_id != claims.call_id {
                    return Err(CapabilityError::new(
                        "invalid_request",
                        "result metadata call_id does not match the authorized token",
                    ));
                }
            }
            _ => {
                return Err(CapabilityError::new(
                    "invalid_request",
                    "result metadata field is not allowlisted",
                ));
            }
        }
    }
    Ok(json!({
        "call_id": claims.call_id,
        "run": claims.owner.run(),
        "owner": claims.owner.key(),
    }))
}
