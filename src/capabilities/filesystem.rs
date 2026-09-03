//! Workspace-relative confined filesystem primitives.
//!
//! These operations do not embed model-visible tool names, schemas, or result
//! formatting. Every effect requires a valid execution token.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use rustscript_vm::{
    ConfinedFileType, ConfinedFsError, ConfinedFsErrorKind, ConfinedFsLimits, ConfinedFsRoot,
    ConfinedMetadata, MAX_COMPONENT_BYTES, MAX_ENUM_ENTRIES, MAX_READ_BYTES, MAX_WRITE_BYTES,
};

use super::{
    confined_io::FrozenDir,
    hash::content_hash,
    lifecycle::CapabilityLifecycle,
    types::{CapabilityError, CapabilityOwner, CapabilityRisk, TokenClaims},
};

/// Explicit byte and listing ceilings for one filesystem capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemLimits {
    pub max_read_bytes: usize,
    pub max_write_bytes: usize,
    pub max_list_entries: usize,
}

impl Default for FilesystemLimits {
    fn default() -> Self {
        Self {
            max_read_bytes: 1024 * 1024,
            max_write_bytes: 1024 * 1024,
            max_list_entries: 4096,
        }
    }
}

/// Metadata for one confined workspace path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsMetadata {
    pub file_type: &'static str,
    pub len: u64,
}

/// Bounded range read of a confined regular file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsRead {
    pub bytes: Vec<u8>,
    pub offset: u64,
    pub truncated: bool,
    pub hash: Option<String>,
}

/// One directory listing entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsDirEntry {
    pub name: String,
    pub file_type: &'static str,
    pub len: u64,
}

/// Bounded directory listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsList {
    pub entries: Vec<FsDirEntry>,
    pub cursor: u64,
    pub next_cursor: u64,
    pub truncated: bool,
}

/// Result of an atomic compare-and-swap write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsWrite {
    pub hash: String,
    pub len: usize,
}

/// Confined filesystem capability bound to one lifecycle owner.
#[derive(Clone)]
pub struct FilesystemCapability {
    lifecycle: CapabilityLifecycle,
    owner: CapabilityOwner,
    limits: FilesystemLimits,
    root: Arc<ConfinedFsRoot>,
    frozen: Arc<FrozenDir>,
    cas_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl FilesystemCapability {
    /// Constructs a filesystem capability. Limits must be positive.
    ///
    /// Opens and validates the confined workspace root once at admission.
    pub fn new(
        lifecycle: CapabilityLifecycle,
        owner: CapabilityOwner,
        limits: FilesystemLimits,
    ) -> Result<Self, CapabilityError> {
        if limits.max_read_bytes == 0 || limits.max_write_bytes == 0 || limits.max_list_entries == 0
        {
            return Err(CapabilityError::new(
                "invalid_configuration",
                "filesystem limits must be positive",
            ));
        }
        let root = ConfinedFsRoot::with_limits(
            lifecycle.workspace(),
            ConfinedFsLimits {
                max_read_bytes: MAX_READ_BYTES,
                max_write_bytes: limits.max_write_bytes.min(MAX_WRITE_BYTES),
                max_entries: MAX_ENUM_ENTRIES,
                max_entry_name_bytes: MAX_COMPONENT_BYTES,
                max_temp_attempts: 32,
            },
        )
        .map_err(map_fs_error)?;
        let frozen = FrozenDir::open(lifecycle.workspace())?;
        Ok(Self {
            lifecycle,
            owner,
            limits,
            root: Arc::new(root),
            frozen: Arc::new(frozen),
            cas_locks: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Stats a workspace-relative path without following a leaf symlink.
    pub fn metadata(&self, token: &str, path: &str) -> Result<FsMetadata, CapabilityError> {
        let _claims = self.authorize(token, CapabilityRisk::Read)?;
        let meta = deny_symlink(self.root.metadata(path).map_err(map_fs_error)?)?;
        Ok(FsMetadata {
            file_type: file_type_name(meta.file_type()),
            len: meta.len(),
        })
    }

    /// Reads a bounded byte range from a confined regular file.
    pub fn read_range(
        &self,
        token: &str,
        path: &str,
        offset: u64,
        limit: usize,
    ) -> Result<FsRead, CapabilityError> {
        let _claims = self.authorize(token, CapabilityRisk::Read)?;
        if limit > self.limits.max_read_bytes {
            return Err(CapabilityError::new(
                "budget_exceeded",
                "requested read exceeds the configured bound",
            ));
        }
        let meta = deny_symlink(self.root.metadata(path).map_err(map_fs_error)?)?;
        if meta.file_type() != ConfinedFileType::File {
            return Err(CapabilityError::new(
                "wrong_type",
                "path is not a regular file",
            ));
        }
        let read = self.frozen.read_range(path, offset, limit)?;
        let file_len = read.file_len;
        let truncated = offset.saturating_add(read.bytes.len() as u64) < file_len;
        let complete = offset == 0 && !truncated && (read.bytes.len() as u64) == file_len;
        Ok(FsRead {
            hash: Some(if complete {
                content_hash(&read.bytes)
            } else {
                bounded_identity(offset, read.bytes.len(), file_len)
            }),
            bytes: read.bytes,
            offset,
            truncated,
        })
    }

    /// Lists a confined directory with an explicit entry bound and cursor.
    pub fn list(
        &self,
        token: &str,
        path: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<FsList, CapabilityError> {
        let _claims = self.authorize(token, CapabilityRisk::Read)?;
        if limit > self.limits.max_list_entries {
            return Err(CapabilityError::new(
                "budget_exceeded",
                "requested listing exceeds the configured bound",
            ));
        }
        if !path.is_empty() {
            let meta = deny_symlink(self.root.metadata(path).map_err(map_fs_error)?)?;
            if meta.file_type() != ConfinedFileType::Directory {
                return Err(CapabilityError::new(
                    "wrong_type",
                    "path is not a directory",
                ));
            }
        }
        let page = self.frozen.list_page(path, cursor, limit)?;
        Ok(FsList {
            entries: page
                .entries
                .into_iter()
                .map(|entry| FsDirEntry {
                    name: entry.name,
                    file_type: entry.file_type,
                    len: entry.len,
                })
                .collect(),
            next_cursor: page.next_cursor,
            truncated: page.truncated,
            cursor,
        })
    }

    /// Atomically writes a file when the expected content hash matches.
    ///
    /// An empty `expected_hash` requires the destination not to exist.
    pub fn write_atomic(
        &self,
        token: &str,
        path: &str,
        expected_hash: &str,
        bytes: &[u8],
    ) -> Result<FsWrite, CapabilityError> {
        let _claims = self.authorize(token, CapabilityRisk::Write)?;
        if bytes.len() > self.limits.max_write_bytes {
            return Err(CapabilityError::new(
                "budget_exceeded",
                "requested write exceeds the configured bound",
            ));
        }
        let lock = self.lock_for(path);
        let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.validate_expected_hash(path, expected_hash)?;
        self.root.write_file(path, bytes).map_err(map_fs_error)?;
        Ok(FsWrite {
            hash: content_hash(bytes),
            len: bytes.len(),
        })
    }

    fn validate_expected_hash(
        &self,
        path: &str,
        expected_hash: &str,
    ) -> Result<(), CapabilityError> {
        match self.root.metadata(path) {
            Ok(meta) => {
                if meta.file_type() == ConfinedFileType::Symlink {
                    return Err(CapabilityError::new(
                        "path_denied",
                        "symlinks are not followed",
                    ));
                }
                if expected_hash.is_empty() {
                    return Err(CapabilityError::new(
                        "cas_mismatch",
                        "destination already exists",
                    ));
                }
                if meta.file_type() != ConfinedFileType::File {
                    return Err(CapabilityError::new(
                        "wrong_type",
                        "destination is not a regular file",
                    ));
                }
                let current = self.root.read_file(path).map_err(map_fs_error)?;
                if content_hash(&current) != expected_hash {
                    return Err(CapabilityError::new(
                        "cas_mismatch",
                        "content hash does not match",
                    ));
                }
            }
            Err(error) if error.kind() == ConfinedFsErrorKind::NotFound => {
                if !expected_hash.is_empty() {
                    return Err(CapabilityError::new(
                        "cas_mismatch",
                        "content hash does not match",
                    ));
                }
            }
            Err(error) => return Err(map_fs_error(error)),
        }
        Ok(())
    }

    fn lock_for(&self, path: &str) -> Arc<Mutex<()>> {
        let mut locks = self
            .cas_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locks
            .entry(path.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn authorize(&self, token: &str, risk: CapabilityRisk) -> Result<TokenClaims, CapabilityError> {
        self.lifecycle
            .authorize(&self.owner, token, risk)
            .map_err(CapabilityError::from)
    }
}

fn bounded_identity(offset: u64, window_len: usize, file_len: u64) -> String {
    format!("range:{offset}:{window_len}:{file_len}")
}

fn deny_symlink(meta: ConfinedMetadata) -> Result<ConfinedMetadata, CapabilityError> {
    if meta.file_type() == ConfinedFileType::Symlink {
        return Err(CapabilityError::new(
            "path_denied",
            "symlinks are not followed",
        ));
    }
    Ok(meta)
}

fn file_type_name(file_type: ConfinedFileType) -> &'static str {
    match file_type {
        ConfinedFileType::File => "file",
        ConfinedFileType::Directory => "directory",
        ConfinedFileType::Symlink => "symlink",
        ConfinedFileType::Other => "other",
    }
}

fn map_fs_error(error: ConfinedFsError) -> CapabilityError {
    let code = match error.kind() {
        ConfinedFsErrorKind::ParentTraversal
        | ConfinedFsErrorKind::AbsolutePath
        | ConfinedFsErrorKind::SymlinkDenied
        | ConfinedFsErrorKind::HardlinkDenied
        | ConfinedFsErrorKind::PathPrefix
        | ConfinedFsErrorKind::InvalidSeparator
        | ConfinedFsErrorKind::InvalidPath
        | ConfinedFsErrorKind::RaceDetected
        | ConfinedFsErrorKind::CapabilityMismatch => "path_denied",
        ConfinedFsErrorKind::BudgetExceeded => "budget_exceeded",
        other => other.as_str(),
    };
    CapabilityError::new(code, error.to_string())
}
