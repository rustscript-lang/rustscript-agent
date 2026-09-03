//! Workspace-relative confined filesystem primitives.
//!
//! These operations do not embed model-visible tool names, schemas, or result
//! formatting. Every effect requires a valid execution token.

use rustscript_vm::{
    ConfinedFileType, ConfinedFsError, ConfinedFsErrorKind, ConfinedFsLimits, ConfinedFsRoot,
    ConfinedMetadata, EnumerationBudget, MAX_ENUM_ENTRIES,
};

use super::hash::content_hash;
use super::lifecycle::CapabilityLifecycle;
use super::types::{CapabilityError, CapabilityOwner, CapabilityRisk, TokenClaims};

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
}

impl FilesystemCapability {
    /// Constructs a filesystem capability. Limits must be positive.
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
        Ok(Self {
            lifecycle,
            owner,
            limits,
        })
    }

    /// Stats a workspace-relative path without following a leaf symlink.
    pub fn metadata(&self, token: &str, path: &str) -> Result<FsMetadata, CapabilityError> {
        let claims = self.authorize(token, CapabilityRisk::Read)?;
        let root = open_root(&claims)?;
        let meta = deny_symlink(root.metadata(path).map_err(map_fs_error)?)?;
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
        let claims = self.authorize(token, CapabilityRisk::Read)?;
        if limit > self.limits.max_read_bytes {
            return Err(CapabilityError::new(
                "budget_exceeded",
                "requested read exceeds the configured bound",
            ));
        }
        let root = open_root(&claims)?;
        let meta = deny_symlink(root.metadata(path).map_err(map_fs_error)?)?;
        if meta.file_type() != ConfinedFileType::File {
            return Err(CapabilityError::new(
                "wrong_type",
                "path is not a regular file",
            ));
        }
        let contents = root.read_file(path).map_err(map_fs_error)?;
        let hash = Some(content_hash(&contents));
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if start >= contents.len() {
            return Ok(FsRead {
                bytes: Vec::new(),
                offset,
                truncated: false,
                hash,
            });
        }
        let end = start.saturating_add(limit).min(contents.len());
        Ok(FsRead {
            bytes: contents[start..end].to_vec(),
            offset,
            truncated: end < contents.len(),
            hash,
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
        let claims = self.authorize(token, CapabilityRisk::Read)?;
        if limit > self.limits.max_list_entries {
            return Err(CapabilityError::new(
                "budget_exceeded",
                "requested listing exceeds the configured bound",
            ));
        }
        let root = open_root(&claims)?;
        if !path.is_empty() {
            let meta = deny_symlink(root.metadata(path).map_err(map_fs_error)?)?;
            if meta.file_type() != ConfinedFileType::Directory {
                return Err(CapabilityError::new(
                    "wrong_type",
                    "path is not a directory",
                ));
            }
        }
        let budget = EnumerationBudget {
            max_entries: MAX_ENUM_ENTRIES,
            max_name_bytes: 255,
        };
        let mut entries = root
            .enumerate_with_budget(path, budget)
            .map_err(map_fs_error)?;
        entries.retain(|entry| entry.name() != "." && entry.name() != "..");
        let start = usize::try_from(cursor).unwrap_or(usize::MAX);
        let page = if start >= entries.len() {
            Vec::new()
        } else {
            entries[start..entries.len().min(start.saturating_add(limit))]
                .iter()
                .map(|entry| FsDirEntry {
                    name: entry.name().to_string(),
                    file_type: file_type_name(entry.metadata().file_type()),
                    len: entry.metadata().len(),
                })
                .collect()
        };
        let next = start.saturating_add(page.len());
        Ok(FsList {
            truncated: next < entries.len(),
            next_cursor: u64::try_from(next).unwrap_or(u64::MAX),
            cursor,
            entries: page,
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
        let claims = self.authorize(token, CapabilityRisk::Write)?;
        if bytes.len() > self.limits.max_write_bytes {
            return Err(CapabilityError::new(
                "budget_exceeded",
                "requested write exceeds the configured bound",
            ));
        }
        let root = open_root(&claims)?;
        match root.metadata(path) {
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
                let current = root.read_file(path).map_err(map_fs_error)?;
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
        root.write_file(path, bytes).map_err(map_fs_error)?;
        Ok(FsWrite {
            hash: content_hash(bytes),
            len: bytes.len(),
        })
    }

    fn authorize(&self, token: &str, risk: CapabilityRisk) -> Result<TokenClaims, CapabilityError> {
        self.lifecycle
            .authorize(&self.owner, token, risk)
            .map_err(CapabilityError::from)
    }
}

fn open_root(claims: &TokenClaims) -> Result<ConfinedFsRoot, CapabilityError> {
    ConfinedFsRoot::with_limits(&claims.workspace, ConfinedFsLimits::default())
        .map_err(map_fs_error)
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
