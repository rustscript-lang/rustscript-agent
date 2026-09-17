//! Agent-owned confined filesystem and bounded process backends.
//!
//! Frozen core no longer exports these types. The implementations are vendored
//! from the last SHA that published them so capability behavior stays intact.

#![allow(dead_code)]
#![allow(clippy::result_large_err)]

pub mod bounded_process;
pub mod confined_fs;
mod shared;

pub use bounded_process::{
    BoundedProcess, BoundedProcessError, BoundedProcessHandle, BoundedProcessRequest,
    CancellationToken, LogSnapshot, MAX_OUTPUT_BYTES, MAX_STDIN_BYTES, MAX_TIMEOUT, ProcessStatus,
};
pub use confined_fs::{
    ConfinedFileType, ConfinedFsError, ConfinedFsErrorKind, ConfinedFsLimits, ConfinedFsRoot,
    ConfinedMetadata, ConfinedPublicationState, MAX_COMPONENT_BYTES, MAX_ENUM_ENTRIES,
    MAX_READ_BYTES, MAX_WRITE_BYTES,
};
