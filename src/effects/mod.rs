//! Native filesystem effect: private views, immutable trees, and checkpoints.
//!
//! This module does not integrate plugins, OCI bundles, or a control plane.

mod checkpoint;
mod tree_store;
mod types;
mod workspace;

#[doc(hidden)]
pub use checkpoint::pre_conversion_yaml_error;
pub use checkpoint::{parse_checkpoint_yaml, CheckpointRecord, RestoredBranch};
pub use types::{
    BranchEpoch, BranchId, CheckpointId, CheckpointRequest, EffectCancellation, EffectDeadline,
    EffectError, EffectErrorKind, EffectFailure, ExternalEffectNotice, ImportConsistency,
    ImportWorkspace, JournalEntry, JournalKind, OpenViewRequest, OwnerId, PublicCheckpointRef,
    PublicWorkspaceRef, Publication, PublishRequest, ResourceQuota, RestoreRequest, TreeId,
    WorkspaceId, MAX_TREE_BYTES, MAX_TREE_DEPTH, MAX_TREE_ENTRIES,
};
#[cfg(feature = "workspace-io-fault")]
pub use workspace::SimulatedIoFault;
pub use workspace::{EffectStore, WorkspaceHandle, WritableView};
