//! Native filesystem effect: private views, immutable trees, and checkpoints.
//!
//! This module does not integrate plugins, OCI bundles, or a control plane.

pub(crate) mod authority;
pub(crate) mod broker;
mod checkpoint;
pub(crate) mod journal;
mod retention;
mod tree_store;
mod types;
mod workspace;

#[cfg(feature = "workspace-io-fault")]
pub use broker::{ManagedEffectFault, ManagedPrepareGateGuard};
pub use broker::{ManagedFinalWitness, ManagedStartedWitness};
#[doc(hidden)]
pub use checkpoint::pre_conversion_yaml_error;
pub use checkpoint::{CheckpointRecord, RestoredBranch, parse_checkpoint_yaml};
pub use journal::{
    CanonicalToolResultJson, DirectoryIdentity, ManagedApprovalBasis, ManagedArgumentIdentity,
    ManagedCallIdentity, ManagedCallReplay, ManagedCodeIdentity, ManagedCommitOutcome,
    ManagedEffectGetRequest, ManagedEffectRecord, ManagedEventRef, ManagedExternalEffects,
    ManagedMessageRef, ManagedObjectKind, ManagedObjectRef, ManagedOperationClass,
    ManagedOwnerScope, ManagedPreparedRecord, ManagedPublicationRef, ManagedPublicationStatus,
    ManagedRecoveryObservation, ManagedWorkspaceHead, ManagedWorkspaceIdentity,
    ManagedWorkspaceRecord, ManagedWriterState, parse_managed_effect_yaml,
    parse_managed_workspace_yaml,
};
pub use journal::{
    ManagedBranchCreateRequest, ManagedBranchReceipt, ManagedPublishReceipt, ManagedPublishRequest,
    ManagedWorkspacePublication,
};
pub use journal::{
    ManagedCheckpointArtifactRef, ManagedCheckpointCreateRequest, ManagedCheckpointGraphRef,
    ManagedCheckpointMode, ManagedCheckpointPublicConfig, ManagedCheckpointPublication,
    ManagedCheckpointReceipt, ManagedCheckpointRef, ManagedCheckpointStateCoverage,
    ManagedClosedOutputRef, ManagedExternalBoundary, ManagedExternalHighWater,
    ManagedExternalNotice, ManagedFrozenHistoryRef, ManagedMaintenanceFailure,
    ManagedPluginStateRootRef, ManagedPublicConfigRef, ManagedSourceCas,
    parse_managed_checkpoint_request_yaml, parse_managed_checkpoint_yaml,
    parse_managed_restore_request_yaml, parse_managed_restore_yaml,
};
pub use journal::{
    ManagedEffectListRequest, ManagedEffectPage, ManagedEffectSummary, ManagedResultChunk,
    ManagedResultReadRequest, ManagedRunEffectError, ManagedRunEffectListRequest,
};
pub use journal::{
    ManagedObjectReference, ManagedObjectReferenceKind, ManagedObjectReferencesRequest,
};
pub use journal::{
    ManagedRestoreAndAdmitRequest, ManagedRestoreAndAdmitResult, ManagedRestoreDisposition,
    ManagedRestoreGraphSelection, ManagedRestoreRunInput,
};
pub use types::{
    BranchEpoch, BranchId, CheckpointId, CheckpointRequest, EffectCancellation, EffectDeadline,
    EffectError, EffectErrorKind, EffectFailure, ExternalEffectNotice, ImportConsistency,
    ImportWorkspace, JournalEntry, JournalKind, MAX_TREE_BYTES, MAX_TREE_DEPTH, MAX_TREE_ENTRIES,
    OpenViewRequest, OwnerId, PublicCheckpointRef, PublicWorkspaceRef, Publication, PublishRequest,
    ResourceQuota, RestoreRequest, TreeId, WorkspaceId,
};
#[cfg(feature = "workspace-io-fault")]
pub use workspace::SimulatedIoFault;
pub use workspace::{EffectStore, WorkspaceHandle, WritableView};
