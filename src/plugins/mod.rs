//! RSS plugin manifest, immutable package store, and effect closure.
//!
//! This module stops at a prepared closed entry. It does not activate a
//! service, open global storage, or turn a signature into a capability.

mod control_store;
mod error;
mod manifest;
mod pin;
mod prepare;
mod resolve;
mod schema;
mod state;
mod store;
mod yaml;

pub use crate::runtime::native_tools::trusted_tool_package_root;
pub use control_store::{
    ActivationHistoryEntry, ActivationPointer, GraphPinRequirement, GraphRetention,
    GraphRevocation, PackageArtifactRef, PluginControlError, PluginControlStore, StoreLockReceipt,
    ValidatedLockMetadata,
};
pub use error::{
    COMPILE_ENVIRONMENT, EFFECT_KINDS, EFFECT_RECOVERY, GRAPH_LOCK_FIELDS, HOST_RUNTIME,
    MANIFEST_FIELDS, PLUGIN_KINDS, PluginError, PluginErrorKind,
};
pub use manifest::{StateDeclaration, StateMigration, parse_plugin_manifest};
pub use pin::{
    PinnedAdmitContext, PinnedToolAdmission, PinnedToolAdmitError, admit_pinned_tool_run,
    restore_owned_pin,
};
pub(crate) use pin::{
    PreparedProductionPin, prepare_checkpoint_pin, prepare_production_pin,
    restore_owned_pin_with_cancellation, seal_production_receipt, validate_owned_admission_receipt,
    validate_owned_harness_fact,
};
pub(crate) use prepare::{SupportedManagedTopology, verified_pure_leaves};
pub(crate) use prepare::child_program_import_allowed;
pub use resolve::{
    CompatibilityCheck, EffectOrigin, GraphLock, GraphMetadataDiff, HarnessSelection,
    HarnessSelectionRequest, LockedEdge, LockedEffect, LockedEffectItem, LockedPackage,
    PackageRequirement, PackageRevisionDiff, PermissionChange, PermissionChangeKind,
    PermissionDiff, PermissionIdentity, PermissionLocation, PermissionValue, PurePolicySelection,
    ResolveRequest, ScopeBinding, resolve_installed,
};
pub use schema::{canonical_schema_documents, schema_snapshot_drift};
pub(crate) use schema::{
    validate_managed_effect, validate_managed_maintenance, validate_managed_workspace,
};
pub(crate) use state::{
    CollectorHealthState, PLUGIN_STATE_MAX_RESERVATIONS, PluginStateCandidateLease,
    PluginStateCandidates, PluginStateWriterLease, PluginStateWriters,
};
pub use state::{
    PluginStateBindRequest, PluginStateBinding, PluginStateError, PluginStateMigrationProgram,
    PluginStateObject, PluginStatePayload, PluginStateRestoreRequest, PluginStateRoot,
    PluginStateRootKey, PluginStateRootRef, PluginStateScope, PluginStateSnapshot,
    PluginStateStore, STATE_DOCUMENT_MAX_BYTES, validate_state_migration_source,
};
pub(crate) use store::embedding_payload_bytes;
pub use store::{
    InstallAuthorization, InstalledPackage, PackageRevision, PackageStore, PackageTrust,
    PublisherKey,
};
pub(crate) use yaml::strict_managed_yaml_to_json;
pub use yaml::strict_yaml_to_json;
