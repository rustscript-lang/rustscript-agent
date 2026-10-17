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
mod store;
mod yaml;

pub use crate::runtime::native_tools::trusted_tool_package_root;
pub use control_store::{
    ActivationHistoryEntry, ActivationPointer, GraphRetention, PackageArtifactRef,
    PluginControlError, PluginControlStore, StoreLockReceipt, ValidatedLockMetadata,
};
pub use error::{
    COMPILE_ENVIRONMENT, EFFECT_KINDS, EFFECT_RECOVERY, GRAPH_LOCK_FIELDS, HOST_RUNTIME,
    MANIFEST_FIELDS, PLUGIN_KINDS, PluginError, PluginErrorKind,
};
pub use manifest::parse_plugin_manifest;
pub use pin::{
    PinnedAdmitContext, PinnedToolAdmission, PinnedToolAdmitError, admit_pinned_tool_run,
    restore_owned_pin,
};
pub(crate) use pin::{prepare_production_pin, seal_production_receipt};
pub use resolve::{
    EffectOrigin, GraphLock, LockedEdge, LockedEffect, LockedEffectItem, LockedPackage,
    PackageRequirement, ResolveRequest, ScopeBinding, resolve_installed,
};
pub use schema::{canonical_schema_documents, schema_snapshot_drift};
pub(crate) use store::embedding_payload_bytes;
pub use store::{
    InstallAuthorization, InstalledPackage, PackageRevision, PackageStore, PackageTrust,
    PublisherKey,
};
pub use yaml::strict_yaml_to_json;
