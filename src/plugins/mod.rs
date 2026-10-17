//! RSS plugin manifest, immutable package store, and effect closure.
//!
//! This module stops at a prepared closed entry. It does not activate a
//! service, open global storage, or turn a signature into a capability.

mod error;
mod manifest;
mod prepare;
mod resolve;
mod schema;
mod store;
mod yaml;

pub use error::{
    EFFECT_KINDS, EFFECT_RECOVERY, GRAPH_LOCK_FIELDS, HOST_RUNTIME, MANIFEST_FIELDS, PLUGIN_KINDS,
    PluginError, PluginErrorKind,
};
pub use manifest::parse_plugin_manifest;
pub use resolve::{GraphLock, PackageRequirement, ResolveRequest, resolve_installed};
pub use schema::{canonical_schema_documents, schema_snapshot_drift};
pub use store::{
    InstallAuthorization, InstalledPackage, PackageRevision, PackageStore, PackageTrust,
    PublisherKey,
};
pub use yaml::strict_yaml_to_json;
