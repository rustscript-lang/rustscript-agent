//! Auth bundle entry: a thin adapter over the generic closed-bundle compiler.
//!
//! Only the auth-specific constants, catalog, dialects, host-root factory, and
//! error mapping live here. The compile/admission algorithm is owned by
//! `crate::runtime::closed_bundle`.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use super::{AUTH_ENTRY_PARSER_DIALECT, AuthEntryError, AuthEntryRunner, MAX_AGENT_SOURCE_BYTES};
use crate::auth::host::{auth_host_catalog, auth_host_module};
use crate::runtime::closed_bundle::{
    ClosedBundleError, ClosedBundleLimits, ClosedBundleOptions, compile_closed_bundle,
};

const MAX_BUNDLE_FILES: usize = 64;
const MAX_BUNDLE_DEPTH: usize = 16;
const MAX_BUNDLE_SOURCE_BYTES: usize = 4 * MAX_AGENT_SOURCE_BYTES;
const VIRTUAL_BUNDLE_ROOT: &str = "/__rustscript_agent_auth_bundle__";
const JSON_ROOT: &str = "json";
const AUTH_ENTRY_EXPORT: &str = "run";

impl AuthEntryRunner {
    /// Compile a closed, bounded RSS tree from trusted embedding-owned bytes.
    /// No input path is opened or materialized on disk.
    pub fn from_bundle(entry_path: &str, sources: &[(&str, &str)]) -> Result<Self, AuthEntryError> {
        let host_roots = admitted_host_roots();
        let catalog = auth_host_catalog();
        let compiled = compile_closed_bundle(
            entry_path,
            sources,
            ClosedBundleOptions {
                limits: ClosedBundleLimits {
                    max_files: MAX_BUNDLE_FILES,
                    max_depth: MAX_BUNDLE_DEPTH,
                    max_file_bytes: MAX_AGENT_SOURCE_BYTES,
                    max_total_bytes: MAX_BUNDLE_SOURCE_BYTES,
                },
                virtual_root: Path::new(VIRTUAL_BUNDLE_ROOT),
                host_roots: &host_roots,
                catalog: Arc::clone(&catalog),
                dialect: &AUTH_ENTRY_PARSER_DIALECT,
                entry_export: AUTH_ENTRY_EXPORT,
            },
        )
        .map_err(map_bundle_error)?;
        Ok(Self {
            program: compiled.program,
            catalog,
            bundle_json_encode: true,
            entry_name: compiled.entry_name,
        })
    }
}

fn map_bundle_error(error: ClosedBundleError) -> AuthEntryError {
    match error {
        ClosedBundleError::SourceTooLarge => AuthEntryError::SourceTooLarge,
        ClosedBundleError::SourceInvalid => AuthEntryError::SourceInvalid,
        ClosedBundleError::ImportDenied => AuthEntryError::ImportDenied,
        ClosedBundleError::CompileFailed => AuthEntryError::CompileFailed,
    }
}

fn admitted_host_roots() -> BTreeSet<String> {
    let mut roots = BTreeSet::new();
    for descriptor in auth_host_module().descriptors() {
        if let Some((root, _)) = descriptor.schema.name.split_once("::") {
            roots.insert(root.to_owned());
        }
    }
    roots.insert(JSON_ROOT.to_owned());
    roots
}
