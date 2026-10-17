//! Prepare a locked graph's real closed RSS entries.
//!
//! Compilation sees only captured package bytes. Host imports are charged from
//! the native catalog, never from a plugin's own description of itself.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use rustscript_vm::{ImportClause, SharedParserOptions, UsePathSegment, parse_source_with_dialect};

use crate::runtime::agent_host::agent_host_catalog;
use crate::runtime::closed_bundle::{self, ClosedBundleLimits, ClosedBundleOptions};
use crate::runtime::module_snapshot::snapshot_parser_dialect;

use super::error::{COMPILE_ENVIRONMENT, PluginError, PluginErrorKind};
use super::resolve::GraphLock;
use super::store::{InstalledPackage, PackageStore, PackageTrust};

const VIRTUAL_ROOT: &str = "/__rustscript_agent_plugin_rss__";

#[derive(Debug)]
pub struct PreparedGraph {
    sources: BTreeMap<(String, String), Vec<u8>>,
    callables: BTreeMap<String, String>,
    trust: BTreeMap<String, PackageTrust>,
}

impl PreparedGraph {
    pub fn captured_source(&self, package_id: &str, path: &str) -> Option<&[u8]> {
        self.sources
            .get(&(package_id.to_string(), path.to_string()))
            .map(Vec::as_slice)
    }

    pub fn entry_callable(&self, package_id: &str) -> Option<&str> {
        self.callables.get(package_id).map(String::as_str)
    }

    pub fn trust(&self, package_id: &str) -> Option<PackageTrust> {
        self.trust.get(package_id).copied()
    }
}

impl PackageStore {
    pub fn resolve(
        &self,
        request: &super::resolve::ResolveRequest,
    ) -> Result<GraphLock, PluginError> {
        super::resolve::resolve_installed(&self.load_installed()?, request)
    }

    pub fn prepare(&self, lock: &GraphLock) -> Result<PreparedGraph, PluginError> {
        if lock.compile_environment != COMPILE_ENVIRONMENT {
            return Err(PluginError::new(
                PluginErrorKind::ContractIncompatible,
                "compile environment",
            ));
        }
        // One verified capture. Compilation uses these bytes and does not re-read the store.
        let required: Vec<(&str, &str)> = lock
            .packages
            .iter()
            .map(|locked| (locked.id.as_str(), locked.artifact_id.as_str()))
            .collect();
        let installed = self.verified_capture(&required)?;
        let mut selected = Vec::new();
        for locked in &lock.packages {
            let package = installed
                .iter()
                .find(|package| {
                    package.artifact_id == locked.artifact_id && package.manifest.id == locked.id
                })
                .ok_or_else(|| {
                    PluginError::new(PluginErrorKind::MissingDependency, locked.id.clone())
                })?;
            selected.push(package);
        }
        for package in &selected {
            scan_package(package, &selected)?;
        }
        let mut prepared = PreparedGraph {
            sources: BTreeMap::new(),
            callables: BTreeMap::new(),
            trust: BTreeMap::new(),
        };
        for package in &selected {
            for (path, bytes) in &package.sources {
                prepared
                    .sources
                    .insert((package.manifest.id.clone(), path.clone()), bytes.clone());
            }
            prepared
                .trust
                .insert(package.manifest.id.clone(), package.trust);
            let callable = compile_package(package)?;
            prepared
                .callables
                .insert(package.manifest.id.clone(), callable);
        }
        Ok(prepared)
    }
}

fn scan_package(
    package: &InstalledPackage,
    selected: &[&InstalledPackage],
) -> Result<(), PluginError> {
    let aliases: BTreeSet<&str> = package
        .manifest
        .dependencies
        .iter()
        .map(|dependency| dependency.alias.as_str())
        .collect();
    let roots = host_roots();
    let prelude = catalog_prelude();
    for (path, bytes) in &package.sources {
        let source = std::str::from_utf8(bytes)
            .map_err(|_| PluginError::new(PluginErrorKind::CompileFailed, path.clone()))?;
        let Ok(imports) = scan_source(&format!("{prelude}{source}")) else {
            continue;
        };
        let prelude_count = scan_source(&prelude).map(|items| items.len()).unwrap_or(0);
        for import in imports.into_iter().skip(prelude_count) {
            let Some(first) = import.first() else {
                continue;
            };
            if aliases.contains(first.as_str()) {
                return Err(PluginError::new(
                    PluginErrorKind::PluginBoundaryBypass,
                    format!("{} {first}", package.manifest.id),
                ));
            }
            if roots.contains(first) && !is_allowed_host_root(first) {
                return Err(PluginError::new(
                    PluginErrorKind::UnauthorizedHostImport,
                    format!("{} {first}", package.manifest.id),
                ));
            }
        }
    }
    let _ = selected;
    Ok(())
}

fn scan_source(
    source: &str,
) -> Result<Vec<Vec<String>>, crate::runtime::closed_bundle::ClosedBundleError> {
    let ir = parse_source_with_dialect(
        source,
        snapshot_parser_dialect(),
        SharedParserOptions {
            source_id: 0,
            allow_implicit_externs: true,
            allow_implicit_semicolons: false,
            enforce_mutable_bindings: false,
            import_scan_mode: true,
        },
    )
    .map_err(|_| crate::runtime::closed_bundle::ClosedBundleError::SourceInvalid)?;
    let mut imports = Vec::new();
    for declaration in ir.use_declarations {
        if !matches!(
            declaration.clause,
            ImportClause::AllPublic | ImportClause::Named(_) | ImportClause::Namespace(_)
        ) {
            return Err(crate::runtime::closed_bundle::ClosedBundleError::ImportDenied);
        }
        let mut path = Vec::new();
        for segment in declaration.path {
            match segment {
                UsePathSegment::Ident(name) => path.push(name),
                UsePathSegment::Self_ | UsePathSegment::Super => {}
            }
        }
        imports.push(path);
    }
    Ok(imports)
}

fn compile_package(package: &InstalledPackage) -> Result<String, PluginError> {
    let host_roots = host_roots();
    let catalog = agent_host_catalog();
    let owned: Vec<(String, String)> = package
        .sources
        .iter()
        .filter_map(|(path, bytes)| {
            std::str::from_utf8(bytes).ok().map(|text| {
                let compiled_text = if path == &package.manifest.entry.path {
                    // Pure builtin namespaces only. This is compile context, not
                    // stored package bytes, and it cannot grant an effect.
                    format!("use bytes;\nuse json;\n{text}")
                } else {
                    text.to_string()
                };
                (path.clone(), compiled_text)
            })
        })
        .collect();
    let sources: Vec<(&str, &str)> = owned
        .iter()
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let compiled = closed_bundle::compile_bundled_closed_bundle(
        &package.manifest.entry.path,
        &sources,
        ClosedBundleOptions {
            limits: ClosedBundleLimits {
                max_files: 64,
                max_depth: 16,
                max_file_bytes: 1024 * 1024,
                max_total_bytes: 8 * 1024 * 1024,
            },
            virtual_root: Path::new(VIRTUAL_ROOT),
            host_roots: &host_roots,
            catalog: Arc::clone(&catalog),
            dialect: snapshot_parser_dialect(),
            entry_export: &package.manifest.entry.export,
        },
    )
    .map_err(|_| PluginError::new(PluginErrorKind::CompileFailed, package.manifest.id.clone()))?;
    let entry = compiled.entry_name.ok_or_else(|| {
        PluginError::new(
            PluginErrorKind::UncoveredExport,
            package.manifest.entry.export.clone(),
        )
    })?;
    charge_program(package, &compiled.program)?;
    Ok(entry)
}

fn charge_program(
    package: &InstalledPackage,
    program: &rustscript_vm::Program,
) -> Result<(), PluginError> {
    for import in &program.imports {
        if let Some(effect) = charge_name(&import.name)? {
            let declared = package
                .manifest
                .effects
                .entries
                .get(&package.manifest.entry.export)
                .map(|entry| entry.direct.iter().any(|item| item.kind == effect))
                .unwrap_or(false);
            if !declared {
                return Err(PluginError::new(
                    PluginErrorKind::UndeclaredDirectEffect,
                    format!("{} {}", package.manifest.id, effect),
                ));
            }
        }
    }
    Ok(())
}

fn charge_name(name: &str) -> Result<Option<&'static str>, PluginError> {
    if is_pure(name) {
        return Ok(None);
    }
    let effect = match name {
        "cap::fs_metadata" | "cap::fs_read_range" | "cap::fs_list" => Some("workspace.fs.read"),
        "cap::fs_write_atomic" => Some("workspace.fs.write"),
        "cap::process_spawn" | "cap::process_poll" | "cap::process_wait" | "cap::process_log"
        | "cap::process_write" | "cap::process_close" | "cap::process_kill" => {
            Some("process.spawn")
        }
        "cap::clock_monotonic_ms" => Some("clock.read"),
        "agent::model_request" => Some("model.request"),
        "stream::emit" => Some("event.emit"),
        _ if name.starts_with("http::") => Some("remote.write"),
        _ if name.starts_with("sqlite::")
            || name.starts_with("auth::")
            || name.starts_with("agent_runtime::") =>
        {
            None
        }
        _ => None,
    };
    if name.starts_with("sqlite::")
        || name.starts_with("auth::")
        || name.starts_with("agent_runtime::")
    {
        return Err(PluginError::new(
            PluginErrorKind::UnauthorizedHostImport,
            name,
        ));
    }
    if effect.is_none() && !is_pure(name) {
        return Err(PluginError::new(
            PluginErrorKind::UnauthorizedHostImport,
            name,
        ));
    }
    Ok(effect)
}

fn is_pure(name: &str) -> bool {
    name.starts_with("json::")
        || name.starts_with("bytes::")
        || matches!(
            name,
            "agent::utf8_byte_len"
                | "agent::utf8_truncate"
                | "agent::parse_json_object"
                | "agent::control_check"
        )
}

fn is_allowed_host_root(root: &str) -> bool {
    matches!(root, "json" | "bytes" | "cap" | "agent" | "http" | "stream")
}

fn catalog_prelude() -> String {
    let mut prelude = String::new();
    for root in host_roots() {
        prelude.push_str("use ");
        prelude.push_str(&root);
        prelude.push_str(";\n");
    }
    prelude
}

fn host_roots() -> BTreeSet<String> {
    let mut roots = BTreeSet::from(["json".to_string(), "bytes".to_string()]);
    for function in agent_host_catalog().functions() {
        if let Some((namespace, _)) = function.name.split_once("::") {
            roots.insert(namespace.to_string());
        }
    }
    roots
}
