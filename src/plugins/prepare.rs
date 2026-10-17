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

#[derive(Clone)]
pub struct PreparedGraph {
    sources: BTreeMap<(String, String), Vec<u8>>,
    callables: BTreeMap<String, String>,
    exports: BTreeMap<String, String>,
    trust: BTreeMap<String, PackageTrust>,
    programs: BTreeMap<String, Arc<rustscript_vm::Program>>,
}

impl std::fmt::Debug for PreparedGraph {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedGraph")
            .field("callables", &self.callables)
            .field("trust", &self.trust)
            .field("programs", &self.programs.keys().collect::<Vec<_>>())
            .finish()
    }
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

    /// Export name from the captured package manifest, not a later store read.
    pub fn export_name(&self, package_id: &str) -> Option<&str> {
        self.exports.get(package_id).map(String::as_str)
    }

    pub fn trust(&self, package_id: &str) -> Option<PackageTrust> {
        self.trust.get(package_id).copied()
    }

    /// Callable program compiled from the captured bytes. The graph id is not
    /// a substitute for this program.
    pub fn program(&self, package_id: &str) -> Option<Arc<rustscript_vm::Program>> {
        self.programs.get(package_id).cloned()
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
        if let Some((cached_lock, prepared)) = self
            .prepared
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            && cached_lock == lock
        {
            return Ok(prepared.clone());
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
            exports: BTreeMap::new(),
            trust: BTreeMap::new(),
            programs: BTreeMap::new(),
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
            prepared.exports.insert(
                package.manifest.id.clone(),
                package.manifest.entry.export.clone(),
            );
            let (callable, program) = compile_package(package)?;
            prepared
                .callables
                .insert(package.manifest.id.clone(), callable);
            prepared
                .programs
                .insert(package.manifest.id.clone(), program);
        }
        *self
            .prepared
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some((lock.clone(), prepared.clone()));
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

fn compile_package(
    package: &InstalledPackage,
) -> Result<(String, Arc<rustscript_vm::Program>), PluginError> {
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
    Ok((entry, Arc::new(compiled.program)))
}

fn is_tool_role(package: &InstalledPackage) -> bool {
    package.manifest.kind == "tool" && package.manifest.contract == "agent.tool/v1"
}

fn charge_program(
    package: &InstalledPackage,
    program: &rustscript_vm::Program,
) -> Result<(), PluginError> {
    let tool_role = is_tool_role(package);
    for import in &program.imports {
        // Role fencing precedes embedding exemptions: bounded completion and
        // cancellation-aware waiting are tool operations regardless of trust.
        if (is_tool_lease(&import.name) || import.name == "agent::sleep_ms") && !tool_role {
            return Err(PluginError::new(
                PluginErrorKind::UnauthorizedHostImport,
                import.name.clone(),
            ));
        }
        if package.trust == PackageTrust::EmbeddingOwnedBuiltin
            && is_embedding_runtime_import(&import.name)
        {
            continue;
        }
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
        "cap::clock_monotonic_ms" | "agent::sleep_ms" => Some("clock.read"),
        "agent::model_request" => Some("model.request"),
        "stream::emit" => Some("event.emit"),
        _ if name.starts_with("http::") => Some("remote.write"),
        _ if is_tool_lease(name) => None,
        _ if name.starts_with("sqlite::") || name.starts_with("auth::") => None,
        _ => None,
    };
    if name.starts_with("sqlite::")
        || name.starts_with("auth::")
        || (name.starts_with("agent_runtime::") && !is_tool_lease(name))
    {
        return Err(PluginError::new(
            PluginErrorKind::UnauthorizedHostImport,
            name,
        ));
    }
    if effect.is_none() && !is_pure(name) && !is_tool_lease(name) {
        return Err(PluginError::new(
            PluginErrorKind::UnauthorizedHostImport,
            name,
        ));
    }
    Ok(effect)
}

fn is_embedding_runtime_import(name: &str) -> bool {
    name.starts_with("cap::artifact_")
}

fn is_tool_lease(name: &str) -> bool {
    // Exact bounded call-result publication shares the prepared-call protocol.
    // Native owner/call/run, metadata, single-result, quota and rollback checks
    // remain authoritative; this grants no generic artifact put/get/reference.
    matches!(
        name,
        "agent_runtime::tool_prepare" | "agent_runtime::tool_commit" | "cap::artifact_put_result"
    )
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
    matches!(
        root,
        "json" | "bytes" | "cap" | "agent" | "agent_runtime" | "http" | "stream"
    )
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

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn completion_names_are_exact_and_embedding_trust_cannot_bypass_tool_role() {
        assert_eq!(charge_name("cap::artifact_put_result").unwrap(), None);
        for name in [
            "cap::artifact_put",
            "cap::artifact_get",
            "cap::artifact_reference",
            "cap::artifact_put_results",
            "cap::artifact_unknown",
        ] {
            assert_eq!(
                charge_name(name).unwrap_err().kind,
                PluginErrorKind::UnauthorizedHostImport
            );
        }
        let manifest = super::super::manifest::parse_plugin_manifest(
            "format: rustscript.plugin/v1\nid: org.rustscript.policy\nversion: 1.0.0\nkind: library\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.library/v1\nhost_abi: agent.cap/v1\nentry:\n  path: invoke.rss\n  export: invoke\ndependencies: []\ncapabilities: []\neffects:\n  contract: agent.effects/v1\n  entries:\n    invoke:\n      direct: []\n      delegated: []\n"
        ).unwrap();
        for trust in [
            PackageTrust::AcceptedPublisher,
            PackageTrust::EmbeddingOwnedBuiltin,
        ] {
            for source in [
                "pub fn invoke(token: string) -> map { cap::artifact_put_result(token, bytes::from_utf8(\"result\"), {}) }\n",
                "pub fn invoke(value: map) -> map { agent_runtime::tool_prepare(value) }\n",
                "pub fn invoke(token: string) -> map { agent_runtime::tool_commit(token, {}) }\n",
                "pub fn invoke(value: int) -> int { agent::sleep_ms(value) }\n",
            ] {
                let mut package = InstalledPackage::new(
                    "policy",
                    manifest.clone(),
                    BTreeMap::from([("invoke.rss".into(), source.as_bytes().to_vec())]),
                );
                package.trust = trust;
                assert_eq!(
                    compile_package(&package).unwrap_err().kind,
                    PluginErrorKind::UnauthorizedHostImport
                );
            }
        }
        let mut manifest = manifest;
        manifest.kind = "tool".into();
        manifest.contract = "agent.tool/v1".into();
        let mut package = InstalledPackage::new(
            "policy",
            manifest,
            BTreeMap::from([(
                "invoke.rss".into(),
                b"pub fn invoke(value: int) -> int { agent::sleep_ms(value) }\n".to_vec(),
            )]),
        );
        package.trust = PackageTrust::EmbeddingOwnedBuiltin;
        assert_eq!(
            compile_package(&package).unwrap_err().kind,
            PluginErrorKind::UndeclaredDirectEffect
        );
    }
}
