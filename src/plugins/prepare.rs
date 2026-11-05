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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SupportedManagedTopology {
    selection: super::resolve::HarnessSelection,
}
impl SupportedManagedTopology {
    pub(crate) fn validate(lock: &GraphLock, tool: &InstalledPackage) -> Option<Self> {
        use super::resolve::HarnessSelection;
        if !tool.manifest.dependencies.is_empty() || !lock.edges.is_empty() {
            // Phase-A narrow shape: one AcceptedPublisher stateless tool plus
            // one pure leaf library. The leaf manifest and sources are
            // verified at prepare time; lock plus tool manifest already pin
            // the exact shape, including the single library-relation edge.
            return tool_library_topology(lock, tool).map(|_| Self {
                selection: lock.harness_selection.clone(),
            });
        }
        let embedding = tool.manifest.id == crate::runtime::native_tools::EMBEDDING_PACKAGE_ID
            && tool.trust == PackageTrust::EmbeddingOwnedBuiltin;
        if !embedding && !signed_stateless_tool_only(lock, tool) {
            return None;
        }
        let valid = match &lock.harness_selection {
            HarnessSelection::ToolOnly { tool_package } => {
                tool_package == &tool.manifest.id
                    && lock.packages.len() == 1
                    && lock
                        .closure
                        .iter()
                        .all(|item| item.package == tool.manifest.id)
                    && lock
                        .closure
                        .iter()
                        .filter(|item| item.entry == tool.manifest.entry.export)
                        .count()
                        == 1
                    && lock
                        .closure
                        .iter()
                        .filter(|item| item.entry != tool.manifest.entry.export)
                        .all(|item| item.effects.is_empty())
                    && (embedding || catalog_export_paths(tool).len() == 1)
            }
            HarnessSelection::ContextPrompt {
                tool_package,
                policy,
            } => {
                embedding
                    && tool_package == &tool.manifest.id
                    && lock.packages.len() == 2
                    && lock.closure.len() == 4
                    && lock.packages.iter().any(|p| {
                        p.id == policy.package_id
                            && p.artifact_id == policy.artifact_id
                            && p.kind == "library"
                    })
                    && [
                        &policy.prompt_export,
                        &policy.context_export,
                        &policy.guardian_export,
                    ]
                    .iter()
                    .all(|name| {
                        lock.closure
                            .iter()
                            .filter(|e| {
                                e.package == policy.package_id
                                    && &e.entry == *name
                                    && e.effects.is_empty()
                            })
                            .count()
                            == 1
                    })
            }
            HarnessSelection::Unselected => false,
        };
        valid.then(|| Self {
            selection: lock.harness_selection.clone(),
        })
    }
}

/// Phase-A narrow link metadata visible from the lock plus tool manifest.
/// The leaf manifest and sources need the installed leaf package and are
/// verified separately at prepare time; revocation only needs this much
/// because it tombstones a graph without granting execution.
pub(crate) struct ToolLibraryLinkMeta {
    pub alias: String,
    pub leaf_id: String,
    pub leaf_artifact: String,
}

/// Phase-A shape gate: exactly one AcceptedPublisher stateless read-only tool
/// plus one leaf library joined by a single `library`-relation edge. Anything
/// else returns `None` so the legacy edgeless or plugin-edge paths keep their
/// previous behavior; `None` here never widens an edge into a call.
pub(crate) fn tool_library_topology(
    lock: &GraphLock,
    tool: &InstalledPackage,
) -> Option<ToolLibraryLinkMeta> {
    use super::resolve::HarnessSelection;
    let HarnessSelection::ToolOnly { tool_package } = &lock.harness_selection else {
        return None;
    };
    if tool_package != &tool.manifest.id {
        return None;
    }
    if lock.packages.len() != 2 || lock.edges.len() != 1 || lock.closure.len() != 2 {
        return None;
    }
    let edge = &lock.edges[0];
    if edge.from != tool.manifest.id
        || edge.from_entry != tool.manifest.entry.export
        || edge.relation != "library"
        || !edge.bindings.is_empty()
    {
        return None;
    }
    if !is_tool_role(tool)
        || tool.trust != PackageTrust::AcceptedPublisher
        || tool.manifest.state.is_some()
    {
        return None;
    }
    if tool.manifest.dependencies.len() != 1 {
        return None;
    }
    let dependency = &tool.manifest.dependencies[0];
    if dependency.alias != edge.alias
        || dependency.id != edge.to
        || dependency.version != edge.version_requirement
    {
        return None;
    }
    let leaf = lock.packages.iter().find(|package| package.id == edge.to)?;
    if leaf.kind != "library"
        || edge.to_version != leaf.version
        || edge.to_artifact_id != leaf.artifact_id
    {
        return None;
    }
    // The public read-only surface is fixed: one read effect on the tool
    // entry, nothing delegated, no state, and the workspace.read capability.
    if tool.manifest.capabilities != ["workspace.read".to_string()] {
        return None;
    }
    let entry_effects = tool
        .manifest
        .effects
        .entries
        .get(&tool.manifest.entry.export)?;
    if entry_effects.direct.len() != 1 || !entry_effects.delegated.is_empty() {
        return None;
    }
    let declared = &entry_effects.direct[0];
    if declared.kind != "workspace.fs.read"
        || declared.scope != "bound_workspace"
        || declared.recovery != "none"
    {
        return None;
    }
    if tool.manifest.effects.entries.iter().any(|(name, effects)| {
        name != &tool.manifest.entry.export
            && (!effects.direct.is_empty() || !effects.delegated.is_empty())
    }) {
        return None;
    }
    let tool_closure = lock.closure.iter().find(|item| {
        item.package == tool.manifest.id && item.entry == tool.manifest.entry.export
    })?;
    if tool_closure.effects.len() != 1 {
        return None;
    }
    let locked = &tool_closure.effects[0];
    if locked.kind != "workspace.fs.read"
        || locked.scope != "bound_workspace"
        || locked.recovery != "none"
        || locked.via.relation != "direct"
        || locked.via.caller_package != tool.manifest.id
        || locked.via.caller_entry != tool.manifest.entry.export
        || !locked.via.alias.is_empty()
        || locked.via.callee_package != tool.manifest.id
        || locked.via.callee_entry != tool.manifest.entry.export
    {
        return None;
    }
    let leaf_closure = lock
        .closure
        .iter()
        .find(|item| item.package == leaf.id && item.entry == edge.to_entry)?;
    if !leaf_closure.effects.is_empty() {
        return None;
    }
    // The alias becomes the single-file module `<alias>.rss` in the memory
    // compile view. It must be a valid module name and must shadow neither a
    // host namespace nor one of the tool's own local modules.
    if !crate::runtime::closed_bundle::valid_module_identifier(&dependency.alias) {
        return None;
    }
    if host_roots().contains(&dependency.alias) {
        return None;
    }
    for path in tool.sources.keys() {
        let first = path.split('/').next().unwrap_or("");
        let stem = first.strip_suffix(".rss").unwrap_or(first);
        if stem == dependency.alias {
            return None;
        }
    }
    Some(ToolLibraryLinkMeta {
        alias: dependency.alias.clone(),
        leaf_id: leaf.id.clone(),
        leaf_artifact: leaf.artifact_id.clone(),
    })
}

/// The verified phase-A link: the tool keeps its Native effects, the leaf
/// only formats strings, and the alias maps to `<alias>.rss` in the memory
/// compile view. Captured bytes are never rewritten; the mapping lives only
/// in this compilation.
struct ToolLibraryLink<'a> {
    tool: &'a InstalledPackage,
    leaf: &'a InstalledPackage,
    alias: String,
}

/// Resolve the full phase-A link from the verified capture, including the
/// leaf manifest and source-file facts that the lock alone cannot carry.
/// `None` falls back to the legacy paths; it never widens an edge.
fn tool_library_link<'a>(
    lock: &GraphLock,
    selected: &[&'a InstalledPackage],
) -> Option<ToolLibraryLink<'a>> {
    let super::resolve::HarnessSelection::ToolOnly { tool_package } = &lock.harness_selection
    else {
        return None;
    };
    let tool = selected
        .iter()
        .copied()
        .find(|package| package.manifest.id == *tool_package)?;
    let meta = tool_library_topology(lock, tool)?;
    let leaf = selected
        .iter()
        .copied()
        .find(|package| package.manifest.id == meta.leaf_id)?;
    if leaf.artifact_id != meta.leaf_artifact {
        return None;
    }
    if leaf.manifest.kind != "library"
        || leaf.manifest.contract != "agent.library/v1"
        || leaf.trust != PackageTrust::AcceptedPublisher
        || leaf.manifest.state.is_some()
        || !leaf.manifest.dependencies.is_empty()
        || !leaf.manifest.capabilities.is_empty()
    {
        return None;
    }
    if leaf
        .manifest
        .effects
        .entries
        .values()
        .any(|entry| !entry.direct.is_empty() || !entry.delegated.is_empty())
    {
        return None;
    }
    if !leaf
        .manifest
        .effects
        .entries
        .contains_key(&leaf.manifest.entry.export)
    {
        return None;
    }
    if leaf.sources.len() != 1 || !leaf.sources.contains_key(&leaf.manifest.entry.path) {
        return None;
    }
    Some(ToolLibraryLink {
        tool,
        leaf,
        alias: meta.alias,
    })
}

/// The structural skeleton: ToolOnly plus two packages joined by one
/// `library`-relation edge. No manifest judgment here; that is the precise
/// diagnosis below.
struct LibrarySkeleton<'a> {
    tool: &'a InstalledPackage,
    leaf: &'a InstalledPackage,
}

fn library_skeleton<'a>(
    lock: &GraphLock,
    selected: &[&'a InstalledPackage],
) -> Option<LibrarySkeleton<'a>> {
    let super::resolve::HarnessSelection::ToolOnly { tool_package } = &lock.harness_selection
    else {
        return None;
    };
    if lock.packages.len() != 2 || lock.edges.len() != 1 {
        return None;
    }
    let edge = &lock.edges[0];
    if edge.relation != "library" || edge.from != *tool_package {
        return None;
    }
    let tool = selected
        .iter()
        .copied()
        .find(|package| package.manifest.id == *tool_package)?;
    let leaf = selected
        .iter()
        .copied()
        .find(|package| package.manifest.id == edge.to)?;
    Some(LibrarySkeleton { tool, leaf })
}

/// Precise rejection for a library skeleton that misses the narrow shape.
/// Only used when the tool actually imports the alias; disconnected graphs
/// keep their legacy behavior. Forgery and revision checks come first, then
/// the tool surface, the lock closure, the alias mapping, and the leaf
/// manifest. Leaf *source* impurity is diagnosed separately on the linked
/// path, where the leaf manifest is already clean.
fn diagnose_library_link(lock: &GraphLock, skeleton: &LibrarySkeleton<'_>) -> PluginError {
    let tool = skeleton.tool;
    let leaf = skeleton.leaf;
    let shape = |item: String| PluginError::new(PluginErrorKind::ContractIncompatible, item);
    let Some(edge) = lock.edges.first() else {
        return shape(format!("{} library_shape", tool.manifest.id));
    };
    if edge.from_entry != tool.manifest.entry.export {
        return shape(format!("{} library_edge_entry", tool.manifest.id));
    }
    if !edge.bindings.is_empty() {
        return shape(format!("{} library_edge_bindings", tool.manifest.id));
    }
    if !is_tool_role(tool)
        || tool.trust != PackageTrust::AcceptedPublisher
        || tool.manifest.state.is_some()
    {
        return shape(format!("{} library_tool_shape", tool.manifest.id));
    }
    if tool.manifest.dependencies.len() != 1 {
        return shape(format!("{} library_tool_shape", tool.manifest.id));
    }
    let dependency = &tool.manifest.dependencies[0];
    if dependency.alias != edge.alias
        || dependency.id != edge.to
        || dependency.version != edge.version_requirement
    {
        return shape(format!("{} library_edge_mismatch", tool.manifest.id));
    }
    let locked_leaf = lock.packages.iter().find(|package| package.id == edge.to);
    let Some(locked_leaf) = locked_leaf else {
        return shape(format!("{} library_leaf_revision", tool.manifest.id));
    };
    if locked_leaf.kind != "library"
        || edge.to_version != locked_leaf.version
        || edge.to_artifact_id != locked_leaf.artifact_id
    {
        return shape(format!("{} library_leaf_revision", tool.manifest.id));
    }
    if tool.manifest.capabilities != ["workspace.read".to_string()] {
        return shape(format!("{} library_tool_capabilities", tool.manifest.id));
    }
    let entry_effects = tool
        .manifest
        .effects
        .entries
        .get(&tool.manifest.entry.export);
    let Some(entry_effects) = entry_effects else {
        return shape(format!("{} library_tool_effects", tool.manifest.id));
    };
    if entry_effects.direct.len() != 1 || !entry_effects.delegated.is_empty() {
        return shape(format!("{} library_tool_effects", tool.manifest.id));
    }
    let declared = &entry_effects.direct[0];
    if declared.kind != "workspace.fs.read"
        || declared.scope != "bound_workspace"
        || declared.recovery != "none"
    {
        return shape(format!("{} library_tool_effects", tool.manifest.id));
    }
    if tool.manifest.effects.entries.iter().any(|(name, effects)| {
        name != &tool.manifest.entry.export
            && (!effects.direct.is_empty() || !effects.delegated.is_empty())
    }) {
        return shape(format!("{} library_tool_effects", tool.manifest.id));
    }
    if lock.closure.len() != 2 {
        return shape(format!("{} library_closure", tool.manifest.id));
    }
    let tool_closure = lock
        .closure
        .iter()
        .find(|item| item.package == tool.manifest.id && item.entry == tool.manifest.entry.export);
    let Some(tool_closure) = tool_closure else {
        return shape(format!("{} library_closure", tool.manifest.id));
    };
    if tool_closure.effects.len() != 1 {
        return shape(format!("{} library_closure", tool.manifest.id));
    }
    let locked = &tool_closure.effects[0];
    if locked.kind != "workspace.fs.read"
        || locked.scope != "bound_workspace"
        || locked.recovery != "none"
        || locked.via.relation != "direct"
        || locked.via.caller_package != tool.manifest.id
        || locked.via.caller_entry != tool.manifest.entry.export
        || !locked.via.alias.is_empty()
        || locked.via.callee_package != tool.manifest.id
        || locked.via.callee_entry != tool.manifest.entry.export
    {
        return shape(format!("{} library_closure", tool.manifest.id));
    }
    let leaf_closure = lock
        .closure
        .iter()
        .find(|item| item.package == locked_leaf.id && item.entry == edge.to_entry);
    let Some(leaf_closure) = leaf_closure else {
        return shape(format!("{} library_closure", tool.manifest.id));
    };
    if !leaf_closure.effects.is_empty() {
        return shape(format!("{} library_leaf_effects", tool.manifest.id));
    }
    if !crate::runtime::closed_bundle::valid_module_identifier(&dependency.alias)
        || host_roots().contains(&dependency.alias)
    {
        return shape(format!("{} library_alias", tool.manifest.id));
    }
    for path in tool.sources.keys() {
        let first = path.split('/').next().unwrap_or("");
        let stem = first.strip_suffix(".rss").unwrap_or(first);
        if stem == dependency.alias {
            return shape(format!("{} library_alias", tool.manifest.id));
        }
    }
    if leaf.manifest.kind != "library"
        || leaf.manifest.contract != "agent.library/v1"
        || leaf.trust != PackageTrust::AcceptedPublisher
        || leaf.manifest.state.is_some()
        || !leaf.manifest.dependencies.is_empty()
        || !leaf.manifest.capabilities.is_empty()
    {
        return shape(format!("{} library_leaf_manifest", leaf.manifest.id));
    }
    if leaf
        .manifest
        .effects
        .entries
        .values()
        .any(|entry| !entry.direct.is_empty() || !entry.delegated.is_empty())
        || !leaf
            .manifest
            .effects
            .entries
            .contains_key(&leaf.manifest.entry.export)
    {
        return shape(format!("{} library_leaf_effects", leaf.manifest.id));
    }
    if leaf.sources.len() != 1 || !leaf.sources.contains_key(&leaf.manifest.entry.path) {
        return shape(format!("{} library_leaf_sources", leaf.manifest.id));
    }
    shape(format!("{} library_shape", tool.manifest.id))
}

#[derive(Clone)]
pub struct PreparedGraph {
    sources: BTreeMap<(String, String), Vec<u8>>,
    pub(crate) harness_selection: super::resolve::HarnessSelection,
    callables: BTreeMap<String, String>,
    exports: BTreeMap<String, String>,
    trust: BTreeMap<String, PackageTrust>,
    managed_contracts: BTreeMap<String, crate::effects::broker::ManagedEntryContract>,
    managed_policy_catalogs:
        BTreeMap<String, Arc<crate::effects::authority::ManagedToolPolicyCatalog>>,
    state_migrations: BTreeMap<String, Arc<crate::plugins::state::PluginStateMigrationProgram>>,
    state_declarations: BTreeMap<String, crate::plugins::manifest::StateDeclaration>,
    programs: BTreeMap<String, Arc<rustscript_vm::Program>>,
    // Prepared with the captured code, never with a run or capability owner.
    registries: BTreeMap<String, Result<Arc<rustscript_vm::HostFunctionRegistry>, String>>,
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

    pub(crate) fn managed_contract(
        &self,
        package_id: &str,
    ) -> Option<crate::effects::broker::ManagedEntryContract> {
        self.managed_contracts.get(package_id).cloned()
    }

    pub(crate) fn managed_policy_catalog(
        &self,
        package_id: &str,
    ) -> Option<Arc<crate::effects::authority::ManagedToolPolicyCatalog>> {
        self.managed_policy_catalogs.get(package_id).cloned()
    }

    /// Code-scoped import binding only; no run, owner, token or grant is retained.
    pub(crate) fn registry(
        &self,
        package_id: &str,
    ) -> Option<Result<Arc<rustscript_vm::HostFunctionRegistry>, String>> {
        self.registries.get(package_id).cloned()
    }

    /// Callable program compiled from the captured bytes. The graph id is not
    /// a substitute for this program.
    pub fn program(&self, package_id: &str) -> Option<Arc<rustscript_vm::Program>> {
        self.programs.get(package_id).cloned()
    }

    /// Compiled pure migration entry for a stateful package, if declared.
    pub fn state_migration(
        &self,
        package_id: &str,
    ) -> Option<Arc<crate::plugins::state::PluginStateMigrationProgram>> {
        self.state_migrations.get(package_id).cloned()
    }

    pub(crate) fn state_declaration(
        &self,
        package_id: &str,
    ) -> Option<crate::plugins::manifest::StateDeclaration> {
        self.state_declarations.get(package_id).cloned()
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
        self.prepare_inner(lock, None)
    }
    pub(crate) fn prepare_harness_graph(
        &self,
        lock: &GraphLock,
        cancel: &crate::RunCancellation,
    ) -> Result<PreparedGraph, PluginError> {
        self.prepare_inner(lock, Some(cancel))
    }
    fn prepare_inner(
        &self,
        lock: &GraphLock,
        cancel: Option<&crate::RunCancellation>,
    ) -> Result<PreparedGraph, PluginError> {
        check_cancel(cancel)?;
        if cancel.is_none()
            && matches!(
                lock.harness_selection,
                super::HarnessSelection::ContextPrompt { .. }
            )
        {
            return Err(PluginError::new(
                PluginErrorKind::CompileFailed,
                "deadline_elapsed",
            ));
        }
        lock.validate_persisted()?;
        if cancel.is_some() {
            for package in &lock.packages {
                self.read_installed(&package.artifact_id).map_err(|_| {
                    PluginError::new(
                        PluginErrorKind::MissingDependency,
                        "plugin_artifact_unavailable",
                    )
                })?;
            }
        }
        check_cancel(cancel)?;
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
        // Phase-A narrow link, resolved once from the verified capture. `None`
        // keeps every legacy path identical; `Some` only admits the exact
        // single-tool plus pure-leaf shape.
        let link = tool_library_link(lock, &selected);
        // A library skeleton that misses the narrow shape keeps the legacy
        // disconnected behavior unless the tool actually imports the alias.
        // The precise shape error then replaces the generic bypass at the
        // import site; leaf source impurity is diagnosed on the linked path.
        let skeleton = library_skeleton(lock, &selected);
        let link_error = if link.is_none() {
            skeleton
                .as_ref()
                .map(|shape| diagnose_library_link(lock, shape))
        } else {
            None
        };
        // A host-namespace alias would shadow the host in every combined
        // view, and the duplicate import may not even parse for the scan to
        // see. Reject it before scanning; disconnected graphs with sane
        // aliases keep their legacy behavior.
        if link.is_none()
            && let Some(shape) = skeleton.as_ref()
            && lock
                .edges
                .first()
                .is_some_and(|edge| host_roots().contains(&edge.alias))
        {
            return Err(diagnose_library_link(lock, shape));
        }
        let request = match &lock.harness_selection {
            super::resolve::HarnessSelection::Unselected => {
                super::resolve::HarnessSelectionRequest::Unselected
            }
            super::resolve::HarnessSelection::ToolOnly { tool_package } => {
                super::resolve::HarnessSelectionRequest::ToolOnly {
                    tool_package: tool_package.clone(),
                }
            }
            super::resolve::HarnessSelection::ContextPrompt {
                tool_package,
                policy,
            } => super::resolve::HarnessSelectionRequest::ContextPrompt {
                tool_package: tool_package.clone(),
                policy_package: policy.package_id.clone(),
                prompt_export: policy.prompt_export.clone(),
                context_export: policy.context_export.clone(),
                guardian_export: policy.guardian_export.clone(),
            },
        };
        let actual = selected
            .iter()
            .map(|p| (p.manifest.id.clone(), *p))
            .collect();
        if super::resolve::select_harness(&actual, &request)? != lock.harness_selection {
            return Err(PluginError::new(
                PluginErrorKind::ContractIncompatible,
                "harness_policy_selection_invalid",
            ));
        }
        for package in &selected {
            let pure = matches!(&lock.harness_selection,super::HarnessSelection::ContextPrompt{policy,..} if policy.package_id==package.manifest.id);
            let allowed_library_alias = link.as_ref().and_then(|linked| {
                (linked.tool.manifest.id == package.manifest.id).then_some(linked.alias.as_str())
            });
            scan_package(
                package,
                &selected,
                pure,
                allowed_library_alias,
                link_error.as_ref(),
            )
            .map_err(|error| {
                if pure {
                    PluginError::new(error.kind, "harness_policy_not_pure")
                } else {
                    error
                }
            })?;
        }
        if let Some(linked) = link.as_ref() {
            scan_pure_library_source(linked.leaf, &linked.alias)?;
            check_library_string_interface(linked.leaf)?;
        }
        let mut prepared = PreparedGraph {
            sources: BTreeMap::new(),
            harness_selection: lock.harness_selection.clone(),
            callables: BTreeMap::new(),
            exports: BTreeMap::new(),
            trust: BTreeMap::new(),
            managed_contracts: BTreeMap::new(),
            managed_policy_catalogs: BTreeMap::new(),
            state_migrations: BTreeMap::new(),
            state_declarations: BTreeMap::new(),
            programs: BTreeMap::new(),
            registries: BTreeMap::new(),
        };
        for package in &selected {
            if package.trust == PackageTrust::EmbeddingOwnedBuiltin {
                let catalog = capture_managed_policy_catalog_inner(package, lock, cancel)?;
                prepared
                    .managed_policy_catalogs
                    .insert(package.manifest.id.clone(), catalog);
            } else if let Some(catalog) = capture_signed_stateless_catalog(package, lock, cancel)? {
                prepared
                    .managed_policy_catalogs
                    .insert(package.manifest.id.clone(), catalog);
            } else if let Some(linked) = link
                .as_ref()
                .filter(|linked| linked.tool.manifest.id == package.manifest.id)
                && let Some(catalog) =
                    capture_signed_tool_library_catalog(package, linked.leaf, lock, cancel)?
            {
                prepared
                    .managed_policy_catalogs
                    .insert(package.manifest.id.clone(), catalog);
            }
            let effects = lock
                .closure
                .iter()
                .find(|item| {
                    item.package == package.manifest.id
                        && item.entry == package.manifest.entry.export
                })
                .map(|entry| {
                    entry
                        .effects
                        .iter()
                        .map(|effect| crate::effects::broker::ManagedEffectRequirement {
                            kind: effect.kind.clone(),
                            scope: effect.scope.clone(),
                            recovery: effect.recovery.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            prepared.managed_contracts.insert(
                package.manifest.id.clone(),
                crate::effects::broker::ManagedEntryContract {
                    trust: package.trust,
                    effects,
                    topology: match link.as_ref() {
                        Some(linked) if linked.tool.manifest.id == package.manifest.id => {
                            SupportedManagedTopology::validate(lock, package)
                        }
                        _ if package.manifest.dependencies.is_empty() && lock.edges.is_empty() => {
                            SupportedManagedTopology::validate(lock, package)
                        }
                        _ => None,
                    },
                },
            );
            for (path, bytes) in &package.sources {
                prepared
                    .sources
                    .insert((package.manifest.id.clone(), path.clone()), bytes.clone());
            }
            prepared
                .trust
                .insert(package.manifest.id.clone(), package.trust);
            if let Some(migration) = capture_state_migration_program(package, lock, cancel)? {
                prepared
                    .state_migrations
                    .insert(package.manifest.id.clone(), migration);
            }
            if let Some(state) = package.manifest.state.as_ref() {
                prepared
                    .state_declarations
                    .insert(package.manifest.id.clone(), state.clone());
            }
            prepared.exports.insert(
                package.manifest.id.clone(),
                package.manifest.entry.export.clone(),
            );
            check_cancel(cancel)?;
            let (callable, program) = match link.as_ref() {
                Some(linked) if linked.tool.manifest.id == package.manifest.id => {
                    compile_tool_with_library(linked.tool, linked.leaf, &linked.alias)?
                }
                Some(linked) if linked.leaf.manifest.id == package.manifest.id => {
                    let (callable, program) = compile_leaf_package(linked.leaf)?;
                    for import in &program.imports {
                        if !is_pure(&import.name) {
                            return Err(PluginError::new(
                                PluginErrorKind::UnauthorizedHostImport,
                                import.name.clone(),
                            ));
                        }
                    }
                    (callable, program)
                }
                _ => compile_package(package)?,
            };
            check_cancel(cancel)?;
            let imports: Vec<_> = program
                .imports
                .iter()
                .map(|import| import.name.clone())
                .collect();
            // Retain preparation errors for the same invocation-time failure boundary.
            let registry = crate::runtime::rss_runner::build_pinned_registry(&imports)
                .map(Arc::new)
                .map_err(|error| error.to_string());
            prepared
                .registries
                .insert(package.manifest.id.clone(), registry);
            prepared
                .callables
                .insert(package.manifest.id.clone(), callable);
            prepared
                .programs
                .insert(package.manifest.id.clone(), program);
        }
        check_cancel(cancel)?;
        *self
            .prepared
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some((lock.clone(), prepared.clone()));
        Ok(prepared)
    }
}

fn check_cancel(cancel: Option<&crate::RunCancellation>) -> Result<(), PluginError> {
    if let Some(cancel) = cancel {
        cancel
            .ensure_open()
            .map_err(|e| PluginError::new(PluginErrorKind::CompileFailed, e))?;
    }
    Ok(())
}

#[cfg(test)]
fn capture_managed_policy_catalog(
    package: &InstalledPackage,
    lock: &GraphLock,
) -> Result<Arc<crate::effects::authority::ManagedToolPolicyCatalog>, PluginError> {
    capture_managed_policy_catalog_inner(package, lock, None)
}

fn capture_managed_policy_catalog_inner(
    package: &InstalledPackage,
    lock: &GraphLock,
    cancel: Option<&crate::RunCancellation>,
) -> Result<Arc<crate::effects::authority::ManagedToolPolicyCatalog>, PluginError> {
    check_cancel(cancel)?;
    let invalid = || {
        PluginError::new(
            PluginErrorKind::ContractIncompatible,
            "managed captured catalog",
        )
    };
    if package.trust != PackageTrust::EmbeddingOwnedBuiltin
        || !is_tool_role(package)
        || package.manifest.id != crate::runtime::native_tools::EMBEDDING_PACKAGE_ID
        || !matches!(lock.packages.len(), 1 | 2)
        || !lock.edges.is_empty()
        || !package.manifest.dependencies.is_empty()
        || package.manifest.effects.entries.len() != 1
        || package
            .manifest
            .effects
            .entries
            .get(&package.manifest.entry.export)
            .is_none_or(|entry| !entry.delegated.is_empty())
    {
        return Err(invalid());
    }
    let rebuilt = super::resolve::resolve_installed(
        std::slice::from_ref(package),
        &super::resolve::ResolveRequest {
            roots: vec![super::resolve::PackageRequirement {
                id: package.manifest.id.clone(),
                version: package.manifest.version.clone(),
            }],
            host_runtime: lock.host_runtime.clone(),
            harness_selection: super::resolve::HarnessSelectionRequest::ToolOnly {
                tool_package: package.manifest.id.clone(),
            },
        },
    )?;
    if rebuilt.packages
        != lock
            .packages
            .iter()
            .filter(|p| p.id == package.manifest.id)
            .cloned()
            .collect::<Vec<_>>()
        || rebuilt.closure
            != lock
                .closure
                .iter()
                .filter(|e| e.package == package.manifest.id)
                .cloned()
                .collect::<Vec<_>>()
    {
        return Err(invalid());
    }
    let sources: Vec<_> = package
        .sources
        .iter()
        .map(|(key, bytes)| {
            std::str::from_utf8(bytes)
                .map(|text| (key.as_str(), text))
                .map_err(|_| invalid())
        })
        .collect::<Result<_, _>>()?;
    let compiled = closed_bundle::compile_bundled_closed_bundle(
        "rss/tools/types.rss",
        &sources,
        ClosedBundleOptions {
            limits: ClosedBundleLimits {
                max_files: 64,
                max_depth: 16,
                max_file_bytes: 1024 * 1024,
                max_total_bytes: 8 * 1024 * 1024,
            },
            virtual_root: Path::new(VIRTUAL_ROOT),
            host_roots: &host_roots(),
            catalog: agent_host_catalog(),
            dialect: snapshot_parser_dialect(),
            entry_export: "managed_authority_catalog",
        },
    )
    .map_err(|_| invalid())?;
    let entry = compiled.entry_name.ok_or_else(invalid)?;
    check_cancel(cancel)?;
    let program = Arc::new(compiled.program);
    if let Some(cancel) = cancel {
        cancel
            .ensure_open()
            .map_err(|e| PluginError::new(PluginErrorKind::CompileFailed, e))?;
    }
    let value =
        crate::runtime::rss_runner::eval_captured_pure_export(program, &entry).map_err(|e| {
            if cancel.is_some() {
                PluginError::new(PluginErrorKind::CompileFailed, e)
            } else {
                invalid()
            }
        })?;
    if let Some(cancel) = cancel {
        cancel
            .ensure_open()
            .map_err(|e| PluginError::new(PluginErrorKind::CompileFailed, e))?;
    }
    crate::effects::authority::ManagedToolPolicyCatalog::from_captured_value(
        &package.manifest.id,
        &package.artifact_id,
        &package.manifest.entry.export,
        &value,
    )
    .map_err(|_| invalid())
}

const MANAGED_CATALOG_EXPORT: &str = "managed_authority_catalog";

fn signed_stateless_tool_only(lock: &GraphLock, package: &InstalledPackage) -> bool {
    use super::resolve::HarnessSelection;

    package.trust == PackageTrust::AcceptedPublisher
        && is_tool_role(package)
        && package.manifest.dependencies.is_empty()
        && lock.edges.is_empty()
        && lock.packages.len() == 1
        && lock
            .closure
            .iter()
            .all(|item| item.package == package.manifest.id)
        && lock
            .closure
            .iter()
            .filter(|item| item.entry == package.manifest.entry.export)
            .count()
            == 1
        && lock
            .closure
            .iter()
            .filter(|item| item.entry != package.manifest.entry.export)
            .all(|item| item.effects.is_empty())
        && matches!(
            &lock.harness_selection,
            HarnessSelection::ToolOnly { tool_package } if tool_package == &package.manifest.id
        )
        && !package.manifest.effects.entries.is_empty()
        && package
            .manifest
            .effects
            .entries
            .iter()
            .all(|(entry, effects)| {
                effects.delegated.is_empty()
                    && (entry == &package.manifest.entry.export
                        || (effects.direct.is_empty() && effects.delegated.is_empty()))
            })
        && package
            .manifest
            .effects
            .entries
            .contains_key(&package.manifest.entry.export)
}

fn catalog_export_paths(package: &InstalledPackage) -> Vec<String> {
    export_paths(package, MANAGED_CATALOG_EXPORT)
}

fn export_paths(package: &InstalledPackage, export_name: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (path, bytes) in &package.sources {
        let Ok(text) = std::str::from_utf8(bytes) else {
            continue;
        };
        let scanned = format!("{}{text}", catalog_prelude());
        let Ok(ir) = parse_source_with_dialect(
            &scanned,
            snapshot_parser_dialect(),
            SharedParserOptions {
                source_id: 0,
                allow_implicit_externs: true,
                allow_implicit_semicolons: false,
                enforce_mutable_bindings: false,
                import_scan_mode: true,
            },
        ) else {
            continue;
        };
        if ir
            .functions
            .iter()
            .any(|function| function.exported && function.name == export_name)
        {
            found.push(path.clone());
        }
    }
    found.sort();
    found
}

fn capture_signed_stateless_catalog(
    package: &InstalledPackage,
    lock: &GraphLock,
    cancel: Option<&crate::RunCancellation>,
) -> Result<Option<Arc<crate::effects::authority::ManagedToolPolicyCatalog>>, PluginError> {
    if !signed_stateless_tool_only(lock, package) {
        return Ok(None);
    }
    let invalid = || {
        PluginError::new(
            PluginErrorKind::ContractIncompatible,
            "managed captured catalog",
        )
    };
    let paths = catalog_export_paths(package);
    let entry_path = match paths.len() {
        0 => return Ok(None),
        1 => paths[0].clone(),
        _ => return Err(invalid()),
    };
    check_cancel(cancel)?;
    let rebuilt = super::resolve::resolve_installed(
        std::slice::from_ref(package),
        &super::resolve::ResolveRequest {
            roots: vec![super::resolve::PackageRequirement {
                id: package.manifest.id.clone(),
                version: package.manifest.version.clone(),
            }],
            host_runtime: lock.host_runtime.clone(),
            harness_selection: super::resolve::HarnessSelectionRequest::ToolOnly {
                tool_package: package.manifest.id.clone(),
            },
        },
    )?;
    if rebuilt.packages
        != lock
            .packages
            .iter()
            .filter(|item| item.id == package.manifest.id)
            .cloned()
            .collect::<Vec<_>>()
        || rebuilt.closure
            != lock
                .closure
                .iter()
                .filter(|item| item.package == package.manifest.id)
                .cloned()
                .collect::<Vec<_>>()
    {
        return Err(invalid());
    }
    let sources: Vec<_> = package
        .sources
        .iter()
        .map(|(key, bytes)| {
            std::str::from_utf8(bytes)
                .map(|text| (key.as_str(), text))
                .map_err(|_| invalid())
        })
        .collect::<Result<_, _>>()?;
    let value = eval_tool_catalog_value(&sources, &entry_path, cancel)?;
    if let Some(cancel) = cancel {
        cancel
            .ensure_open()
            .map_err(|e| PluginError::new(PluginErrorKind::CompileFailed, e))?;
    }
    crate::effects::authority::ManagedToolPolicyCatalog::from_captured_value(
        &package.manifest.id,
        &package.artifact_id,
        &package.manifest.entry.export,
        &value,
    )
    .map(Some)
    .map_err(|_| invalid())
}

/// Signed catalog capture for the phase-A tool plus pure-leaf graph. The
/// whole two-package lock (packages, edges, closure, harness selection) is
/// rebuilt and compared; the catalog value itself still comes from the tool's
/// own catalog export alone, which must not reach into the leaf.
fn capture_signed_tool_library_catalog(
    tool: &InstalledPackage,
    leaf: &InstalledPackage,
    lock: &GraphLock,
    cancel: Option<&crate::RunCancellation>,
) -> Result<Option<Arc<crate::effects::authority::ManagedToolPolicyCatalog>>, PluginError> {
    let invalid = || {
        PluginError::new(
            PluginErrorKind::ContractIncompatible,
            "managed captured catalog",
        )
    };
    let meta = tool_library_topology(lock, tool).ok_or_else(invalid)?;
    if meta.leaf_id != leaf.manifest.id || meta.leaf_artifact != leaf.artifact_id {
        return Err(invalid());
    }
    // A verified tool plus leaf link is fully lock-checked even when the tool
    // ships no catalog export: the optional catalog lookup must not precede
    // the rebuild, or a forged lock would be accepted without a catalog.
    check_cancel(cancel)?;
    let rebuilt = super::resolve::resolve_installed(
        &[tool.clone(), leaf.clone()],
        &super::resolve::ResolveRequest {
            roots: vec![super::resolve::PackageRequirement {
                id: tool.manifest.id.clone(),
                version: tool.manifest.version.clone(),
            }],
            host_runtime: lock.host_runtime.clone(),
            harness_selection: super::resolve::HarnessSelectionRequest::ToolOnly {
                tool_package: tool.manifest.id.clone(),
            },
        },
    )?;
    if rebuilt.packages != lock.packages
        || rebuilt.edges != lock.edges
        || rebuilt.closure != lock.closure
        || rebuilt.harness_selection != lock.harness_selection
    {
        return Err(invalid());
    }
    let paths = catalog_export_paths(tool);
    let entry_path = match paths.len() {
        0 => return Ok(None),
        1 => paths[0].clone(),
        _ => return Err(invalid()),
    };
    let sources: Vec<_> = tool
        .sources
        .iter()
        .map(|(key, bytes)| {
            std::str::from_utf8(bytes)
                .map(|text| (key.as_str(), text))
                .map_err(|_| invalid())
        })
        .collect::<Result<_, _>>()?;
    let value = eval_tool_catalog_value(&sources, &entry_path, cancel)?;
    if let Some(cancel) = cancel {
        cancel
            .ensure_open()
            .map_err(|e| PluginError::new(PluginErrorKind::CompileFailed, e))?;
    }
    crate::effects::authority::ManagedToolPolicyCatalog::from_captured_value(
        &tool.manifest.id,
        &tool.artifact_id,
        &tool.manifest.entry.export,
        &value,
    )
    .map(Some)
    .map_err(|_| invalid())
}

/// Evaluate one tool-owned catalog export over that tool's captured sources
/// only. The leaf never participates: a catalog that reaches the alias fails
/// the closure selection instead of inheriting leaf code.
fn eval_tool_catalog_value(
    sources: &[(&str, &str)],
    entry_path: &str,
    cancel: Option<&crate::RunCancellation>,
) -> Result<rustscript_vm::Value, PluginError> {
    let invalid = || {
        PluginError::new(
            PluginErrorKind::ContractIncompatible,
            "managed captured catalog",
        )
    };
    let host_roots = host_roots();
    let selected = closed_bundle::select_catalog_closure(
        sources,
        agent_host_catalog().as_ref(),
        entry_path,
        &host_roots,
    )
    .map_err(|_| invalid())?;
    let sources: Vec<_> = sources
        .iter()
        .copied()
        .filter(|(path, _)| selected.iter().any(|item| item == path))
        .collect();
    let compiled = closed_bundle::compile_bundled_closed_bundle(
        entry_path,
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
            catalog: agent_host_catalog(),
            dialect: snapshot_parser_dialect(),
            entry_export: MANAGED_CATALOG_EXPORT,
        },
    )
    .map_err(|_| invalid())?;
    let entry = compiled.entry_name.ok_or_else(invalid)?;
    check_cancel(cancel)?;
    let program = Arc::new(compiled.program);
    if let Some(cancel) = cancel {
        cancel
            .ensure_open()
            .map_err(|e| PluginError::new(PluginErrorKind::CompileFailed, e))?;
    }
    crate::runtime::rss_runner::eval_captured_pure_export(program, &entry).map_err(|e| {
        if cancel.is_some() {
            PluginError::new(PluginErrorKind::CompileFailed, e)
        } else {
            invalid()
        }
    })
}

fn capture_state_migration_program(
    package: &InstalledPackage,
    lock: &GraphLock,
    cancel: Option<&crate::RunCancellation>,
) -> Result<Option<Arc<crate::plugins::state::PluginStateMigrationProgram>>, PluginError> {
    let Some(state) = package.manifest.state.as_ref() else {
        return Ok(None);
    };
    let Some(migration) = state.migration.as_ref() else {
        return Ok(None);
    };
    let entry_effects = package
        .manifest
        .effects
        .entries
        .get(&migration.entry)
        .ok_or_else(|| {
            PluginError::new(
                PluginErrorKind::ContractIncompatible,
                "plugin_state_migration_undeclared",
            )
        })?;
    if !entry_effects.direct.is_empty() || !entry_effects.delegated.is_empty() {
        return Err(PluginError::new(
            PluginErrorKind::ContractIncompatible,
            "plugin_state_migration_impure",
        ));
    }
    crate::plugins::validate_state_migration_source(package, &migration.entry)
        .map_err(|code| PluginError::new(PluginErrorKind::ContractIncompatible, code))?;
    check_cancel(cancel)?;
    let rebuilt = super::resolve::resolve_installed(
        std::slice::from_ref(package),
        &super::resolve::ResolveRequest {
            roots: vec![super::resolve::PackageRequirement {
                id: package.manifest.id.clone(),
                version: package.manifest.version.clone(),
            }],
            host_runtime: lock.host_runtime.clone(),
            harness_selection: super::resolve::HarnessSelectionRequest::ToolOnly {
                tool_package: package.manifest.id.clone(),
            },
        },
    )?;
    if rebuilt.packages
        != lock
            .packages
            .iter()
            .filter(|item| item.id == package.manifest.id)
            .cloned()
            .collect::<Vec<_>>()
        || rebuilt.closure
            != lock
                .closure
                .iter()
                .filter(|item| item.package == package.manifest.id)
                .cloned()
                .collect::<Vec<_>>()
    {
        return Err(PluginError::new(
            PluginErrorKind::ContractIncompatible,
            "plugin_state_migration_graph_mismatch",
        ));
    }
    let paths = export_paths(package, &migration.entry);
    let entry_path = match paths.len() {
        0 => {
            return Err(PluginError::new(
                PluginErrorKind::ContractIncompatible,
                "plugin_state_migration_missing",
            ));
        }
        1 => paths[0].clone(),
        _ => {
            return Err(PluginError::new(
                PluginErrorKind::ContractIncompatible,
                "plugin_state_migration_ambiguous",
            ));
        }
    };
    let sources: Vec<(&str, &str)> = package
        .sources
        .iter()
        .map(|(key, bytes)| {
            std::str::from_utf8(bytes)
                .map(|text| (key.as_str(), text))
                .map_err(|_| {
                    PluginError::new(
                        PluginErrorKind::ContractIncompatible,
                        "plugin_state_migration_source",
                    )
                })
        })
        .collect::<Result<_, _>>()?;
    let host_roots: BTreeSet<String> = BTreeSet::from(["json".to_string(), "bytes".to_string()]);
    let selected = closed_bundle::select_catalog_closure(
        &sources,
        agent_host_catalog().as_ref(),
        &entry_path,
        &host_roots,
    )
    .map_err(|_| {
        PluginError::new(
            PluginErrorKind::UnauthorizedHostImport,
            "plugin_state_migration_impure",
        )
    })?;
    let selected_sources: Vec<(&str, &str)> = sources
        .into_iter()
        .filter(|(path, _)| selected.iter().any(|item| item == path))
        .collect();
    check_cancel(cancel)?;
    let compiled = closed_bundle::compile_bundled_closed_bundle(
        &entry_path,
        &selected_sources,
        ClosedBundleOptions {
            limits: ClosedBundleLimits {
                max_files: 64,
                max_depth: 16,
                max_file_bytes: 1024 * 1024,
                max_total_bytes: 8 * 1024 * 1024,
            },
            virtual_root: Path::new(VIRTUAL_ROOT),
            host_roots: &host_roots,
            catalog: agent_host_catalog(),
            dialect: snapshot_parser_dialect(),
            entry_export: &migration.entry,
        },
    )
    .map_err(|_| {
        PluginError::new(
            PluginErrorKind::ContractIncompatible,
            "plugin_state_migration_compile_failed",
        )
    })?;
    let entry = compiled.entry_name.ok_or_else(|| {
        PluginError::new(
            PluginErrorKind::ContractIncompatible,
            "plugin_state_migration_missing",
        )
    })?;
    let program = Arc::new(compiled.program);
    if !program.imports.is_empty() {
        return Err(PluginError::new(
            PluginErrorKind::UnauthorizedHostImport,
            "plugin_state_migration_impure",
        ));
    }
    check_cancel(cancel)?;
    Ok(Some(Arc::new(
        crate::plugins::state::PluginStateMigrationProgram::new(
            program,
            entry,
            u32::try_from(state.schema).map_err(|_| {
                PluginError::new(PluginErrorKind::ContractIncompatible, "plugin_state_schema")
            })?,
        ),
    )))
}

fn scan_package(
    package: &InstalledPackage,
    selected: &[&InstalledPackage],
    pure: bool,
    allowed_library_alias: Option<&str>,
    library_error: Option<&PluginError>,
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
            if pure && !matches!(first.as_str(), "json" | "bytes") {
                let local = package.sources.keys().any(|path| {
                    path == &format!("{first}.rss") || path.starts_with(&format!("{first}/"))
                });
                if roots.contains(first) || !local {
                    return Err(PluginError::new(
                        PluginErrorKind::UnauthorizedHostImport,
                        "harness_policy_not_pure",
                    ));
                }
            }
            if aliases.contains(first.as_str()) {
                // The single verified library alias resolves inside the
                // combined memory compile view; every other dependency alias
                // stays a cross-package call behind the broker boundary. A
                // library skeleton that misses the narrow shape reports its
                // precise shape error at the import site instead.
                if allowed_library_alias != Some(first.as_str()) {
                    if let Some(error) = library_error {
                        return Err(error.clone());
                    }
                    return Err(PluginError::new(
                        PluginErrorKind::PluginBoundaryBypass,
                        format!("{} {first}", package.manifest.id),
                    ));
                }
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

fn scan_pure_library_source(leaf: &InstalledPackage, alias: &str) -> Result<(), PluginError> {
    // The leaf is one file with no caller. Only the pure `json`/`bytes`
    // namespaces may appear; a host namespace is an effect grab and any other
    // first segment smuggles a local or caller module into the leaf.
    let roots = host_roots();
    let prelude = catalog_prelude();
    for (path, bytes) in &leaf.sources {
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
            if first == "json" || first == "bytes" {
                continue;
            }
            if first == alias {
                return Err(PluginError::new(
                    PluginErrorKind::ContractIncompatible,
                    format!("{} {first}", leaf.manifest.id),
                ));
            }
            if roots.contains(first) {
                return Err(PluginError::new(
                    PluginErrorKind::UnauthorizedHostImport,
                    format!("{} {first}", leaf.manifest.id),
                ));
            }
            return Err(PluginError::new(
                PluginErrorKind::PluginBoundaryBypass,
                format!("{} {first}", leaf.manifest.id),
            ));
        }
    }
    Ok(())
}

fn check_library_string_interface(leaf: &InstalledPackage) -> Result<(), PluginError> {
    // Phase A moves only strings across the link. Every exported leaf
    // function must take strings and return a string; tokens, resources,
    // callbacks, maps, and handles have no representation here.
    let bytes = leaf.sources.get(&leaf.manifest.entry.path).ok_or_else(|| {
        PluginError::new(
            PluginErrorKind::ContractIncompatible,
            leaf.manifest.id.clone(),
        )
    })?;
    let source = std::str::from_utf8(bytes).map_err(|_| {
        PluginError::new(
            PluginErrorKind::CompileFailed,
            leaf.manifest.entry.path.clone(),
        )
    })?;
    let ir = parse_source_with_dialect(
        source,
        snapshot_parser_dialect(),
        SharedParserOptions {
            source_id: 0,
            allow_implicit_externs: true,
            allow_implicit_semicolons: false,
            enforce_mutable_bindings: false,
            import_scan_mode: false,
        },
    )
    .map_err(|_| PluginError::new(PluginErrorKind::CompileFailed, leaf.manifest.id.clone()))?;
    let mut saw_export = false;
    for function in &ir.functions {
        if !function.exported {
            continue;
        }
        let shape_ok = function.name == leaf.manifest.entry.export
            && function.return_schema == Some(rustscript_vm::TypeSchema::String)
            && function
                .arg_schemas
                .iter()
                .all(|schema| *schema == Some(rustscript_vm::TypeSchema::String));
        if !shape_ok {
            return Err(PluginError::new(
                PluginErrorKind::ContractIncompatible,
                format!("{} {}", leaf.manifest.id, function.name),
            ));
        }
        saw_export = true;
    }
    if !saw_export {
        return Err(PluginError::new(
            PluginErrorKind::UncoveredExport,
            leaf.manifest.entry.export.clone(),
        ));
    }
    Ok(())
}

fn compile_package(
    package: &InstalledPackage,
) -> Result<(String, Arc<rustscript_vm::Program>), PluginError> {
    compile_package_export(package, &package.manifest.entry.export)
}
fn compile_package_export(
    package: &InstalledPackage,
    export: &str,
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
            entry_export: export,
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

/// Compile the tool entry together with the single verified leaf. Both
/// packages share one closed-bundle budget; the leaf is mapped to
/// `<alias>.rss` in this memory view only, and the tool keeps its declared
/// Native effects. The combined program is charged against the tool manifest
/// because the leaf contributes no host imports of its own.
fn compile_tool_with_library(
    tool: &InstalledPackage,
    leaf: &InstalledPackage,
    alias: &str,
) -> Result<(String, Arc<rustscript_vm::Program>), PluginError> {
    let host_roots = host_roots();
    let catalog = agent_host_catalog();
    let mut owned: Vec<(String, String)> = tool
        .sources
        .iter()
        .filter_map(|(path, bytes)| {
            std::str::from_utf8(bytes).ok().map(|text| {
                let compiled_text = if path == &tool.manifest.entry.path {
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
    let leaf_path = format!("{alias}.rss");
    let leaf_bytes = leaf.sources.get(&leaf.manifest.entry.path).ok_or_else(|| {
        PluginError::new(
            PluginErrorKind::ContractIncompatible,
            leaf.manifest.id.clone(),
        )
    })?;
    let leaf_text = std::str::from_utf8(leaf_bytes).map_err(|_| {
        PluginError::new(
            PluginErrorKind::CompileFailed,
            leaf.manifest.entry.path.clone(),
        )
    })?;
    owned.push((leaf_path, leaf_text.to_string()));
    let sources: Vec<(&str, &str)> = owned
        .iter()
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let compiled = closed_bundle::compile_bundled_closed_bundle(
        &tool.manifest.entry.path,
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
            entry_export: &tool.manifest.entry.export,
        },
    )
    .map_err(|_| PluginError::new(PluginErrorKind::CompileFailed, tool.manifest.id.clone()))?;
    let entry = compiled.entry_name.ok_or_else(|| {
        PluginError::new(
            PluginErrorKind::UncoveredExport,
            tool.manifest.entry.export.clone(),
        )
    })?;
    charge_program(tool, &compiled.program)?;
    Ok((entry, Arc::new(compiled.program)))
}

/// Standalone purity proof for the leaf: compiled alone, with no caller
/// modules in the view, so a later combined run cannot gain caller host or
/// module reachability through it. Callers additionally require every program
/// import to be pure.
fn compile_leaf_package(
    leaf: &InstalledPackage,
) -> Result<(String, Arc<rustscript_vm::Program>), PluginError> {
    let host_roots = host_roots();
    let catalog = agent_host_catalog();
    let owned: Vec<(String, String)> = leaf
        .sources
        .iter()
        .filter_map(|(path, bytes)| {
            std::str::from_utf8(bytes)
                .ok()
                .map(|text| (path.clone(), text.to_string()))
        })
        .collect();
    if owned.len() != leaf.sources.len() {
        return Err(PluginError::new(
            PluginErrorKind::CompileFailed,
            leaf.manifest.id.clone(),
        ));
    }
    let sources: Vec<(&str, &str)> = owned
        .iter()
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let compiled = closed_bundle::compile_bundled_closed_bundle(
        &leaf.manifest.entry.path,
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
            entry_export: &leaf.manifest.entry.export,
        },
    )
    .map_err(|_| PluginError::new(PluginErrorKind::CompileFailed, leaf.manifest.id.clone()))?;
    let entry = compiled.entry_name.ok_or_else(|| {
        PluginError::new(
            PluginErrorKind::UncoveredExport,
            leaf.manifest.entry.export.clone(),
        )
    })?;
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
        "state::read" => Some("workspace.fs.read"),
        "state::write" => Some("workspace.fs.write"),
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
        "json" | "bytes" | "cap" | "agent" | "agent_runtime" | "http" | "stream" | "state"
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
    use ring::signature::KeyPair;

    #[test]
    fn captured_policy_closure_is_exact_and_role_and_capture_bound() {
        let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
            .join(format!("policy-closure-{}", uuid::Uuid::new_v4().simple()));
        let store = PackageStore::open(root).unwrap();
        store.bind_policy(&super::super::store::InstallAuthorization {
            admin: false,
            accepted_publishers: vec![],
            unsigned_dev_space: None,
        });
        let revision = store.install_embedding_owned().unwrap();
        let package = store.read_installed(&revision.artifact_id).unwrap();
        let lock = super::super::resolve::resolve_installed(
            std::slice::from_ref(&package),
            &super::super::resolve::ResolveRequest {
                harness_selection: crate::plugins::HarnessSelectionRequest::ToolOnly {
                    tool_package: package.manifest.id.clone(),
                },
                roots: vec![super::super::resolve::PackageRequirement {
                    id: package.manifest.id.clone(),
                    version: package.manifest.version.clone(),
                }],
                host_runtime: super::super::error::HOST_RUNTIME.into(),
            },
        )
        .unwrap();
        let prepared = store.prepare(&lock).unwrap();
        let catalog = prepared
            .managed_policy_catalog(&package.manifest.id)
            .unwrap();
        assert!(Arc::ptr_eq(
            &catalog,
            &store
                .prepare(&lock)
                .unwrap()
                .managed_policy_catalog(&package.manifest.id)
                .unwrap()
        ));
        let mut variants = Vec::new();
        let mut wrong = lock.clone();
        wrong.closure.clear();
        variants.push(wrong);
        let mut wrong = lock.clone();
        wrong.closure.push(wrong.closure[0].clone());
        variants.push(wrong);
        let mut wrong = lock.clone();
        let duplicate = wrong.closure[0].effects[0].clone();
        wrong.closure[0].effects.push(duplicate);
        variants.push(wrong);
        let mut wrong = lock.clone();
        wrong.closure[0].effects[0].via.caller_package = "forged".into();
        variants.push(wrong);
        let mut wrong = lock.clone();
        wrong.packages[0].artifact_id = "wrong-artifact".into();
        variants.push(wrong);
        let mut wrong = lock.clone();
        wrong.packages.push(wrong.packages[0].clone());
        variants.push(wrong);
        let mut wrong = lock.clone();
        wrong.edges.push(super::super::resolve::LockedEdge {
            from: package.manifest.id.clone(),
            from_entry: package.manifest.entry.export.clone(),
            alias: "forged".into(),
            to: package.manifest.id.clone(),
            to_version: package.manifest.version.clone(),
            to_artifact_id: package.artifact_id.clone(),
            to_entry: package.manifest.entry.export.clone(),
            relation: "delegated".into(),
            version_requirement: "1.0.0".into(),
            bindings: vec![],
        });
        variants.push(wrong);
        for wrong in variants {
            assert!(capture_managed_policy_catalog(&package, &wrong).is_err());
        }
        let mut dependency = package.clone();
        dependency
            .manifest
            .dependencies
            .push(super::super::manifest::PluginDependency {
                alias: "forged".into(),
                id: package.manifest.id.clone(),
                version: "1.0.0".into(),
            });
        assert!(capture_managed_policy_catalog(&dependency, &lock).is_err());
        let mut delegated = package.clone();
        delegated
            .manifest
            .effects
            .entries
            .get_mut(&package.manifest.entry.export)
            .unwrap()
            .delegated
            .push(super::super::manifest::DelegatedCall {
                dependency: "forged".into(),
                entry: package.manifest.entry.export.clone(),
                allow: vec![],
            });
        assert!(capture_managed_policy_catalog(&delegated, &lock).is_err());
        for trust in [PackageTrust::DevUnsigned, PackageTrust::AcceptedPublisher] {
            let mut wrong = package.clone();
            wrong.trust = trust;
            assert!(capture_managed_policy_catalog(&wrong, &lock).is_err());
        }
        let mut wrong = package.clone();
        wrong.manifest.kind = "library".into();
        wrong.manifest.contract = "agent.library/v1".into();
        assert!(capture_managed_policy_catalog(&wrong, &lock).is_err());
        let mut wrong = package.clone();
        wrong.sources.remove("rss/tools/types.rss");
        assert!(capture_managed_policy_catalog(&wrong, &lock).is_err());
    }

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

    #[test]
    fn signed_stateless_tool_only_captures_same_package_catalog() {
        let root =
            std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap()).join(
                format!("signed-catalog-capture-{}", uuid::Uuid::new_v4().simple()),
            );
        let _ = std::fs::remove_dir_all(&root);
        let store = PackageStore::open(root.join("store")).unwrap();
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let auth = super::super::store::InstallAuthorization {
            admin: true,
            accepted_publishers: vec![super::super::store::PublisherKey {
                publisher: "org.rustscript".into(),
                verifying_key: pair.public_key().as_ref().to_vec(),
            }],
            unsigned_dev_space: None,
        };
        let id = "org.rustscript.tools.catalogcapture";
        let package = root.join("package");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(
            package.join("manifest.yaml"),
            format!(
                "format: rustscript.plugin/v1\nid: {id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\n  - workspace.write\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
            ),
        )
        .unwrap();
        std::fs::write(
            package.join("run.rss"),
            "pub fn run(context: map) -> map { context }\n",
        )
        .unwrap();
        std::fs::write(
            package.join("catalog.rss"),
            include_bytes!("../../rss/tools/types.rss"),
        )
        .unwrap();
        let signature = pair.sign(&store.signature_payload(&package).unwrap());
        std::fs::write(package.join("signature.ed25519"), signature.as_ref()).unwrap();
        let installed = store.install(&package, &auth).unwrap();
        assert_eq!(installed.trust, PackageTrust::AcceptedPublisher);
        let lock = store
            .resolve(&super::super::resolve::ResolveRequest {
                harness_selection: crate::plugins::HarnessSelectionRequest::ToolOnly {
                    tool_package: id.into(),
                },
                roots: vec![super::super::resolve::PackageRequirement {
                    id: id.into(),
                    version: "1.0.0".into(),
                }],
                host_runtime: super::super::error::HOST_RUNTIME.into(),
            })
            .unwrap();
        let prepared = store.prepare(&lock).unwrap();
        assert_eq!(prepared.trust(id), Some(PackageTrust::AcceptedPublisher));
        assert_ne!(
            prepared.trust(id),
            Some(PackageTrust::EmbeddingOwnedBuiltin)
        );
        let catalog = prepared
            .managed_policy_catalog(id)
            .expect("verified AcceptedPublisher stateless ToolOnly catalog capture missing");
        let snapshot = crate::runtime::rss_runner::bundled_tool_registry()
            .unwrap()
            .snapshot();
        let code = crate::effects::ManagedCodeIdentity {
            graph_id: "untrusted-graph".into(),
            activation_generation: 0,
            graph_ref_id: "untrusted-ref".into(),
            package_id: id.into(),
            artifact_id: installed.artifact_id.clone(),
            export: "run".into(),
            registry_identity: snapshot.identity().to_string(),
            effect_contract_version: 1,
        };
        assert!(catalog.matches_code(&code));
        let mut forged = code.clone();
        forged.artifact_id = "forged-artifact".into();
        assert!(!catalog.matches_code(&forged));
        forged.artifact_id = installed.artifact_id.clone();
        forged.package_id = "forged-package".into();
        assert!(!catalog.matches_code(&forged));
        forged.package_id = id.into();
        forged.export = "managed_authority_catalog".into();
        assert!(!catalog.matches_code(&forged));
        catalog
            .seal(
                &code,
                &snapshot,
                "write_file",
                crate::capabilities::CapabilityRisk::Write,
                "{\"path\":\"out.txt\",\"content\":\"A\"}",
            )
            .unwrap();
        assert!(prepared.managed_contract(id).unwrap().topology.is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn open_root(label: &str) -> std::path::PathBuf {
        let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
            .join(format!("{label}-{}", uuid::Uuid::new_v4().simple()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn try_sign_install(
        root: &std::path::Path,
        manifest: &str,
        files: &[(&str, &[u8])],
        signed: bool,
    ) -> Result<
        (
            PackageStore,
            super::super::store::InstallAuthorization,
            super::super::store::PackageRevision,
        ),
        PluginError,
    > {
        let store = PackageStore::open(root.join("store")).unwrap();
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let package = root.join("package");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
        for (name, bytes) in files {
            std::fs::write(package.join(name), bytes).unwrap();
        }
        let auth = if signed {
            let signature = pair.sign(&store.signature_payload(&package).unwrap());
            std::fs::write(package.join("signature.ed25519"), signature.as_ref()).unwrap();
            super::super::store::InstallAuthorization {
                admin: true,
                accepted_publishers: vec![super::super::store::PublisherKey {
                    publisher: "org.rustscript".into(),
                    verifying_key: pair.public_key().as_ref().to_vec(),
                }],
                unsigned_dev_space: None,
            }
        } else {
            super::super::store::InstallAuthorization {
                admin: true,
                accepted_publishers: vec![],
                unsigned_dev_space: Some(root.to_path_buf()),
            }
        };
        let installed = store.install(&package, &auth)?;
        Ok((store, auth, installed))
    }

    fn sign_install(
        root: &std::path::Path,
        _id: &str,
        manifest: &str,
        files: &[(&str, &[u8])],
        signed: bool,
    ) -> (
        PackageStore,
        super::super::store::InstallAuthorization,
        super::super::store::PackageRevision,
    ) {
        try_sign_install(root, manifest, files, signed).unwrap()
    }

    fn stateless_manifest(id: &str) -> String {
        format!(
            "format: rustscript.plugin/v1\nid: {id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\n  - workspace.write\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
        )
    }

    /// State declaration plus an optional pure migration entry. Mirrors the
    /// accepted T12 manifest shape (session scope, schema 2, migration entry
    /// declared under `state` and under `effects.entries` with no effects).
    fn stateful_manifest(id: &str, schema: u32, migration_effects: Option<&str>) -> String {
        let migration_block = migration_effects
            .map(|_| "  migration:\n    entry: migrate\n")
            .unwrap_or_default();
        let migration_entry = migration_effects
            .map(|effects| format!("    migrate:\n      direct: {effects}\n      delegated: []\n"))
            .unwrap_or_default();
        format!(
            "format: rustscript.plugin/v1\nid: {id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\n  - workspace.write\nstate:\n  scope: session\n  schema: {schema}\n{migration_block}effects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n{migration_entry}"
        )
    }

    const PURE_MIGRATION_SOURCE: &str = r#"
use json;
pub fn migrate(input: map) -> map {
    let document: string = input["document"];
    let mut decoded: map = json::decode(document);
    decoded.version = 2;
    { schema: 2, document: json::encode(decoded) }
}
"#;

    fn resolve_tool(store: &PackageStore, id: &str) -> super::super::resolve::GraphLock {
        store
            .resolve(&super::super::resolve::ResolveRequest {
                harness_selection: crate::plugins::HarnessSelectionRequest::ToolOnly {
                    tool_package: id.into(),
                },
                roots: vec![super::super::resolve::PackageRequirement {
                    id: id.into(),
                    version: "1.0.0".into(),
                }],
                host_runtime: super::super::error::HOST_RUNTIME.into(),
            })
            .unwrap()
    }

    #[test]
    fn signed_tool_without_catalog_export_prepares_without_catalog() {
        let root = open_root("signed-no-catalog");
        let id = "org.rustscript.tools.nocatalog";
        let (store, _, installed) = sign_install(
            &root,
            id,
            &stateless_manifest(id),
            &[("run.rss", b"pub fn run(context: map) -> map { context }\n")],
            true,
        );
        assert_eq!(installed.trust, PackageTrust::AcceptedPublisher);
        let prepared = store.prepare(&resolve_tool(&store, id)).unwrap();
        assert!(prepared.managed_policy_catalog(id).is_none());
        assert!(prepared.managed_contract(id).unwrap().topology.is_none());
        assert_eq!(prepared.trust(id), Some(PackageTrust::AcceptedPublisher));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn source_edit_after_install_does_not_change_captured_catalog() {
        let root = open_root("signed-source-edit");
        let id = "org.rustscript.tools.catalogfrozen";
        let (store, _, installed) = sign_install(
            &root,
            id,
            &stateless_manifest(id),
            &[
                ("run.rss", b"pub fn run(context: map) -> map { context }\n"),
                ("catalog.rss", include_bytes!("../../rss/tools/types.rss")),
            ],
            true,
        );
        std::fs::write(
            root.join("package/catalog.rss"),
            b"pub fn managed_authority_catalog(context: map) -> map { context }\n",
        )
        .unwrap();
        std::fs::write(
            root.join("package/run.rss"),
            b"pub fn run(context: map) -> map { {} }\n",
        )
        .unwrap();
        let prepared = store.prepare(&resolve_tool(&store, id)).unwrap();
        assert_eq!(
            prepared.captured_source(id, "catalog.rss").unwrap(),
            include_bytes!("../../rss/tools/types.rss")
        );
        let code = crate::effects::ManagedCodeIdentity {
            graph_id: "untrusted-graph".into(),
            activation_generation: 0,
            graph_ref_id: "untrusted-ref".into(),
            package_id: id.into(),
            artifact_id: installed.artifact_id,
            export: "run".into(),
            registry_identity: "not-used-for-match".into(),
            effect_contract_version: 1,
        };
        assert!(
            prepared
                .managed_policy_catalog(id)
                .unwrap()
                .matches_code(&code)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unsigned_library_and_unsupported_edges_do_not_capture_catalog() {
        let catalog = include_bytes!("../../rss/tools/types.rss");
        let run = b"pub fn run(context: map) -> map { context }\n";
        let root = open_root("signed-ineligible");
        let unsigned_id = "org.rustscript.tools.unsignedcatalog";
        let (store, _, installed) = sign_install(
            &root,
            unsigned_id,
            &stateless_manifest(unsigned_id),
            &[("run.rss", run), ("catalog.rss", catalog)],
            false,
        );
        assert_eq!(installed.trust, PackageTrust::DevUnsigned);
        let prepared = store.prepare(&resolve_tool(&store, unsigned_id)).unwrap();
        assert!(prepared.managed_policy_catalog(unsigned_id).is_none());
        assert_ne!(
            prepared.trust(unsigned_id),
            Some(PackageTrust::EmbeddingOwnedBuiltin)
        );

        let library_id = "org.rustscript.lib.cataloglib";
        let library_root = open_root("signed-library");
        let library_manifest = format!(
            "format: rustscript.plugin/v1\nid: {library_id}\nversion: 1.0.0\nkind: library\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.library/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities: []\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct: []\n      delegated: []\n"
        );
        let (store, _, _) = sign_install(
            &library_root,
            library_id,
            &library_manifest,
            &[("run.rss", run), ("catalog.rss", catalog)],
            true,
        );
        let prepared = store.prepare(&resolve_tool(&store, library_id)).unwrap();
        assert!(prepared.managed_policy_catalog(library_id).is_none());

        let edge_id = "org.rustscript.tools.catalogedge";
        let dep_id = "org.rustscript.lib.catalogdep";
        let edge_root = open_root("signed-edge");
        let store = PackageStore::open(edge_root.join("store")).unwrap();
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let auth = super::super::store::InstallAuthorization {
            admin: true,
            accepted_publishers: vec![super::super::store::PublisherKey {
                publisher: "org.rustscript".into(),
                verifying_key: pair.public_key().as_ref().to_vec(),
            }],
            unsigned_dev_space: None,
        };
        let library = edge_root.join("library");
        std::fs::create_dir_all(&library).unwrap();
        std::fs::write(
            library.join("manifest.yaml"),
            format!(
                "format: rustscript.plugin/v1\nid: {dep_id}\nversion: 1.0.0\nkind: library\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.library/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities: []\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct: []\n      delegated: []\n"
            ),
        )
        .unwrap();
        std::fs::write(library.join("run.rss"), run).unwrap();
        std::fs::write(
            library.join("signature.ed25519"),
            pair.sign(&store.signature_payload(&library).unwrap())
                .as_ref(),
        )
        .unwrap();
        store.install(&library, &auth).unwrap();
        let tool = edge_root.join("tool");
        std::fs::create_dir_all(&tool).unwrap();
        std::fs::write(
            tool.join("manifest.yaml"),
            stateless_manifest(edge_id).replace(
                "dependencies: []\n",
                &format!(
                    "dependencies:\n  - alias: lib\n    id: {dep_id}\n    version: \"1.0.0\"\n"
                ),
            ),
        )
        .unwrap();
        std::fs::write(tool.join("run.rss"), run).unwrap();
        std::fs::write(tool.join("catalog.rss"), catalog).unwrap();
        std::fs::write(
            tool.join("signature.ed25519"),
            pair.sign(&store.signature_payload(&tool).unwrap()).as_ref(),
        )
        .unwrap();
        store.install(&tool, &auth).unwrap();
        let lock = resolve_tool(&store, edge_id);
        assert!(!lock.edges.is_empty());
        let prepared = store.prepare(&lock).unwrap();
        assert!(prepared.managed_policy_catalog(edge_id).is_none());
        assert!(
            prepared
                .managed_contract(edge_id)
                .unwrap()
                .topology
                .is_none()
        );
        assert_eq!(
            prepared.trust(edge_id),
            Some(PackageTrust::AcceptedPublisher)
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&library_root);
        let _ = std::fs::remove_dir_all(&edge_root);
    }

    #[test]
    fn stateful_tool_only_captures_catalog_and_topology() {
        let root = open_root("signed-stateful-catalog");
        let id = "org.rustscript.tools.statefulcatalog";
        let (store, _, installed) = sign_install(
            &root,
            id,
            &stateful_manifest(id, 1, None),
            &[
                ("run.rss", b"pub fn run(context: map) -> map { context }\n"),
                ("catalog.rss", include_bytes!("../../rss/tools/types.rss")),
            ],
            true,
        );
        assert_eq!(installed.trust, PackageTrust::AcceptedPublisher);
        let prepared = store.prepare(&resolve_tool(&store, id)).unwrap();
        assert!(
            prepared.managed_policy_catalog(id).is_some(),
            "stateful single-package ToolOnly must capture its same-package catalog"
        );
        assert!(
            prepared.managed_contract(id).unwrap().topology.is_some(),
            "stateful single-package ToolOnly must keep the supported topology"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stateful_pure_migration_entry_captures_catalog_and_topology() {
        let root = open_root("signed-stateful-migration");
        let id = "org.rustscript.tools.statefulmigration";
        let (store, _, _) = sign_install(
            &root,
            id,
            &stateful_manifest(id, 2, Some("[]")),
            &[
                ("run.rss", b"pub fn run(context: map) -> map { context }\n"),
                ("migrate.rss", PURE_MIGRATION_SOURCE.as_bytes()),
                ("catalog.rss", include_bytes!("../../rss/tools/types.rss")),
            ],
            true,
        );
        let prepared = store.prepare(&resolve_tool(&store, id)).unwrap();
        assert!(
            prepared.managed_policy_catalog(id).is_some(),
            "pure same-package migration must not suppress the tool catalog"
        );
        assert!(
            prepared.managed_contract(id).unwrap().topology.is_some(),
            "pure same-package migration must keep the supported ToolOnly topology"
        );
        assert_eq!(
            prepared.state_migration(id).unwrap().target_schema,
            2,
            "the pure migration entry must be compiled, not dropped"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn effectful_migration_entry_is_rejected_exactly_before_install() {
        let root = open_root("signed-stateful-effect");
        let id = "org.rustscript.tools.statefuleffect";
        let error = match try_sign_install(
            &root,
            &stateful_manifest(
                id,
                2,
                Some("[{kind: workspace.fs.write, scope: bound_workspace, recovery: none}]"),
            ),
            &[
                ("run.rss", b"pub fn run(context: map) -> map { context }\n"),
                ("migrate.rss", PURE_MIGRATION_SOURCE.as_bytes()),
            ],
            true,
        ) {
            Ok(_) => panic!("an effectful migration entry must not install"),
            Err(error) => error,
        };
        assert_eq!(error.kind, PluginErrorKind::UncoveredExport);
        assert_eq!(
            error.to_string(),
            "UncoveredExport: state migration must be pure",
            "the manifest contract rejects the effectful migration entry explicitly"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn signed_context_prompt_does_not_validate_as_managed_topology() {
        let root = open_root("signed-context");
        let id = "org.rustscript.tools.catalogprompt";
        let (store, _, _) = sign_install(
            &root,
            id,
            &stateless_manifest(id),
            &[
                ("run.rss", b"pub fn run(context: map) -> map { context }\n"),
                ("catalog.rss", include_bytes!("../../rss/tools/types.rss")),
            ],
            true,
        );
        let mut lock = resolve_tool(&store, id);
        lock.harness_selection = super::super::resolve::HarnessSelection::ContextPrompt {
            tool_package: id.into(),
            policy: super::super::resolve::PurePolicySelection {
                package_id: "org.rustscript.lib.prompt".into(),
                artifact_id: "forged".into(),
                entry_path: "policy.rss".into(),
                prompt_export: "prompt".into(),
                context_export: "context".into(),
                guardian_export: "guardian".into(),
            },
        };
        let installed = store
            .verified_capture(&[(id, lock.packages[0].artifact_id.as_str())])
            .unwrap();
        assert!(SupportedManagedTopology::validate(&lock, &installed[0]).is_none());
        assert!(store.prepare(&lock).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn impure_or_inconsistent_catalog_rejects_prepare() {
        let root = open_root("signed-impure");
        let cases: &[(&str, &[u8])] = &[
            (
                "org.rustscript.tools.catalogcap",
                b"pub fn managed_authority_catalog(context: map) -> map {\n    let written: map = cap::fs_write_atomic(\"t\", \"p\", \"*\", context);\n    written\n}\n",
            ),
            (
                "org.rustscript.tools.catalogruntime",
                b"pub fn managed_authority_catalog(context: map) -> map {\n    let prepared: map = agent_runtime::tool_prepare(context);\n    prepared\n}\n",
            ),
            (
                "org.rustscript.tools.catalogrisk",
                b"pub fn managed_authority_catalog(context: map) -> map {\n    {\n        declarations: [{ tool_name: \"write_file\", operation: \"workspace_read\" }],\n        descriptors: [{\n            name: \"write_file\",\n            description: \"forged\",\n            toolset: \"coding\",\n            risk_class: \"write\",\n            schema: { type: \"object\" }\n        }]\n    }\n}\n",
            ),
        ];
        for (id, catalog) in cases {
            let case_root = open_root(id);
            let (store, _, _) = sign_install(
                &case_root,
                id,
                &stateless_manifest(id),
                &[
                    ("run.rss", b"pub fn run(context: map) -> map { context }\n"),
                    ("catalog.rss", catalog),
                ],
                true,
            );
            let error = store.prepare(&resolve_tool(&store, id)).unwrap_err();
            assert_eq!(
                error.kind,
                PluginErrorKind::ContractIncompatible,
                "{id} {:?}",
                error.kind
            );
            assert!(
                error.to_string().contains("managed captured catalog"),
                "{id} {error}"
            );
            let _ = std::fs::remove_dir_all(&case_root);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cancelled_signed_prepare_does_not_return_a_catalog() {
        let root = open_root("signed-cancel");
        let id = "org.rustscript.tools.catalogcancel";
        let (store, _, _) = sign_install(
            &root,
            id,
            &stateless_manifest(id),
            &[
                ("run.rss", b"pub fn run(context: map) -> map { context }\n"),
                ("catalog.rss", include_bytes!("../../rss/tools/types.rss")),
            ],
            true,
        );
        let lock = resolve_tool(&store, id);
        let cancel = crate::RunCancellation::with_deadline(
            std::time::Instant::now() + std::time::Duration::from_secs(30),
        );
        cancel.request(crate::CancellationReason::Requested);
        assert!(store.prepare_harness_graph(&lock, &cancel).is_err());
        let expired = crate::RunCancellation::with_deadline(
            std::time::Instant::now() - std::time::Duration::from_secs(1),
        );
        assert!(store.prepare_harness_graph(&lock, &expired).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn narrow_pair_manifests(
        tool_id: &str,
        leaf_id: &str,
    ) -> (String, String, &'static str, &'static str) {
        let tool = format!(
            "format: rustscript.plugin/v1\nid: {tool_id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: text\n    id: {leaf_id}\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
        );
        let leaf = format!(
            "format: rustscript.plugin/v1\nid: {leaf_id}\nversion: 1.0.0\nkind: library\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.library/v1\nhost_abi: agent.cap/v1\nentry:\n  path: format.rss\n  export: format\ndependencies: []\ncapabilities: []\neffects:\n  contract: agent.effects/v1\n  entries:\n    format:\n      direct: []\n      delegated: []\n"
        );
        (
            tool,
            leaf,
            "pub fn format(value: string) -> string { \"libA:\" + value }\n",
            "use bytes;\nuse text::{format};\n\npub fn run(token: string, path: string) -> map {\n    let read: map = cap::fs_read_range(token, path, 0, 8);\n    let payload: bytes = read.bytes;\n    { ok: true, content: format(bytes::to_utf8(payload)) }\n}\n",
        )
    }

    fn install_narrow_pair(
        root: &std::path::Path,
        tool_id: &str,
        leaf_id: &str,
    ) -> super::super::store::PackageStore {
        let (tool_manifest, leaf_manifest, leaf_source, tool_source) =
            narrow_pair_manifests(tool_id, leaf_id);
        let store = super::super::store::PackageStore::open(root.join("store")).unwrap();
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let auth = super::super::store::InstallAuthorization {
            admin: true,
            accepted_publishers: vec![super::super::store::PublisherKey {
                publisher: "org.rustscript".into(),
                verifying_key: pair.public_key().as_ref().to_vec(),
            }],
            unsigned_dev_space: None,
        };
        for (dir, manifest, files) in [
            (
                "leaf",
                leaf_manifest.as_str(),
                vec![("format.rss", leaf_source)],
            ),
            (
                "tool",
                tool_manifest.as_str(),
                vec![("run.rss", tool_source)],
            ),
        ] {
            let package = root.join(dir);
            std::fs::create_dir_all(&package).unwrap();
            std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
            for (name, body) in files {
                std::fs::write(package.join(name), body).unwrap();
            }
            std::fs::write(
                package.join("signature.ed25519"),
                pair.sign(&store.signature_payload(&package).unwrap())
                    .as_ref(),
            )
            .unwrap();
            store.install(&package, &auth).unwrap();
        }
        store
    }

    #[test]
    fn tool_library_topology_accepts_only_the_narrow_shape() {
        let root = open_root("narrow-topology");
        let tool_id = "org.rustscript.tools.narrowread";
        let leaf_id = "org.rustscript.lib.narrowtext";
        let store = install_narrow_pair(&root, tool_id, leaf_id);
        let lock = resolve_tool(&store, tool_id);
        assert_eq!(lock.packages.len(), 2);
        assert_eq!(lock.edges.len(), 1);
        let installed = store
            .verified_capture(&[(
                tool_id,
                lock.packages
                    .iter()
                    .find(|package| package.id == tool_id)
                    .unwrap()
                    .artifact_id
                    .as_str(),
            )])
            .unwrap();
        let tool = installed
            .iter()
            .find(|package| package.manifest.id == tool_id)
            .unwrap();
        assert!(SupportedManagedTopology::validate(&lock, tool).is_some());
        assert!(store.prepare(&lock).unwrap().program(tool_id).is_some());

        let mut plugin_edge = lock.clone();
        plugin_edge.edges[0].relation = "plugin".into();
        assert!(SupportedManagedTopology::validate(&plugin_edge, tool).is_none());

        let mut unselected = lock.clone();
        unselected.harness_selection = super::super::resolve::HarnessSelection::Unselected;
        assert!(SupportedManagedTopology::validate(&unselected, tool).is_none());

        let mut write_cap = tool.clone();
        write_cap
            .manifest
            .capabilities
            .push("workspace.write".into());
        assert!(SupportedManagedTopology::validate(&lock, &write_cap).is_none());

        let leaf = store
            .verified_capture(&[(
                leaf_id,
                lock.packages
                    .iter()
                    .find(|package| package.id == leaf_id)
                    .unwrap()
                    .artifact_id
                    .as_str(),
            )])
            .unwrap();
        let leaf = leaf
            .iter()
            .find(|package| package.manifest.id == leaf_id)
            .unwrap();
        assert!(SupportedManagedTopology::validate(&lock, leaf).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }
}
