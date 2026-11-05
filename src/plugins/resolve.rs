//! Version resolution and effect-closure construction.
//!
//! The graph id is an opaque lock identity. It is not a permission, and the
//! semantic lock excludes it so install order cannot change the solution.
//! Edge fields keep the caller entry, callee entry, alias, requirement, and
//! resolved revision. Provenance is not collapsed to a single delegated label.

use std::collections::{BTreeMap, BTreeSet};

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::error::{
    COMPILE_ENVIRONMENT, EFFECT_KINDS, PLUGIN_KINDS, PluginError, PluginErrorKind,
    recovery_allowed, scope_for,
};
use super::manifest::EffectRequirement;
use super::store::InstalledPackage;

const MAX_PACKAGES: usize = 64;
const MAX_EDGES: usize = 256;
const MAX_DEPTH: usize = 16;
const MAX_VERSIONS: usize = 32;
const MAX_DECISIONS: usize = 4096;
// Per lock, before deduplication. Each identity yields at most two changes;
// the public stored-lock path also enforces its existing document byte limit.
const MAX_PERMISSION_ITEMS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageRequirement {
    pub id: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolveRequest {
    pub roots: Vec<PackageRequirement>,
    pub host_runtime: String,
    pub harness_selection: HarnessSelectionRequest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HarnessSelectionRequest {
    Unselected,
    ToolOnly {
        tool_package: String,
    },
    ContextPrompt {
        tool_package: String,
        policy_package: String,
        prompt_export: String,
        context_export: String,
        guardian_export: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum HarnessSelection {
    Unselected,
    ToolOnly {
        tool_package: String,
    },
    ContextPrompt {
        tool_package: String,
        policy: PurePolicySelection,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurePolicySelection {
    pub package_id: String,
    pub artifact_id: String,
    pub entry_path: String,
    pub prompt_export: String,
    pub context_export: String,
    pub guardian_export: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedPackage {
    pub id: String,
    pub version: String,
    pub kind: String,
    pub artifact_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBinding {
    pub kind: String,
    pub scope: String,
    pub recovery: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedEdge {
    pub from: String,
    pub from_entry: String,
    pub alias: String,
    pub to: String,
    pub to_version: String,
    pub to_artifact_id: String,
    pub to_entry: String,
    pub relation: String,
    pub version_requirement: String,
    pub bindings: Vec<ScopeBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectOrigin {
    pub relation: String,
    pub caller_package: String,
    pub caller_entry: String,
    pub alias: String,
    pub callee_package: String,
    pub callee_version: String,
    pub callee_entry: String,
    pub version_requirement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedEffect {
    pub package: String,
    pub entry: String,
    pub effects: Vec<LockedEffectItem>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedEffectItem {
    pub kind: String,
    pub scope: String,
    pub recovery: String,
    pub via: EffectOrigin,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphLock {
    pub graph_id: String,
    pub harness_selection: HarnessSelection,
    pub host_runtime: String,
    pub compile_environment: String,
    pub packages: Vec<LockedPackage>,
    pub edges: Vec<LockedEdge>,
    pub closure: Vec<LockedEffect>,
}

/// Permission review data only; this never grants activation authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionDiff {
    /// False means no permission expansion was found; compatibility and approval
    /// remain unchecked. Neither value authorizes activation.
    pub requires_reapproval: bool,
    pub changes: Vec<PermissionChange>,
    pub compatibility: CompatibilityCheck,
    pub metadata: GraphMetadataDiff,
}

/// Metadata changes are distinct from permission expansion. All still require
/// compatibility inspection, including pure dependency and entry changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphMetadataDiff {
    pub package_revisions: Vec<PackageRevisionDiff>,
    pub edges_changed: bool,
    pub entries_changed: bool,
    pub host_contract_changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageRevisionDiff {
    pub package: String,
    pub before: Option<LockedPackage>,
    pub after: Option<LockedPackage>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatibilityCheck {
    /// ABI, schemas, dependency calls, and administrator approval are not checked.
    Unchecked,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PermissionIdentity {
    pub location: PermissionLocation,
    pub package: String,
    pub package_kind: String,
    pub entry: String,
    pub kind: String,
    pub relation: String,
    pub caller_package: String,
    pub caller_entry: String,
    pub alias: String,
    pub callee_package: String,
    pub callee_entry: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PermissionLocation {
    Closure,
    EdgeBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PermissionChangeKind {
    Added,
    Removed,
    ScopeChanged,
    RecoveryChanged,
    RecoveryDowngraded,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PermissionChange {
    pub identity: PermissionIdentity,
    pub kind: PermissionChangeKind,
    pub before: Vec<PermissionValue>,
    pub after: Vec<PermissionValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PermissionValue {
    pub scope: String,
    pub recovery: String,
}

fn permission_values(lock: &GraphLock) -> BTreeMap<PermissionIdentity, BTreeSet<PermissionValue>> {
    let packages: BTreeMap<_, _> = lock.packages.iter().map(|p| (&p.id, &p.kind)).collect();
    let mut values: BTreeMap<_, BTreeSet<_>> = BTreeMap::new();
    for entry in &lock.closure {
        for effect in &entry.effects {
            let identity = PermissionIdentity {
                location: PermissionLocation::Closure,
                package: entry.package.clone(),
                package_kind: packages
                    .get(&entry.package)
                    .map(|kind| (*kind).clone())
                    .unwrap_or_default(),
                entry: entry.entry.clone(),
                kind: effect.kind.clone(),
                relation: effect.via.relation.clone(),
                caller_package: effect.via.caller_package.clone(),
                caller_entry: effect.via.caller_entry.clone(),
                alias: effect.via.alias.clone(),
                callee_package: effect.via.callee_package.clone(),
                callee_entry: effect.via.callee_entry.clone(),
            };
            values.entry(identity).or_default().insert(PermissionValue {
                scope: effect.scope.clone(),
                recovery: effect.recovery.clone(),
            });
        }
    }
    for edge in &lock.edges {
        for binding in &edge.bindings {
            let identity = PermissionIdentity {
                location: PermissionLocation::EdgeBinding,
                package: edge.from.clone(),
                package_kind: packages
                    .get(&edge.from)
                    .map(|kind| (*kind).clone())
                    .unwrap_or_default(),
                entry: edge.from_entry.clone(),
                kind: binding.kind.clone(),
                relation: edge.relation.clone(),
                caller_package: edge.from.clone(),
                caller_entry: edge.from_entry.clone(),
                alias: edge.alias.clone(),
                callee_package: edge.to.clone(),
                callee_entry: edge.to_entry.clone(),
            };
            values.entry(identity).or_default().insert(PermissionValue {
                scope: binding.scope.clone(),
                recovery: binding.recovery.clone(),
            });
        }
    }
    values
}

pub(crate) fn compare_graph_permissions(
    previous: &GraphLock,
    candidate: &GraphLock,
) -> Result<PermissionDiff, PluginError> {
    for lock in [previous, candidate] {
        if lock.packages.len() > MAX_PACKAGES
            || lock.edges.len() > MAX_EDGES
            || lock.closure.len() > MAX_PACKAGES
        {
            return Err(budget("permission_diff_items"));
        }
        let mut items = 0usize;
        for count in lock
            .closure
            .iter()
            .map(|entry| entry.effects.len())
            .chain(lock.edges.iter().map(|edge| edge.bindings.len()))
        {
            items = items.saturating_add(count);
            if items > MAX_PERMISSION_ITEMS {
                return Err(budget("permission_diff_items"));
            }
        }
    }
    let metadata = graph_metadata_diff(previous, candidate);
    let previous = permission_values(previous);
    let candidate = permission_values(candidate);
    let mut changes = Vec::new();
    for (identity, after) in &candidate {
        let before = previous.get(identity);
        let mut kinds = Vec::new();
        if let Some(before) = before {
            let old_scopes: BTreeSet<_> = before.iter().map(|v| &v.scope).collect();
            let new_scopes: BTreeSet<_> = after.iter().map(|v| &v.scope).collect();
            if old_scopes != new_scopes {
                kinds.push(PermissionChangeKind::ScopeChanged);
            }
            let old_recovery: BTreeSet<_> = before.iter().map(|v| v.recovery.as_str()).collect();
            let new_recovery: BTreeSet<_> = after.iter().map(|v| v.recovery.as_str()).collect();
            if old_recovery != new_recovery {
                kinds.push(
                    if old_recovery.contains("checkpoint") && new_recovery.contains("none") {
                        PermissionChangeKind::RecoveryDowngraded
                    } else {
                        PermissionChangeKind::RecoveryChanged
                    },
                );
            }
        } else {
            kinds.push(PermissionChangeKind::Added);
        }
        for kind in kinds {
            changes.push(PermissionChange {
                identity: identity.clone(),
                kind,
                before: before.into_iter().flatten().cloned().collect(),
                after: after.iter().cloned().collect(),
            });
        }
    }
    for (identity, before) in &previous {
        if !candidate.contains_key(identity) {
            changes.push(PermissionChange {
                identity: identity.clone(),
                kind: PermissionChangeKind::Removed,
                before: before.iter().cloned().collect(),
                after: Vec::new(),
            });
        }
    }
    changes.sort();
    Ok(PermissionDiff {
        requires_reapproval: changes.iter().any(|change| {
            matches!(
                change.kind,
                PermissionChangeKind::Added
                    | PermissionChangeKind::ScopeChanged
                    | PermissionChangeKind::RecoveryDowngraded
            )
        }),
        changes,
        compatibility: CompatibilityCheck::Unchecked,
        metadata,
    })
}

fn graph_metadata_diff(previous: &GraphLock, candidate: &GraphLock) -> GraphMetadataDiff {
    let old: BTreeMap<_, _> = previous.packages.iter().map(|p| (&p.id, p)).collect();
    let new: BTreeMap<_, _> = candidate.packages.iter().map(|p| (&p.id, p)).collect();
    let ids: BTreeSet<_> = old.keys().chain(new.keys()).copied().collect();
    let package_revisions = ids
        .into_iter()
        .filter_map(|id| {
            let before = old.get(id).copied();
            let after = new.get(id).copied();
            (before != after).then(|| PackageRevisionDiff {
                package: id.clone(),
                before: before.cloned(),
                after: after.cloned(),
            })
        })
        .collect();
    let edges = |lock: &GraphLock| -> BTreeSet<LockedEdge> {
        lock.edges
            .iter()
            .cloned()
            .map(|mut edge| {
                edge.bindings.sort();
                edge.bindings.dedup();
                edge
            })
            .collect()
    };
    let entries = |lock: &GraphLock| -> BTreeSet<(String, String)> {
        lock.closure
            .iter()
            .map(|entry| (entry.package.clone(), entry.entry.clone()))
            .collect()
    };
    GraphMetadataDiff {
        package_revisions,
        edges_changed: edges(previous) != edges(candidate),
        entries_changed: entries(previous) != entries(candidate),
        host_contract_changed: previous.host_runtime != candidate.host_runtime
            || previous.compile_environment != candidate.compile_environment
            || previous.harness_selection != candidate.harness_selection,
    }
}

impl GraphLock {
    pub fn closure_kinds(&self, package_id: &str, entry: &str) -> Vec<String> {
        self.closure
            .iter()
            .find(|item| item.package == package_id && item.entry == entry)
            .map(|item| {
                item.effects
                    .iter()
                    .map(|effect| effect.kind.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn semantic_yaml(&self) -> String {
        let mut yaml = String::new();
        yaml.push_str("harness_selection: ");
        yaml.push_str(&serde_json::to_string(&self.harness_selection).expect("typed selection"));
        yaml.push('\n');
        yaml.push_str("compile_environment: ");
        yaml.push_str(&self.compile_environment);
        yaml.push('\n');
        yaml.push_str("host_runtime: ");
        yaml.push_str(&self.host_runtime);
        yaml.push_str("\npackages:\n");
        for package in &self.packages {
            yaml.push_str("  - id: ");
            yaml.push_str(&yaml_scalar(&package.id));
            yaml.push_str("\n    version: ");
            yaml.push_str(&yaml_scalar(&package.version));
            yaml.push_str("\n    kind: ");
            yaml.push_str(&yaml_scalar(&package.kind));
            yaml.push_str("\n    artifact_id: ");
            yaml.push_str(&yaml_scalar(&package.artifact_id));
            yaml.push('\n');
        }
        yaml.push_str("edges:\n");
        for edge in &self.edges {
            yaml.push_str("  - from: ");
            yaml.push_str(&yaml_scalar(&edge.from));
            yaml.push_str("\n    from_entry: ");
            yaml.push_str(&yaml_scalar(&edge.from_entry));
            yaml.push_str("\n    alias: ");
            yaml.push_str(&yaml_scalar(&edge.alias));
            yaml.push_str("\n    to: ");
            yaml.push_str(&yaml_scalar(&edge.to));
            yaml.push_str("\n    to_version: ");
            yaml.push_str(&yaml_scalar(&edge.to_version));
            yaml.push_str("\n    to_artifact_id: ");
            yaml.push_str(&yaml_scalar(&edge.to_artifact_id));
            yaml.push_str("\n    to_entry: ");
            yaml.push_str(&yaml_scalar(&edge.to_entry));
            yaml.push_str("\n    relation: ");
            yaml.push_str(&yaml_scalar(&edge.relation));
            yaml.push_str("\n    version_requirement: ");
            yaml.push_str(&yaml_scalar(&edge.version_requirement));
            yaml.push_str("\n    bindings:\n");
            for binding in &edge.bindings {
                yaml.push_str("      - kind: ");
                yaml.push_str(&yaml_scalar(&binding.kind));
                yaml.push_str("\n        scope: ");
                yaml.push_str(&yaml_scalar(&binding.scope));
                yaml.push_str("\n        recovery: ");
                yaml.push_str(&yaml_scalar(&binding.recovery));
                yaml.push('\n');
            }
        }
        yaml.push_str("closure:\n");
        for entry in &self.closure {
            yaml.push_str("  - package: ");
            yaml.push_str(&yaml_scalar(&entry.package));
            yaml.push_str("\n    entry: ");
            yaml.push_str(&yaml_scalar(&entry.entry));
            yaml.push_str("\n    effects:\n");
            for effect in &entry.effects {
                yaml.push_str("      - kind: ");
                yaml.push_str(&yaml_scalar(&effect.kind));
                yaml.push_str("\n        scope: ");
                yaml.push_str(&yaml_scalar(&effect.scope));
                yaml.push_str("\n        recovery: ");
                yaml.push_str(&yaml_scalar(&effect.recovery));
                yaml.push_str("\n        via:\n");
                yaml.push_str("          relation: ");
                yaml.push_str(&yaml_scalar(&effect.via.relation));
                yaml.push_str("\n          caller_package: ");
                yaml.push_str(&yaml_scalar(&effect.via.caller_package));
                yaml.push_str("\n          caller_entry: ");
                yaml.push_str(&yaml_scalar(&effect.via.caller_entry));
                yaml.push_str("\n          alias: ");
                yaml.push_str(&yaml_scalar(&effect.via.alias));
                yaml.push_str("\n          callee_package: ");
                yaml.push_str(&yaml_scalar(&effect.via.callee_package));
                yaml.push_str("\n          callee_version: ");
                yaml.push_str(&yaml_scalar(&effect.via.callee_version));
                yaml.push_str("\n          callee_entry: ");
                yaml.push_str(&yaml_scalar(&effect.via.callee_entry));
                yaml.push_str("\n          version_requirement: ");
                yaml.push_str(&yaml_scalar(&effect.via.version_requirement));
                yaml.push('\n');
            }
        }
        yaml
    }

    pub(crate) fn schema_value(&self) -> Value {
        json!({
            "graph_id": self.graph_id,
            "harness_selection": self.harness_selection,
            "host_runtime": self.host_runtime,
            "compile_environment": self.compile_environment,
            "packages": self.packages.iter().map(|package| json!({
                "id": package.id,
                "version": package.version,
                "kind": package.kind,
                "artifact_id": package.artifact_id,
            })).collect::<Vec<_>>(),
            "edges": self.edges.iter().map(|edge| json!({
                "from": edge.from,
                "from_entry": edge.from_entry,
                "alias": edge.alias,
                "to": edge.to,
                "to_version": edge.to_version,
                "to_artifact_id": edge.to_artifact_id,
                "to_entry": edge.to_entry,
                "relation": edge.relation,
                "version_requirement": edge.version_requirement,
                "bindings": edge.bindings.iter().map(|binding| json!({
                    "kind": binding.kind,
                    "scope": binding.scope,
                    "recovery": binding.recovery,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "closure": self.closure.iter().map(|entry| json!({
                "package": entry.package,
                "entry": entry.entry,
                "effects": entry.effects.iter().map(|effect| json!({
                    "kind": effect.kind,
                    "scope": effect.scope,
                    "recovery": effect.recovery,
                    "via": {
                        "relation": effect.via.relation,
                        "caller_package": effect.via.caller_package,
                        "caller_entry": effect.via.caller_entry,
                        "alias": effect.via.alias,
                        "callee_package": effect.via.callee_package,
                        "callee_version": effect.via.callee_version,
                        "callee_entry": effect.via.callee_entry,
                        "version_requirement": effect.via.version_requirement,
                    },
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        })
    }

    pub(crate) fn from_schema_value(value: Value) -> Result<Self, PluginError> {
        serde_json::from_value(value)
            .map_err(|_| PluginError::new(PluginErrorKind::UnknownField, "lock"))
    }

    pub(crate) fn validate_persisted(&self) -> Result<(), PluginError> {
        if !plain_identity(&self.graph_id) {
            return Err(PluginError::new(PluginErrorKind::PathEscape, "graph_id"));
        }
        Version::parse(&self.host_runtime)
            .map_err(|_| PluginError::new(PluginErrorKind::ContractIncompatible, "host runtime"))?;
        if self.compile_environment != COMPILE_ENVIRONMENT {
            return Err(PluginError::new(
                PluginErrorKind::ContractIncompatible,
                "compile environment",
            ));
        }
        if self.packages.is_empty() || self.packages.len() > 64 {
            return Err(PluginError::new(PluginErrorKind::UnknownField, "packages"));
        }
        let mut package_ids = BTreeSet::new();
        let mut packages = BTreeMap::new();
        for package in &self.packages {
            if !package_ids.insert(package.id.clone())
                || !plain_identity(&package.id)
                || !plain_identity(&package.artifact_id)
                || !PLUGIN_KINDS.contains(&package.kind.as_str())
                || Version::parse(&package.version).is_err()
            {
                return Err(PluginError::new(PluginErrorKind::UnknownField, "package"));
            }
            packages.insert(package.id.clone(), package);
        }
        if self.edges.len() > 256 || self.closure.len() > 64 {
            return Err(PluginError::new(PluginErrorKind::UnknownField, "closure"));
        }
        for edge in &self.edges {
            let from = packages
                .get(&edge.from)
                .ok_or_else(|| PluginError::new(PluginErrorKind::MissingDependency, &edge.from))?;
            let to = packages
                .get(&edge.to)
                .ok_or_else(|| PluginError::new(PluginErrorKind::MissingDependency, &edge.to))?;
            let expected_relation = if to.kind == "library" {
                "library"
            } else {
                "plugin"
            };
            let requirement = VersionReq::parse(&edge.version_requirement).map_err(|_| {
                PluginError::new(PluginErrorKind::UnknownField, "version_requirement")
            })?;
            let resolved = Version::parse(&to.version)
                .map_err(|_| PluginError::new(PluginErrorKind::UnknownField, "version"))?;
            if edge.from_entry.is_empty()
                || edge.to_entry.is_empty()
                || edge.alias.is_empty()
                || edge.to_version != to.version
                || edge.to_artifact_id != to.artifact_id
                || edge.relation != expected_relation
                || from.id == to.id
                || !requirement.matches(&resolved)
            {
                return Err(PluginError::new(PluginErrorKind::UnknownField, "edge"));
            }
            for binding in &edge.bindings {
                validate_effect(&binding.kind, &binding.scope, &binding.recovery)?;
            }
        }
        for entry in &self.closure {
            if !packages.contains_key(&entry.package) || entry.entry.is_empty() {
                return Err(PluginError::new(PluginErrorKind::UnknownField, "closure"));
            }
            for effect in &entry.effects {
                validate_effect(&effect.kind, &effect.scope, &effect.recovery)?;
                validate_origin(&effect.via)?;
            }
        }
        Ok(())
    }
}

fn plain_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains("..")
        && value.chars().all(|item| !item.is_control())
}

fn validate_effect(kind: &str, scope: &str, recovery: &str) -> Result<(), PluginError> {
    if !EFFECT_KINDS.contains(&kind)
        || scope_for(kind) != Some(scope)
        || !recovery_allowed(kind, recovery)
    {
        return Err(PluginError::new(PluginErrorKind::UnknownEffect, kind));
    }
    Ok(())
}

fn validate_origin(origin: &EffectOrigin) -> Result<(), PluginError> {
    if !matches!(origin.relation.as_str(), "direct" | "plugin" | "library")
        || origin.caller_package.is_empty()
        || origin.caller_entry.is_empty()
        || origin.callee_package.is_empty()
        || origin.callee_entry.is_empty()
        || Version::parse(&origin.callee_version).is_err()
    {
        return Err(PluginError::new(PluginErrorKind::UnknownField, "via"));
    }
    let direct = origin.relation == "direct";
    if direct != origin.alias.is_empty() {
        return Err(PluginError::new(PluginErrorKind::UnknownField, "via"));
    }
    if !origin.version_requirement.is_empty() {
        let requirement = VersionReq::parse(&origin.version_requirement)
            .map_err(|_| PluginError::new(PluginErrorKind::UnknownField, "via"))?;
        let resolved = Version::parse(&origin.callee_version)
            .map_err(|_| PluginError::new(PluginErrorKind::UnknownField, "via"))?;
        if !requirement.matches(&resolved) {
            return Err(PluginError::new(PluginErrorKind::UnknownField, "via"));
        }
    }
    Ok(())
}

#[derive(Clone)]
struct Bound {
    from: String,
    raw: String,
    requirement: VersionReq,
}

#[derive(Clone)]
struct Pending {
    id: String,
    raw: String,
    from: String,
    path: Vec<String>,
}

#[derive(Clone, Default)]
struct Selection<'a> {
    selected: BTreeMap<String, &'a InstalledPackage>,
    bounds: BTreeMap<String, Vec<Bound>>,
    pending: Vec<Pending>,
    edges: usize,
}

struct ResolveCtx<'a> {
    by_id: &'a BTreeMap<&'a str, Vec<&'a InstalledPackage>>,
    host: &'a Version,
    // Search work belongs to the whole request, never to a rollback snapshot.
    decisions: usize,
}

impl ResolveCtx<'_> {
    fn charge(&mut self) -> Result<(), PluginError> {
        if self.decisions == MAX_DECISIONS {
            return Err(budget("decision_nodes"));
        }
        self.decisions += 1;
        Ok(())
    }
}

pub fn resolve_installed(
    packages: &[InstalledPackage],
    request: &ResolveRequest,
) -> Result<GraphLock, PluginError> {
    let host = Version::parse(&request.host_runtime)
        .map_err(|_| PluginError::new(PluginErrorKind::ContractIncompatible, "host runtime"))?;
    let mut by_id: BTreeMap<&str, Vec<&InstalledPackage>> = BTreeMap::new();
    for package in packages {
        by_id
            .entry(package.manifest.id.as_str())
            .or_default()
            .push(package);
    }
    let mut ctx = ResolveCtx {
        by_id: &by_id,
        host: &host,
        decisions: 0,
    };
    if request.roots.len() > MAX_DECISIONS {
        return Err(budget("decision_nodes"));
    }
    let mut roots = request.roots.iter().collect::<Vec<_>>();
    roots.sort_by(|left, right| (&left.id, &left.version).cmp(&(&right.id, &right.version)));
    let mut selection = Selection::default();
    for root in roots.into_iter().rev() {
        ctx.charge()?;
        selection.pending.push(Pending {
            id: root.id.clone(),
            raw: root.version.clone(),
            from: "root".to_string(),
            path: Vec::new(),
        });
    }
    let ctx = search(&mut ctx, selection).map_err(|error| {
        if ctx.decisions == MAX_DECISIONS {
            budget("decision_nodes")
        } else {
            error
        }
    })?;
    if ctx.selected.len() > MAX_PACKAGES {
        return Err(budget("packages"));
    }
    let mut edges = Vec::new();
    for package in ctx.selected.values() {
        let from_entry = package.manifest.entry.export.clone();
        for dependency in &package.manifest.dependencies {
            let target = ctx.selected.get(&dependency.id).ok_or_else(|| {
                PluginError::new(PluginErrorKind::MissingDependency, dependency.id.clone())
            })?;
            let mut bindings = Vec::new();
            let mut to_entry = target.manifest.entry.export.clone();
            if let Some(contract) = package.manifest.effects.entries.get(&from_entry) {
                for delegated in &contract.delegated {
                    if delegated.dependency != dependency.alias {
                        continue;
                    }
                    to_entry = delegated.entry.clone();
                    for allowed in &delegated.allow {
                        bindings.push(ScopeBinding {
                            kind: allowed.kind.clone(),
                            scope: allowed.scope.clone(),
                            recovery: allowed.recovery.clone(),
                        });
                    }
                }
            }
            edges.push(LockedEdge {
                from: package.manifest.id.clone(),
                from_entry: from_entry.clone(),
                alias: dependency.alias.clone(),
                to: dependency.id.clone(),
                to_version: target.manifest.version.clone(),
                to_artifact_id: target.artifact_id.clone(),
                to_entry,
                relation: if target.manifest.kind == "library" {
                    "library"
                } else {
                    "plugin"
                }
                .to_string(),
                version_requirement: dependency.version.clone(),
                bindings,
            });
        }
    }
    edges.sort_by(|left, right| {
        (&left.from, &left.alias, &left.to, &left.to_entry).cmp(&(
            &right.from,
            &right.alias,
            &right.to,
            &right.to_entry,
        ))
    });
    if edges.len() > MAX_EDGES {
        return Err(budget("edges"));
    }
    let harness_selection = select_harness(&ctx.selected, &request.harness_selection)?;
    let mut closure = Vec::new();
    for package in ctx.selected.values() {
        let entry = package.manifest.entry.export.clone();
        let effects = entry_closure(&package.manifest.id, &entry, &ctx.selected, &mut Vec::new())?;
        closure.push(LockedEffect {
            package: package.manifest.id.clone(),
            entry,
            effects,
        });
    }
    if let HarnessSelection::ContextPrompt { policy, .. } = &harness_selection {
        closure.push(LockedEffect {
            package: policy.package_id.clone(),
            entry: policy.context_export.clone(),
            effects: vec![],
        });
        closure.push(LockedEffect {
            package: policy.package_id.clone(),
            entry: policy.guardian_export.clone(),
            effects: vec![],
        });
    }
    closure
        .sort_by(|left, right| (&left.package, &left.entry).cmp(&(&right.package, &right.entry)));
    let mut locked = ctx
        .selected
        .values()
        .map(|package| LockedPackage {
            id: package.manifest.id.clone(),
            version: package.manifest.version.clone(),
            kind: package.manifest.kind.clone(),
            artifact_id: package.artifact_id.clone(),
        })
        .collect::<Vec<_>>();
    locked.sort_by(|left, right| left.id.cmp(&right.id));
    let lock = GraphLock {
        graph_id: Uuid::new_v4().to_string(),
        harness_selection,
        host_runtime: request.host_runtime.clone(),
        compile_environment: COMPILE_ENVIRONMENT.to_string(),
        packages: locked,
        edges,
        closure,
    };
    super::schema::validate_lock(&lock.schema_value())?;
    Ok(lock)
}

pub(crate) fn select_harness(
    selected: &BTreeMap<String, &InstalledPackage>,
    request: &HarnessSelectionRequest,
) -> Result<HarnessSelection, PluginError> {
    let invalid = || {
        PluginError::new(
            PluginErrorKind::ContractIncompatible,
            "harness_policy_selection_invalid",
        )
    };
    let (tool, policy_request) = match request {
        HarnessSelectionRequest::Unselected => return Ok(HarnessSelection::Unselected),
        HarnessSelectionRequest::ToolOnly { tool_package } => (tool_package, None),
        HarnessSelectionRequest::ContextPrompt {
            tool_package,
            policy_package,
            prompt_export,
            context_export,
            guardian_export,
        } => (
            tool_package,
            Some((
                policy_package,
                prompt_export,
                context_export,
                guardian_export,
            )),
        ),
    };
    if !selected.contains_key(tool.as_str()) {
        return Err(invalid());
    }
    let Some((id, prompt, context, guardian)) = policy_request else {
        return Ok(HarnessSelection::ToolOnly {
            tool_package: tool.clone(),
        });
    };
    let tool_root = selected.get(tool).ok_or_else(invalid)?;
    if tool != crate::runtime::native_tools::EMBEDDING_PACKAGE_ID
        || tool_root.trust != super::PackageTrust::EmbeddingOwnedBuiltin
        || !tool_root.manifest.dependencies.is_empty()
    {
        return Err(invalid());
    }
    let p = selected.get(id).ok_or_else(invalid)?;
    let m = &p.manifest;
    if selected.len() != 2
        || tool == id
        || m.kind != "library"
        || m.contract != "agent.library/v1"
        || m.entry.export != *prompt
        || prompt == context
        || prompt == guardian
        || context == guardian
        || !super::manifest::safe_export(prompt)
        || !super::manifest::safe_export(context)
        || !super::manifest::safe_export(guardian)
        || m.state.is_some()
        || !m.dependencies.is_empty()
        || !m.capabilities.is_empty()
        || m.effects.entries.len() != 3
        || !m.effects.entries.contains_key(prompt)
        || !m.effects.entries.contains_key(context)
        || !m.effects.entries.contains_key(guardian)
        || m.effects
            .entries
            .values()
            .any(|e| !e.direct.is_empty() || !e.delegated.is_empty())
    {
        return Err(invalid());
    }
    Ok(HarnessSelection::ContextPrompt {
        tool_package: tool.clone(),
        policy: PurePolicySelection {
            package_id: id.clone(),
            artifact_id: p.artifact_id.clone(),
            entry_path: m.entry.path.clone(),
            prompt_export: prompt.clone(),
            context_export: context.clone(),
            guardian_export: guardian.clone(),
        },
    })
}

// Each recursive frame owns one newly selected package (at most MAX_PACKAGES).
// The pending continuation includes later roots as well as sibling dependencies.
// Snapshots contain only bounded graph state; the global work meter is not cloned.
fn search<'a>(
    ctx: &mut ResolveCtx<'a>,
    mut state: Selection<'a>,
) -> Result<Selection<'a>, PluginError> {
    while let Some(task) = state.pending.pop() {
        ctx.charge()?;
        let Pending {
            id,
            raw,
            from,
            mut path,
        } = task;
        if path.contains(&id) {
            path.push(id);
            return Err(PluginError {
                kind: PluginErrorKind::Cycle,
                chain: path,
            });
        }
        if path.len() == MAX_DEPTH {
            return Err(budget("depth"));
        }
        let requirement = VersionReq::parse(&raw)
            .map_err(|_| PluginError::new(PluginErrorKind::UnknownField, &raw))?;
        let bounds = state.bounds.entry(id.clone()).or_default();
        if !bounds
            .iter()
            .any(|bound| bound.from == from && bound.raw == raw)
        {
            bounds.push(Bound {
                from,
                raw,
                requirement: requirement.clone(),
            });
        }
        path.push(id.clone());
        if let Some(existing) = state.selected.get(&id).copied() {
            ctx.charge()?;
            let version = existing.manifest.parsed_version()?;
            if !requirement.matches(&version) {
                return Err(conflict(&id, &state.bounds[&id]));
            }
            // Revisit children along this path: selection alone cannot prove
            // absence of a cycle or a too-deep route through a shared DAG.
            enqueue(ctx, &mut state, existing, &path)?;
            continue;
        }
        let candidates = ctx
            .by_id
            .get(id.as_str())
            .ok_or_else(|| PluginError::new(PluginErrorKind::MissingDependency, &id))?;
        if candidates.len() > MAX_VERSIONS {
            return Err(budget("versions_per_package"));
        }
        let mut versions = BTreeSet::new();
        let mut matching = Vec::new();
        let mut host_mismatch = false;
        for candidate in candidates {
            ctx.charge()?;
            if !versions.insert(candidate.manifest.version.clone()) {
                return Err(PluginError::new(
                    PluginErrorKind::Ambiguous,
                    format!("{id} {}", candidate.manifest.version),
                ));
            }
            let version = candidate.manifest.parsed_version()?;
            let compatible = candidate.manifest.runtime_matches(ctx.host)?;
            host_mismatch |= !compatible;
            let mut matches = compatible;
            for bound in &state.bounds[&id] {
                ctx.charge()?;
                matches &= bound.requirement.matches(&version);
            }
            if matches {
                matching.push((version, *candidate));
            }
        }
        if matching.is_empty() {
            if state.bounds[&id].len() > 1 {
                return Err(conflict(&id, &state.bounds[&id]));
            }
            return Err(PluginError::new(
                if host_mismatch {
                    PluginErrorKind::ContractIncompatible
                } else {
                    PluginErrorKind::MissingDependency
                },
                &id,
            ));
        }
        matching.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| left.1.artifact_id.cmp(&right.1.artifact_id))
        });
        if state.selected.len() == MAX_PACKAGES {
            return Err(budget("packages"));
        }
        let mut first_failure = None;
        for (_, candidate) in matching {
            ctx.charge()?;
            let result = if state.edges + candidate.manifest.dependencies.len() > MAX_EDGES {
                Err(budget("edges"))
            } else {
                let mut branch = state.clone();
                branch.selected.insert(id.clone(), candidate);
                branch.edges += candidate.manifest.dependencies.len();
                enqueue(ctx, &mut branch, candidate, &path).and_then(|()| search(ctx, branch))
            };
            match result {
                Ok(solution) => return Ok(solution),
                Err(error) => {
                    // Metadata errors fail closed. Only graph-specific failures
                    // permit another candidate; exhausted work stops all branches.
                    if ctx.decisions == MAX_DECISIONS
                        || !matches!(
                            error.kind,
                            PluginErrorKind::Conflict
                                | PluginErrorKind::MissingDependency
                                | PluginErrorKind::ContractIncompatible
                                | PluginErrorKind::Cycle
                                | PluginErrorKind::BudgetExceeded
                        )
                    {
                        return Err(error);
                    }
                    first_failure.get_or_insert(error);
                }
            }
        }
        return Err(first_failure.expect("nonempty candidate list"));
    }
    Ok(state)
}

fn enqueue(
    ctx: &mut ResolveCtx<'_>,
    state: &mut Selection<'_>,
    package: &InstalledPackage,
    path: &[String],
) -> Result<(), PluginError> {
    let mut dependencies = package.manifest.dependencies.iter().collect::<Vec<_>>();
    dependencies.sort_by(|left, right| {
        (&left.id, &left.alias, &left.version).cmp(&(&right.id, &right.alias, &right.version))
    });
    for dependency in dependencies.into_iter().rev() {
        ctx.charge()?;
        state.pending.push(Pending {
            id: dependency.id.clone(),
            raw: dependency.version.clone(),
            from: package.manifest.id.clone(),
            path: path.to_vec(),
        });
    }
    Ok(())
}

fn entry_closure(
    package_id: &str,
    entry: &str,
    selected: &BTreeMap<String, &InstalledPackage>,
    stack: &mut Vec<(String, String)>,
) -> Result<Vec<LockedEffectItem>, PluginError> {
    if stack
        .iter()
        .any(|(id, name)| id == package_id && name == entry)
    {
        return Err(PluginError {
            kind: PluginErrorKind::Cycle,
            chain: stack
                .iter()
                .map(|(id, name)| format!("{id}::{name}"))
                .collect(),
        });
    }
    let package = selected
        .get(package_id)
        .ok_or_else(|| PluginError::new(PluginErrorKind::MissingDependency, package_id))?;
    let contract = package
        .manifest
        .effects
        .entries
        .get(entry)
        .ok_or_else(|| PluginError::new(PluginErrorKind::UncoveredExport, entry))?;
    if entry != package.manifest.entry.export {
        return Err(PluginError::new(PluginErrorKind::UncoveredExport, entry));
    }
    let mut effects = contract
        .direct
        .iter()
        .map(|effect| locked_direct(package, entry, effect))
        .collect::<Vec<_>>();
    stack.push((package_id.to_string(), entry.to_string()));
    for delegated in &contract.delegated {
        let dependency = package
            .manifest
            .dependencies
            .iter()
            .find(|item| item.alias == delegated.dependency)
            .ok_or_else(|| {
                PluginError::new(
                    PluginErrorKind::MissingDependency,
                    delegated.dependency.clone(),
                )
            })?;
        let callee_package = selected.get(&dependency.id).ok_or_else(|| {
            PluginError::new(PluginErrorKind::MissingDependency, dependency.id.clone())
        })?;
        if delegated.entry != callee_package.manifest.entry.export {
            return Err(PluginError::new(
                PluginErrorKind::UncoveredExport,
                delegated.entry.clone(),
            ));
        }
        let callee = entry_closure(&dependency.id, &delegated.entry, selected, stack)?;
        for effect in &callee {
            let covered = delegated.allow.iter().any(|allowed| {
                allowed.kind == effect.kind
                    && allowed.scope == effect.scope
                    && allowed.recovery == effect.recovery
            });
            if !covered {
                return Err(PluginError {
                    kind: PluginErrorKind::UndeclaredTransitiveEffect,
                    chain: vec![
                        package_id.to_string(),
                        dependency.id.clone(),
                        effect.kind.clone(),
                    ],
                });
            }
        }
        let relation = if callee_package.manifest.kind == "library" {
            "library"
        } else {
            "plugin"
        };
        for effect in callee {
            effects.push(LockedEffectItem {
                kind: effect.kind,
                scope: effect.scope,
                recovery: effect.recovery,
                via: EffectOrigin {
                    relation: relation.to_string(),
                    caller_package: package_id.to_string(),
                    caller_entry: entry.to_string(),
                    alias: dependency.alias.clone(),
                    callee_package: dependency.id.clone(),
                    callee_version: callee_package.manifest.version.clone(),
                    callee_entry: delegated.entry.clone(),
                    version_requirement: dependency.version.clone(),
                },
            });
        }
    }
    stack.pop();
    effects.sort_by(|left, right| {
        (
            &left.kind,
            &left.via.alias,
            &left.via.callee_package,
            &left.via.caller_entry,
        )
            .cmp(&(
                &right.kind,
                &right.via.alias,
                &right.via.callee_package,
                &right.via.caller_entry,
            ))
    });
    effects.dedup();
    Ok(effects)
}

fn locked_direct(
    package: &InstalledPackage,
    entry: &str,
    effect: &EffectRequirement,
) -> LockedEffectItem {
    LockedEffectItem {
        kind: effect.kind.clone(),
        scope: effect.scope.clone(),
        recovery: effect.recovery.clone(),
        via: EffectOrigin {
            relation: "direct".to_string(),
            caller_package: package.manifest.id.clone(),
            caller_entry: entry.to_string(),
            alias: String::new(),
            callee_package: package.manifest.id.clone(),
            callee_version: package.manifest.version.clone(),
            callee_entry: entry.to_string(),
            version_requirement: String::new(),
        },
    }
}

fn conflict(id: &str, bounds: &[Bound]) -> PluginError {
    PluginError {
        kind: PluginErrorKind::Conflict,
        chain: bounds
            .iter()
            .map(|bound| format!("{} requires {id} {}", bound.from, bound.raw))
            .collect(),
    }
}

fn budget(name: &str) -> PluginError {
    PluginError::new(PluginErrorKind::BudgetExceeded, name)
}

fn yaml_scalar(value: &str) -> String {
    if value.is_empty()
        || value
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '/')))
    {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod permission_diff_tests {
    use super::*;

    #[test]
    fn comparison_rejects_work_above_the_item_budget() {
        let mut graph = GraphLock {
            graph_id: "bounded".into(),
            harness_selection: HarnessSelection::Unselected,
            host_runtime: "0.1.0".into(),
            compile_environment: COMPILE_ENVIRONMENT.into(),
            packages: vec![],
            edges: vec![],
            closure: vec![],
        };
        let effect = LockedEffectItem {
            kind: "clock.read".into(),
            scope: "bound_run".into(),
            recovery: "none".into(),
            via: EffectOrigin {
                relation: "direct".into(),
                caller_package: "example".into(),
                caller_entry: "invoke".into(),
                alias: String::new(),
                callee_package: "example".into(),
                callee_version: "1.0.0".into(),
                callee_entry: "invoke".into(),
                version_requirement: String::new(),
            },
        };
        graph.closure.push(LockedEffect {
            package: "example".into(),
            entry: "invoke".into(),
            effects: vec![effect; 4097],
        });
        let result = compare_graph_permissions(&graph, &graph);
        assert!(
            format!("{result:?}").contains("BudgetExceeded"),
            "budget must precede deduplication"
        );
        assert_eq!(
            result.expect_err("over budget").kind,
            PluginErrorKind::BudgetExceeded
        );
        graph.closure[0].effects.pop();
        let at_limit = compare_graph_permissions(&graph, &graph).expect("exact limit accepted");
        assert!(!at_limit.requires_reapproval);
        assert!(at_limit.changes.is_empty());
    }

    #[test]
    fn matched_scope_changes_are_defensive_review_data() {
        // Deliberately bypasses persistence: the current catalog has only one
        // valid scope per kind. This tests comparison, not validator acceptance.
        let previous = GraphLock {
            graph_id: "old".into(),
            harness_selection: HarnessSelection::Unselected,
            host_runtime: "0.1.0".into(),
            compile_environment: COMPILE_ENVIRONMENT.into(),
            packages: vec![LockedPackage {
                id: "example".into(),
                version: "1.0.0".into(),
                kind: "tool".into(),
                artifact_id: "artifact".into(),
            }],
            edges: vec![],
            closure: vec![LockedEffect {
                package: "example".into(),
                entry: "invoke".into(),
                effects: vec![LockedEffectItem {
                    kind: "workspace.fs.read".into(),
                    scope: "bound_workspace".into(),
                    recovery: "none".into(),
                    via: EffectOrigin {
                        relation: "direct".into(),
                        caller_package: "example".into(),
                        caller_entry: "invoke".into(),
                        alias: String::new(),
                        callee_package: "example".into(),
                        callee_version: "1.0.0".into(),
                        callee_entry: "invoke".into(),
                        version_requirement: String::new(),
                    },
                }],
            }],
        };
        let mut candidate = previous.clone();
        candidate.closure[0].effects[0].scope = "defensive_other_scope".into();
        let diff = compare_graph_permissions(&previous, &candidate).expect("bounded diff");
        assert!(
            diff.requires_reapproval,
            "matched scope changes require review: {diff:?}"
        );
        assert!(format!("{diff:?}").contains("ScopeChanged"));
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].kind, PermissionChangeKind::ScopeChanged);
        assert_eq!(diff.changes[0].before[0].scope, "bound_workspace");
        assert_eq!(diff.changes[0].after[0].scope, "defensive_other_scope");
        assert_eq!(diff.compatibility, CompatibilityCheck::Unchecked);
        let reverse =
            compare_graph_permissions(&candidate, &previous).expect("bounded reverse diff");
        assert!(
            reverse.requires_reapproval,
            "scope inequality is conservative in both directions"
        );
        assert_eq!(reverse.compatibility, CompatibilityCheck::Unchecked);
    }
}
