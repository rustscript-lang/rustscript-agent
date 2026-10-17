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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageRequirement {
    pub id: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolveRequest {
    pub roots: Vec<PackageRequirement>,
    pub host_runtime: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedPackage {
    pub id: String,
    pub version: String,
    pub kind: String,
    pub artifact_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBinding {
    pub kind: String,
    pub scope: String,
    pub recovery: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub host_runtime: String,
    pub compile_environment: String,
    pub packages: Vec<LockedPackage>,
    pub edges: Vec<LockedEdge>,
    pub closure: Vec<LockedEffect>,
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

struct Bound {
    from: String,
    raw: String,
    requirement: VersionReq,
}

struct ResolveCtx<'a> {
    by_id: &'a BTreeMap<&'a str, Vec<&'a InstalledPackage>>,
    host: &'a Version,
    decisions: usize,
    selected: BTreeMap<String, &'a InstalledPackage>,
    bounds: BTreeMap<String, Vec<Bound>>,
    stack: Vec<String>,
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
        selected: BTreeMap::new(),
        bounds: BTreeMap::new(),
        stack: Vec::new(),
    };
    for root in &request.roots {
        visit(&mut ctx, root.id.as_str(), &root.version, "root")?;
    }
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
        host_runtime: request.host_runtime.clone(),
        compile_environment: COMPILE_ENVIRONMENT.to_string(),
        packages: locked,
        edges,
        closure,
    };
    super::schema::validate_lock(&lock.schema_value())?;
    Ok(lock)
}

fn visit(ctx: &mut ResolveCtx<'_>, id: &str, raw: &str, from: &str) -> Result<(), PluginError> {
    if ctx.stack.iter().any(|item| item == id) {
        let mut chain = ctx.stack.clone();
        chain.push(id.to_string());
        return Err(PluginError {
            kind: PluginErrorKind::Cycle,
            chain,
        });
    }
    let requirement =
        VersionReq::parse(raw).map_err(|_| PluginError::new(PluginErrorKind::UnknownField, raw))?;
    ctx.bounds.entry(id.to_string()).or_default().push(Bound {
        from: from.to_string(),
        raw: raw.to_string(),
        requirement,
    });
    if let Some(existing) = ctx.selected.get(id) {
        if !ctx.bounds[id].iter().all(|bound| {
            bound
                .requirement
                .matches(&existing.manifest.parsed_version().unwrap())
        }) {
            return Err(conflict(id, &ctx.bounds[id]));
        }
        return Ok(());
    }
    let candidates = ctx
        .by_id
        .get(id)
        .ok_or_else(|| PluginError::new(PluginErrorKind::MissingDependency, id))?;
    if candidates.len() > MAX_VERSIONS {
        return Err(budget("versions_per_package"));
    }
    ctx.decisions = ctx.decisions.saturating_add(candidates.len());
    if ctx.decisions > MAX_DECISIONS {
        return Err(budget("decision_nodes"));
    }
    let mut versions = BTreeSet::new();
    for candidate in candidates {
        if !versions.insert(candidate.manifest.version.clone()) {
            return Err(PluginError::new(
                PluginErrorKind::Ambiguous,
                format!("{id} {}", candidate.manifest.version),
            ));
        }
    }
    let mut matching = candidates
        .iter()
        .copied()
        .filter(|candidate| {
            let version = candidate.manifest.parsed_version().ok();
            version.is_some()
                && ctx.bounds[id]
                    .iter()
                    .all(|bound| bound.requirement.matches(version.as_ref().unwrap()))
                && candidate
                    .manifest
                    .runtime_matches(ctx.host)
                    .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        let host_mismatch = candidates
            .iter()
            .any(|candidate| candidate.manifest.runtime_matches(ctx.host).ok() == Some(false));
        if host_mismatch && ctx.bounds[id].len() == 1 {
            return Err(PluginError::new(PluginErrorKind::ContractIncompatible, id));
        }
        if ctx.bounds[id].len() > 1 {
            return Err(conflict(id, &ctx.bounds[id]));
        }
        return Err(PluginError::new(PluginErrorKind::MissingDependency, id));
    }
    matching.sort_by_key(|candidate| candidate.manifest.parsed_version().ok());
    let chosen = *matching.last().unwrap();
    if ctx.stack.len() + 1 > MAX_DEPTH {
        return Err(budget("depth"));
    }
    ctx.selected.insert(id.to_string(), chosen);
    ctx.stack.push(id.to_string());
    for dependency in &chosen.manifest.dependencies {
        visit(ctx, &dependency.id, &dependency.version, id)?;
    }
    ctx.stack.pop();
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
