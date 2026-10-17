//! Typed plugin-contract failures.
//!
//! A signature, publisher record, or graph id never becomes a capability grant.
//! These errors name the failed boundary and the shortest package chain.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginErrorKind {
    DuplicateField,
    YamlAlias,
    YamlTag,
    YamlMerge,
    MissingEffects,
    UnknownEffect,
    ForgedRecovery,
    UncoveredExport,
    UnknownField,
    PathEscape,
    SymlinkDenied,
    PublisherUnauthorized,
    VersionOverwrite,
    MissingDependency,
    Conflict,
    Cycle,
    Ambiguous,
    BudgetExceeded,
    UndeclaredTransitiveEffect,
    UndeclaredDirectEffect,
    UnauthorizedHostImport,
    PluginBoundaryBypass,
    ContractIncompatible,
    CompileFailed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginError {
    pub kind: PluginErrorKind,
    pub chain: Vec<String>,
}

impl PluginError {
    pub(crate) fn new(kind: PluginErrorKind, item: impl Into<String>) -> Self {
        Self {
            kind,
            chain: vec![item.into()],
        }
    }
}

impl fmt::Display for PluginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.chain.join(" -> "))
    }
}

pub const PLUGIN_KINDS: &[&str] = &["library", "tool"];

pub const EFFECT_KINDS: &[&str] = &[
    "workspace.fs.read",
    "workspace.fs.write",
    "process.spawn",
    "model.request",
    "remote.write",
    "clock.read",
    "event.emit",
    "delivery.send",
    "secret.use",
];

pub const EFFECT_RECOVERY: &[&str] = &["none", "checkpoint"];

pub const MANIFEST_FIELDS: &[&str] = &[
    "capabilities",
    "contract",
    "dependencies",
    "effects",
    "entry",
    "format",
    "host_abi",
    "id",
    "kind",
    "runtime",
    "state",
    "version",
];

pub const GRAPH_LOCK_FIELDS: &[&str] = &[
    "closure",
    "compile_environment",
    "edges",
    "graph_id",
    "host_runtime",
    "packages",
];

pub const HOST_RUNTIME: &str = "0.1.0";
pub const COMPILE_ENVIRONMENT: &str = "closed-bundle/agent.cap/v1";

pub(crate) fn capability_for(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "workspace.fs.read" => "workspace.read",
        "workspace.fs.write" => "workspace.write",
        "process.spawn" => "process.spawn",
        "model.request" => "model.request",
        "remote.write" => "remote.write",
        "clock.read" => "clock.read",
        "event.emit" => "event.emit",
        "delivery.send" => "delivery.send",
        "secret.use" => "secret.use",
        _ => return None,
    })
}

pub(crate) fn scope_for(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "workspace.fs.read" | "workspace.fs.write" => "bound_workspace",
        "process.spawn" => "bound_process",
        "model.request" | "remote.write" | "clock.read" | "event.emit" => "bound_run",
        "delivery.send" => "bound_delivery",
        "secret.use" => "bound_secret",
        _ => return None,
    })
}

pub(crate) fn recovery_allowed(kind: &str, recovery: &str) -> bool {
    match (kind, recovery) {
        ("workspace.fs.write", "none" | "checkpoint") => true,
        (_, "none") => scope_for(kind).is_some(),
        _ => false,
    }
}
