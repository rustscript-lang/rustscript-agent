//! Explicit plugin manifest contract.
//!
//! Missing effects, unknown kinds, uncovered exports, and forged recovery are
//! rejected here. Nothing in this module grants a capability.

use std::collections::{BTreeMap, BTreeSet};

use semver::{Version, VersionReq};
use serde_json::Value;

use super::error::{PluginError, PluginErrorKind, capability_for, recovery_allowed, scope_for};
use super::yaml::strict_yaml_to_json;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectRequirement {
    pub kind: String,
    pub scope: String,
    pub recovery: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegatedCall {
    pub dependency: String,
    pub entry: String,
    pub allow: Vec<EffectRequirement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryEffects {
    pub direct: Vec<EffectRequirement>,
    pub delegated: Vec<DelegatedCall>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectContract {
    pub entries: BTreeMap<String, EntryEffects>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginDependency {
    pub alias: String,
    pub id: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginEntry {
    pub path: String,
    pub export: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateDeclaration {
    pub scope: String,
    pub schema: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginManifest {
    pub id: String,
    pub version: String,
    pub kind: String,
    pub publisher: String,
    pub runtime: String,
    pub contract: String,
    pub entry: PluginEntry,
    pub dependencies: Vec<PluginDependency>,
    pub capabilities: Vec<String>,
    pub effects: EffectContract,
    pub state: Option<StateDeclaration>,
}

impl PluginManifest {
    pub fn declared_capabilities(&self) -> Vec<String> {
        self.capabilities.clone()
    }

    pub(crate) fn parsed_version(&self) -> Result<Version, PluginError> {
        Version::parse(&self.version)
            .map_err(|_| PluginError::new(PluginErrorKind::UnknownField, "version"))
    }

    pub(crate) fn runtime_matches(&self, host: &Version) -> Result<bool, PluginError> {
        let requirement = VersionReq::parse(&self.runtime).map_err(|_| {
            PluginError::new(PluginErrorKind::ContractIncompatible, self.runtime.clone())
        })?;
        Ok(requirement.matches(host))
    }
}

pub fn parse_plugin_manifest(text: &str) -> Result<PluginManifest, PluginError> {
    let value = strict_yaml_to_json(text)?;
    super::schema::validate_manifest(&value)?;
    let object = value
        .as_object()
        .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "manifest"))?;
    for key in object.keys() {
        if !super::error::MANIFEST_FIELDS.contains(&key.as_str()) {
            return Err(PluginError::new(PluginErrorKind::UnknownField, key.clone()));
        }
    }
    require(object, "format", "rustscript.plugin/v1")?;
    require(object, "host_abi", "agent.cap/v1")?;
    if !object.contains_key("effects") {
        return Err(PluginError::new(PluginErrorKind::MissingEffects, "effects"));
    }
    let id = string_field(object, "id")?;
    if !valid_id(&id) {
        return Err(PluginError::new(PluginErrorKind::UnknownField, "id"));
    }
    let version = string_field(object, "version")?;
    Version::parse(&version)
        .map_err(|_| PluginError::new(PluginErrorKind::UnknownField, "version"))?;
    let kind = string_field(object, "kind")?;
    if !super::error::PLUGIN_KINDS.contains(&kind.as_str()) {
        return Err(PluginError::new(PluginErrorKind::UnknownField, "kind"));
    }
    let contract = string_field(object, "contract")?;
    let expected_contract = match kind.as_str() {
        "library" => "agent.library/v1",
        "tool" => "agent.tool/v1",
        _ => return Err(PluginError::new(PluginErrorKind::UnknownField, "kind")),
    };
    if contract != expected_contract {
        return Err(PluginError::new(
            PluginErrorKind::ContractIncompatible,
            contract,
        ));
    }
    let runtime = string_field(object, "runtime")?;
    VersionReq::parse(&runtime)
        .map_err(|_| PluginError::new(PluginErrorKind::UnknownField, "runtime"))?;
    let entry = parse_entry(
        object
            .get("entry")
            .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "entry"))?,
    )?;
    let dependencies = parse_dependencies(
        object
            .get("dependencies")
            .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "dependencies"))?,
    )?;
    let capabilities = parse_capabilities(
        object
            .get("capabilities")
            .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "capabilities"))?,
    )?;
    let effects = parse_effects(object.get("effects").unwrap(), &entry.export, &dependencies)?;
    let state = match object.get("state") {
        Some(value) => Some(parse_state(value)?),
        None => None,
    };
    let required = required_capabilities(&effects);
    if capabilities.iter().collect::<BTreeSet<_>>() != required.iter().collect::<BTreeSet<_>>() {
        return Err(PluginError::new(
            PluginErrorKind::ContractIncompatible,
            "capabilities",
        ));
    }
    let mut parts = id.split('.');
    let publisher = format!("{}.{}", parts.next().unwrap(), parts.next().unwrap());
    Ok(PluginManifest {
        id,
        version,
        kind,
        publisher,
        runtime,
        contract,
        entry,
        dependencies,
        capabilities,
        effects,
        state,
    })
}

fn required_capabilities(effects: &EffectContract) -> Vec<String> {
    let mut caps = BTreeSet::new();
    for entry in effects.entries.values() {
        for effect in &entry.direct {
            if let Some(cap) = capability_for(&effect.kind) {
                caps.insert(cap.to_string());
            }
        }
    }
    caps.into_iter().collect()
}

fn parse_entry(value: &Value) -> Result<PluginEntry, PluginError> {
    let object = value
        .as_object()
        .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "entry"))?;
    reject_unknown(object, &["path", "export"], "entry")?;
    let path = string_field(object, "path")?;
    let export = string_field(object, "export")?;
    if !safe_relative(&path) {
        return Err(PluginError::new(PluginErrorKind::PathEscape, path));
    }
    if !safe_export(&export) {
        return Err(PluginError::new(PluginErrorKind::UnknownField, "export"));
    }
    Ok(PluginEntry { path, export })
}

fn parse_dependencies(value: &Value) -> Result<Vec<PluginDependency>, PluginError> {
    let items = value
        .as_array()
        .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "dependencies"))?;
    let mut aliases = BTreeSet::new();
    let mut dependencies = Vec::new();
    for item in items {
        let object = item
            .as_object()
            .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "dependency"))?;
        reject_unknown(object, &["alias", "id", "version"], "dependency")?;
        let alias = string_field(object, "alias")?;
        let id = string_field(object, "id")?;
        let version = string_field(object, "version")?;
        if !safe_export(&alias) || !valid_id(&id) || VersionReq::parse(&version).is_err() {
            return Err(PluginError::new(
                PluginErrorKind::UnknownField,
                "dependency",
            ));
        }
        if !aliases.insert(alias.clone()) {
            return Err(PluginError::new(PluginErrorKind::DuplicateField, alias));
        }
        dependencies.push(PluginDependency { alias, id, version });
    }
    Ok(dependencies)
}

fn parse_capabilities(value: &Value) -> Result<Vec<String>, PluginError> {
    let items = value
        .as_array()
        .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "capabilities"))?;
    let mut capabilities = Vec::new();
    for item in items {
        let text = item
            .as_str()
            .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "capability"))?;
        if capability_for_name(text).is_none() {
            return Err(PluginError::new(PluginErrorKind::UnknownField, text));
        }
        capabilities.push(text.to_string());
    }
    capabilities.sort();
    if capabilities.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PluginError::new(
            PluginErrorKind::DuplicateField,
            "capabilities",
        ));
    }
    Ok(capabilities)
}

fn capability_for_name(name: &str) -> Option<&'static str> {
    [
        "workspace.read",
        "workspace.write",
        "process.spawn",
        "model.request",
        "remote.write",
        "clock.read",
        "event.emit",
        "delivery.send",
        "secret.use",
    ]
    .into_iter()
    .find(|item| *item == name)
}

fn parse_effects(
    value: &Value,
    export: &str,
    dependencies: &[PluginDependency],
) -> Result<EffectContract, PluginError> {
    let object = value
        .as_object()
        .ok_or_else(|| PluginError::new(PluginErrorKind::MissingEffects, "effects"))?;
    reject_unknown(object, &["contract", "entries"], "effects")?;
    require(object, "contract", "agent.effects/v1")?;
    let entries = object
        .get("entries")
        .and_then(Value::as_object)
        .ok_or_else(|| PluginError::new(PluginErrorKind::MissingEffects, "entries"))?;
    if !entries.contains_key(export) {
        return Err(PluginError::new(PluginErrorKind::UncoveredExport, export));
    }
    let mut parsed = BTreeMap::new();
    for (name, entry) in entries {
        if !safe_export(name) {
            return Err(PluginError::new(
                PluginErrorKind::UncoveredExport,
                name.clone(),
            ));
        }
        parsed.insert(name.clone(), parse_entry_effects(entry, dependencies)?);
    }
    Ok(EffectContract { entries: parsed })
}

fn parse_entry_effects(
    value: &Value,
    dependencies: &[PluginDependency],
) -> Result<EntryEffects, PluginError> {
    let object = value
        .as_object()
        .ok_or_else(|| PluginError::new(PluginErrorKind::MissingEffects, "entry effects"))?;
    reject_unknown(object, &["direct", "delegated"], "entry effects")?;
    let direct = object
        .get("direct")
        .and_then(Value::as_array)
        .ok_or_else(|| PluginError::new(PluginErrorKind::MissingEffects, "direct"))?;
    let delegated = object
        .get("delegated")
        .and_then(Value::as_array)
        .ok_or_else(|| PluginError::new(PluginErrorKind::MissingEffects, "delegated"))?;
    Ok(EntryEffects {
        direct: direct
            .iter()
            .map(parse_effect)
            .collect::<Result<Vec<_>, _>>()?,
        delegated: delegated
            .iter()
            .map(|item| parse_delegated(item, dependencies))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn parse_delegated(
    value: &Value,
    dependencies: &[PluginDependency],
) -> Result<DelegatedCall, PluginError> {
    let object = value
        .as_object()
        .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "delegated"))?;
    reject_unknown(object, &["dependency", "entry", "allow"], "delegated")?;
    let dependency = string_field(object, "dependency")?;
    let entry = string_field(object, "entry")?;
    if !dependencies.iter().any(|item| item.alias == dependency) || !safe_export(&entry) {
        return Err(PluginError::new(PluginErrorKind::UnknownField, dependency));
    }
    let allow = object
        .get("allow")
        .and_then(Value::as_array)
        .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "allow"))?;
    Ok(DelegatedCall {
        dependency,
        entry,
        allow: allow
            .iter()
            .map(parse_effect)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn parse_effect(value: &Value) -> Result<EffectRequirement, PluginError> {
    let object = value
        .as_object()
        .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownEffect, "effect"))?;
    reject_unknown(object, &["kind", "scope", "recovery"], "effect")?;
    let kind = string_field(object, "kind")?;
    let scope = string_field(object, "scope")?;
    let recovery = string_field(object, "recovery")?;
    if capability_for(&kind).is_none() {
        return Err(PluginError::new(PluginErrorKind::UnknownEffect, kind));
    }
    if scope_for(&kind) != Some(scope.as_str()) {
        return Err(PluginError::new(PluginErrorKind::UnknownEffect, scope));
    }
    if !recovery_allowed(&kind, &recovery) {
        return Err(PluginError::new(
            PluginErrorKind::ForgedRecovery,
            format!("{kind} {recovery}"),
        ));
    }
    Ok(EffectRequirement {
        kind,
        scope,
        recovery,
    })
}

fn parse_state(value: &Value) -> Result<StateDeclaration, PluginError> {
    let object = value
        .as_object()
        .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "state"))?;
    reject_unknown(object, &["scope", "schema"], "state")?;
    let scope = string_field(object, "scope")?;
    if scope != "run" {
        return Err(PluginError::new(
            PluginErrorKind::UnknownField,
            "state.scope",
        ));
    }
    let schema = object
        .get("schema")
        .and_then(Value::as_u64)
        .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "state.schema"))?;
    if schema < 1 {
        return Err(PluginError::new(
            PluginErrorKind::UnknownField,
            "state.schema",
        ));
    }
    Ok(StateDeclaration { scope, schema })
}

fn require(
    object: &serde_json::Map<String, Value>,
    key: &str,
    expected: &str,
) -> Result<(), PluginError> {
    let actual = string_field(object, key)?;
    if actual != expected {
        Err(PluginError::new(PluginErrorKind::UnknownField, key))
    } else {
        Ok(())
    }
}

fn string_field(object: &serde_json::Map<String, Value>, key: &str) -> Result<String, PluginError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, key))
}

fn reject_unknown(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> Result<(), PluginError> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(PluginError::new(
                PluginErrorKind::UnknownField,
                format!("{label}.{key}"),
            ));
        }
    }
    for key in allowed {
        if !object.contains_key(*key) {
            return Err(PluginError::new(
                PluginErrorKind::UnknownField,
                format!("{label}.{key}"),
            ));
        }
    }
    Ok(())
}

fn valid_id(id: &str) -> bool {
    let mut parts = id.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    [first, second].into_iter().chain(parts).all(safe_ident)
}

fn safe_ident(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit())
        && chars.all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        && !text.is_empty()
}

fn safe_export(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

pub(crate) fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        && path.split('/').all(|part| {
            part.chars().all(|character| {
                character.is_ascii_alphanumeric()
                    || character == '_'
                    || character == '-'
                    || character == '.'
            })
        })
}
