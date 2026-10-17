//! Bundled YAML schemas are the public structural contract.
//!
//! Native loads these files, validates duplicate-free JSON against them, then
//! applies stronger semantic and authority checks. Canonical JSON is a sorted
//! projection of the same YAML. It is not a second contract and not a digest.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use super::error::{PluginError, PluginErrorKind};
use super::yaml::strict_yaml_to_json;

const MANIFEST_SCHEMA: &str = include_str!("../../schemas/plugin-manifest.schema.yaml");
const EFFECT_SCHEMA: &str = include_str!("../../schemas/effect-contract.schema.yaml");
const LOCK_SCHEMA: &str = include_str!("../../schemas/plugin-graph-lock.schema.yaml");

const SCHEMA_SOURCES: &[(&str, &str)] = &[
    ("plugin-manifest.schema.yaml", MANIFEST_SCHEMA),
    ("effect-contract.schema.yaml", EFFECT_SCHEMA),
    ("plugin-graph-lock.schema.yaml", LOCK_SCHEMA),
];

pub fn canonical_schema_documents() -> Result<BTreeMap<&'static str, String>, PluginError> {
    let mut documents = BTreeMap::new();
    for (name, text) in SCHEMA_SOURCES {
        let json_name = name.replace(".yaml", ".json");
        let value = strict_yaml_to_json(text)?;
        let canonical = canonical_json(&value);
        match json_name.as_str() {
            "plugin-manifest.schema.json" => {
                documents.insert("plugin-manifest.schema.json", canonical)
            }
            "effect-contract.schema.json" => {
                documents.insert("effect-contract.schema.json", canonical)
            }
            "plugin-graph-lock.schema.json" => {
                documents.insert("plugin-graph-lock.schema.json", canonical)
            }
            _ => None,
        };
    }
    Ok(documents)
}

pub fn schema_snapshot_drift(dir: &Path) -> Result<(), String> {
    let documents = canonical_schema_documents().map_err(|err| err.to_string())?;
    for (name, expected) in documents {
        let path = dir.join(name);
        let actual = fs::read_to_string(&path).map_err(|err| format!("missing {name}: {err}"))?;
        if actual != expected {
            return Err(format!("schema snapshot drifted: {name}"));
        }
    }
    Ok(())
}

pub(crate) fn validate_manifest(value: &Value) -> Result<(), PluginError> {
    validate_named("plugin-manifest.schema.yaml", value)
}

pub(crate) fn validate_lock(value: &Value) -> Result<(), PluginError> {
    validate_named("plugin-graph-lock.schema.yaml", value)
}

fn validate_named(name: &str, value: &Value) -> Result<(), PluginError> {
    let schemas = bundled_values()?;
    let registry = registry(&schemas)?;
    let selected = schemas
        .get(name)
        .ok_or_else(|| PluginError::new(PluginErrorKind::ContractIncompatible, name))?;
    let validator = jsonschema::options()
        .with_registry(&registry)
        .build(selected)
        .map_err(|err| PluginError::new(PluginErrorKind::ContractIncompatible, err.to_string()))?;
    let errors: Vec<_> = validator.iter_errors(value).collect();
    if errors.is_empty() {
        return Ok(());
    }
    Err(PluginError::new(
        classify(&errors),
        format!("{name} {}", errors[0]),
    ))
}

fn bundled_values() -> Result<BTreeMap<&'static str, Value>, PluginError> {
    let mut values = BTreeMap::new();
    for (name, text) in SCHEMA_SOURCES {
        values.insert(*name, strict_yaml_to_json(text)?);
    }
    Ok(values)
}

fn registry(
    schemas: &BTreeMap<&'static str, Value>,
) -> Result<jsonschema::Registry<'static>, PluginError> {
    let mut building = jsonschema::Registry::new();
    for (name, value) in schemas {
        building = building
            .add(schema_uri(name), value.clone())
            .map_err(|err| {
                PluginError::new(PluginErrorKind::ContractIncompatible, err.to_string())
            })?;
    }
    building
        .prepare()
        .map_err(|err| PluginError::new(PluginErrorKind::ContractIncompatible, err.to_string()))
}

fn schema_uri(name: &str) -> &'static str {
    match name {
        "plugin-manifest.schema.yaml" => {
            "https://schemas.rustscript.local/v1/plugin-manifest.schema.yaml"
        }
        "effect-contract.schema.yaml" => {
            "https://schemas.rustscript.local/v1/effect-contract.schema.yaml"
        }
        "plugin-graph-lock.schema.yaml" => {
            "https://schemas.rustscript.local/v1/plugin-graph-lock.schema.yaml"
        }
        _ => "https://schemas.rustscript.local/v1/unknown",
    }
}

fn classify(errors: &[jsonschema::ValidationError<'_>]) -> PluginErrorKind {
    let kinds: Vec<_> = errors.iter().map(classify_one).collect();
    for preferred in [
        PluginErrorKind::ForgedRecovery,
        PluginErrorKind::PathEscape,
        PluginErrorKind::MissingEffects,
        PluginErrorKind::UncoveredExport,
        PluginErrorKind::UnknownEffect,
        PluginErrorKind::UnknownField,
    ] {
        if kinds.contains(&preferred) {
            return preferred;
        }
    }
    PluginErrorKind::UnknownField
}

fn classify_one(err: &jsonschema::ValidationError<'_>) -> PluginErrorKind {
    let path = err.instance_path().to_string();
    let keyword = err.kind().keyword();
    if path.contains("recovery") {
        return PluginErrorKind::ForgedRecovery;
    }
    if path.ends_with("/path") && (keyword == "pattern" || keyword == "minLength") {
        return PluginErrorKind::PathEscape;
    }
    if keyword == "required" && err.to_string().contains("effects") {
        return PluginErrorKind::MissingEffects;
    }
    if path.contains("entries") && (keyword == "maxProperties" || keyword == "additionalProperties")
    {
        return PluginErrorKind::UncoveredExport;
    }
    if path.contains("/effects") && (path.ends_with("/kind") || path.ends_with("/scope")) {
        return PluginErrorKind::UnknownEffect;
    }
    PluginErrorKind::UnknownField
}

fn canonical_json(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(&sort_value(value)).expect("schema json");
    text.push('\n');
    text
}

fn sort_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut sorted = Map::new();
            for key in keys {
                sorted.insert(key.clone(), sort_value(&map[&key]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::error::{EFFECT_KINDS, capability_for, recovery_allowed, scope_for};
    use super::validate_manifest;
    use serde_json::json;

    fn sample(kind: &str, scope: &str, recovery: &str) -> serde_json::Value {
        let capability = capability_for(kind).unwrap_or("workspace.read");
        json!({
            "format": "rustscript.plugin/v1",
            "id": "org.rustscript.tools.sample",
            "version": "1.0.0",
            "kind": "tool",
            "runtime": ">=0.1.0, <0.2.0",
            "contract": "agent.tool/v1",
            "host_abi": "agent.cap/v1",
            "entry": {"path": "invoke.rss", "export": "invoke"},
            "dependencies": [],
            "capabilities": [capability],
            "effects": {
                "contract": "agent.effects/v1",
                "entries": {
                    "invoke": {
                        "direct": [{"kind": kind, "scope": scope, "recovery": recovery}],
                        "delegated": []
                    }
                }
            }
        })
    }

    #[test]
    fn recovery_and_scope_matrix_matches_native_allowance() {
        for kind in EFFECT_KINDS {
            let scope = scope_for(kind).unwrap();
            for recovery in ["none", "checkpoint", "replay"] {
                let accepted = validate_manifest(&sample(kind, scope, recovery)).is_ok();
                assert_eq!(
                    accepted,
                    recovery_allowed(kind, recovery),
                    "{kind} {recovery}"
                );
            }
            let wrong_scope = if scope == "bound_run" {
                "bound_workspace"
            } else {
                "bound_run"
            };
            assert!(
                validate_manifest(&sample(kind, wrong_scope, "none")).is_err(),
                "{kind} must not accept scope {wrong_scope}"
            );
        }
    }
}
