//! Bundled YAML schemas are the public structural contract.
//!
//! Native loads these files, validates duplicate-free JSON against them, then
//! applies stronger semantic and authority checks. Canonical JSON is a sorted
//! projection of the same YAML. It is not a second contract and not a digest.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use serde_json::{Map, Value};

use super::error::{PluginError, PluginErrorKind};
use super::yaml::strict_yaml_to_json;

const MANIFEST_SCHEMA: &str = include_str!("../../schemas/plugin-manifest.schema.yaml");
const EFFECT_SCHEMA: &str = include_str!("../../schemas/effect-contract.schema.yaml");
const LOCK_SCHEMA: &str = include_str!("../../schemas/plugin-graph-lock.schema.yaml");
const ACTIVATION_SCHEMA: &str = include_str!("../../schemas/plugin-activation.schema.yaml");
const GRAPH_REF_SCHEMA: &str = include_str!("../../schemas/plugin-graph-ref.schema.yaml");
const CHECKPOINT_SCHEMA: &str = include_str!("../../schemas/v1/checkpoint.schema.yaml");
const MANAGED_EFFECT_SCHEMA: &str = include_str!("../../schemas/managed-effect.schema.yaml");
const MANAGED_WORKSPACE_SCHEMA: &str = include_str!("../../schemas/managed-workspace.schema.yaml");
const MANAGED_CHECKPOINT_SCHEMA: &str =
    include_str!("../../schemas/managed-checkpoint.schema.yaml");
const MANAGED_RESTORE_SCHEMA: &str = include_str!("../../schemas/managed-restore.schema.yaml");

const SCHEMA_SOURCES: &[(&str, &str)] = &[
    ("plugin-manifest.schema.yaml", MANIFEST_SCHEMA),
    ("effect-contract.schema.yaml", EFFECT_SCHEMA),
    ("plugin-graph-lock.schema.yaml", LOCK_SCHEMA),
    ("plugin-activation.schema.yaml", ACTIVATION_SCHEMA),
    ("plugin-graph-ref.schema.yaml", GRAPH_REF_SCHEMA),
    ("checkpoint.schema.yaml", CHECKPOINT_SCHEMA),
    ("managed-effect.schema.yaml", MANAGED_EFFECT_SCHEMA),
    ("managed-workspace.schema.yaml", MANAGED_WORKSPACE_SCHEMA),
    ("managed-checkpoint.schema.yaml", MANAGED_CHECKPOINT_SCHEMA),
    ("managed-restore.schema.yaml", MANAGED_RESTORE_SCHEMA),
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
            "plugin-activation.schema.json" => {
                documents.insert("plugin-activation.schema.json", canonical)
            }
            "plugin-graph-ref.schema.json" => {
                documents.insert("plugin-graph-ref.schema.json", canonical)
            }
            "checkpoint.schema.json" => documents.insert("checkpoint.schema.json", canonical),
            "managed-effect.schema.json" => {
                documents.insert("managed-effect.schema.json", canonical)
            }
            "managed-workspace.schema.json" => {
                documents.insert("managed-workspace.schema.json", canonical)
            }
            "managed-checkpoint.schema.json" => {
                documents.insert("managed-checkpoint.schema.json", canonical)
            }
            "managed-restore.schema.json" => {
                documents.insert("managed-restore.schema.json", canonical)
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

pub(crate) fn validate_managed_effect(value: &Value) -> Result<(), PluginError> {
    validate_named("managed-effect.schema.yaml", value)
}

pub(crate) fn validate_managed_workspace(value: &Value) -> Result<(), PluginError> {
    validate_named("managed-workspace.schema.yaml", value)
}

pub(crate) fn validate_managed_maintenance(
    name: &str,
    definition: &str,
    value: &Value,
) -> Result<(), PluginError> {
    let prepared = prepared_schemas()?;
    let mut selected = prepared.values.get(name).cloned().ok_or_else(|| {
        PluginError::new(
            PluginErrorKind::ContractIncompatible,
            "managed schema unavailable",
        )
    })?;
    selected
        .as_object_mut()
        .expect("managed schema object")
        .remove("oneOf");
    if selected["$defs"].get(definition).is_none() {
        return Err(PluginError::new(
            PluginErrorKind::ContractIncompatible,
            "managed named body unavailable",
        ));
    }
    selected["$ref"] = Value::String(format!("#/$defs/{definition}"));
    let validator = jsonschema::options()
        .with_registry(&prepared.registry)
        .build(&selected)
        .map_err(|_| {
            PluginError::new(
                PluginErrorKind::ContractIncompatible,
                "managed schema invalid",
            )
        })?;
    validator.validate(value).map_err(|_| {
        PluginError::new(
            PluginErrorKind::ContractIncompatible,
            "managed schema rejected",
        )
    })
}

fn validate_named(name: &str, value: &Value) -> Result<(), PluginError> {
    let prepared = prepared_schemas()?;
    let selected = prepared
        .values
        .get(name)
        .ok_or_else(|| PluginError::new(PluginErrorKind::ContractIncompatible, name))?;
    let mut selected = selected.clone();
    if name == "managed-effect.schema.yaml" {
        selected
            .as_object_mut()
            .expect("bundled schema object")
            .remove("oneOf");
        selected["$ref"] = Value::String(
            if value.get("prepared_at_ms").is_some() {
                "#/$defs/prepared"
            } else {
                "#/$defs/record"
            }
            .into(),
        );
    }
    let validator = jsonschema::options()
        .with_registry(&prepared.registry)
        .build(&selected)
        .map_err(|err| PluginError::new(PluginErrorKind::ContractIncompatible, err.to_string()))?;
    let errors: Vec<_> = validator.iter_errors(value).collect();
    if errors.is_empty() {
        return Ok(());
    }
    Err(PluginError::new(
        classify(&errors),
        if name.starts_with("managed-") {
            format!("{name} rejected at {}", errors[0].instance_path())
        } else {
            format!("{name} {}", errors[0])
        },
    ))
}

/// Parsed bundled schema documents and their prepared registry. Both are a pure
/// function of `include_str!` inputs compiled into this binary, so the pair is
/// prepared once and shared read-only; every validation still parses the actual
/// incoming document and runs its own selected schema.
struct PreparedSchemas {
    values: BTreeMap<&'static str, Value>,
    registry: jsonschema::Registry<'static>,
}

static PREPARED_SCHEMAS: OnceLock<Result<PreparedSchemas, PluginError>> = OnceLock::new();

fn prepared_schemas() -> Result<&'static PreparedSchemas, PluginError> {
    PREPARED_SCHEMAS
        .get_or_init(|| {
            let values = bundled_values()?;
            let registry = registry(&values)?;
            Ok(PreparedSchemas { values, registry })
        })
        .as_ref()
        .map_err(|error| error.clone())
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
        "plugin-activation.schema.yaml" => {
            "https://schemas.rustscript.local/v1/plugin-activation.schema.yaml"
        }
        "plugin-graph-ref.schema.yaml" => {
            "https://schemas.rustscript.local/v1/plugin-graph-ref.schema.yaml"
        }
        "checkpoint.schema.yaml" => "https://rustscript.dev/schemas/v1/checkpoint.schema.yaml",
        "managed-effect.schema.yaml" => {
            "https://schemas.rustscript.local/v1/managed-effect.schema.yaml"
        }
        "managed-workspace.schema.yaml" => {
            "https://schemas.rustscript.local/v1/managed-workspace.schema.yaml"
        }
        "managed-checkpoint.schema.yaml" => {
            "https://schemas.rustscript.local/managed-checkpoint.schema.yaml"
        }
        "managed-restore.schema.yaml" => {
            "https://schemas.rustscript.local/managed-restore.schema.yaml"
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
    use super::super::error::{
        EFFECT_KINDS, PluginErrorKind, capability_for, recovery_allowed, scope_for,
    };
    use super::{prepared_schemas, validate_lock, validate_managed_maintenance, validate_manifest};
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

    #[test]
    fn bundled_schema_material_is_prepared_once_and_isolated_from_managed_selection() {
        let first = prepared_schemas().expect("bundled schema values and registry");
        let second = prepared_schemas().expect("bundled schema values and registry");
        assert!(
            std::ptr::eq(first, second),
            "immutable bundled schema material must be shared, not rebuilt"
        );
        let effect_before = first.values["managed-effect.schema.yaml"].clone();
        let manifest_before = first.values["plugin-manifest.schema.yaml"].clone();

        // The managed path removes `oneOf` and rewrites `$ref` on a selected
        // copy; the shared documents must stay untouched across interleavings.
        let unknown_name =
            validate_managed_maintenance("missing.schema.yaml", "Record", &json!({}))
                .expect_err("unknown managed schema name");
        assert_eq!(unknown_name.kind, PluginErrorKind::ContractIncompatible);
        assert_eq!(
            unknown_name.chain,
            vec!["managed schema unavailable".to_string()]
        );
        let unknown_body = validate_managed_maintenance(
            "managed-checkpoint.schema.yaml",
            "UnknownDefinition",
            &json!({}),
        )
        .expect_err("unknown named body");
        assert_eq!(unknown_body.kind, PluginErrorKind::ContractIncompatible);
        assert_eq!(
            unknown_body.chain,
            vec!["managed named body unavailable".to_string()]
        );
        let rejected = validate_managed_maintenance(
            "managed-checkpoint.schema.yaml",
            "ManagedCheckpointCreateRequest",
            &json!({"unexpected_authority": true}),
        )
        .expect_err("invalid managed body");
        assert_eq!(rejected.kind, PluginErrorKind::ContractIncompatible);
        assert_eq!(rejected.chain, vec!["managed schema rejected".to_string()]);

        assert_eq!(first.values["managed-effect.schema.yaml"], effect_before);
        assert_eq!(first.values["plugin-manifest.schema.yaml"], manifest_before);
        let effect_now = prepared_schemas().expect("bundled schema values and registry");
        assert!(std::ptr::eq(first, effect_now));
        assert!(
            effect_now.values["managed-effect.schema.yaml"]
                .get("oneOf")
                .is_some(),
            "managed selection must not remove oneOf from the shared document"
        );

        // Ordinary validation still runs its own selected schema on the shared
        // registry after the managed interleaving.
        validate_manifest(&sample("workspace.fs.read", "bound_workspace", "none"))
            .expect("valid manifest after managed selection");

        let mut escape = sample("workspace.fs.read", "bound_workspace", "none");
        escape["entry"]["path"] = json!("../escape.rss");
        assert_eq!(
            validate_manifest(&escape).expect_err("path escape").kind,
            PluginErrorKind::PathEscape
        );
        let mut forged_recovery = sample("workspace.fs.read", "bound_workspace", "none");
        forged_recovery["effects"]["entries"]["invoke"]["direct"][0]["recovery"] = json!("replay");
        assert_eq!(
            validate_manifest(&forged_recovery)
                .expect_err("forged recovery")
                .kind,
            PluginErrorKind::ForgedRecovery
        );
        let mut unknown_effect = sample("workspace.fs.read", "bound_workspace", "none");
        unknown_effect["effects"]["entries"]["invoke"]["direct"][0]["kind"] =
            json!("workspace.exec");
        assert_eq!(
            validate_manifest(&unknown_effect)
                .expect_err("unknown effect")
                .kind,
            PluginErrorKind::UnknownEffect
        );
        let mut missing_effects = sample("workspace.fs.read", "bound_workspace", "none");
        missing_effects
            .as_object_mut()
            .expect("manifest object")
            .remove("effects");
        assert_eq!(
            validate_manifest(&missing_effects)
                .expect_err("missing effects")
                .kind,
            PluginErrorKind::MissingEffects
        );
        let lock_error = validate_lock(&json!({})).expect_err("empty lock rejected");
        assert_eq!(lock_error.kind, PluginErrorKind::UnknownField);
        assert!(lock_error.chain[0].starts_with("plugin-graph-lock.schema.yaml "));
    }
}
