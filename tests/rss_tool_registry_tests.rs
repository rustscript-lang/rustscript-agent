use std::collections::HashSet;
use std::path::PathBuf;

use rustscript_agent::{AgentConfig, AgentRunner, ToolRegistry};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

fn registry_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/tools/registry.rss")
}

fn registry_runner() -> AgentRunner {
    AgentRunner::from_file(registry_path(), AgentConfig::default())
        .expect("RSS tool registry entry should compile")
}

fn json_to_vm_value(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(value) => Value::Bool(*value),
        JsonValue::Number(value) => {
            if let Some(value) = value.as_i64() {
                Value::Int(value)
            } else {
                Value::Float(value.as_f64().expect("finite json number"))
            }
        }
        JsonValue::String(value) => Value::string(value),
        JsonValue::Array(values) => Value::Array(std::sync::Arc::new(
            values.iter().map(json_to_vm_value).collect::<Vec<_>>(),
        )),
        JsonValue::Object(entries) => Value::map(
            entries
                .iter()
                .map(|(key, value)| (Value::string(key), json_to_vm_value(value)))
                .collect(),
        ),
    }
}

fn vm_value_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Int(value) => json!(value),
        Value::Float(value) => serde_json::Number::from_f64(*value)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Value::Bool(value) => json!(value),
        Value::String(value) => JsonValue::String(value.to_string()),
        Value::Bytes(value) => JsonValue::String(String::from_utf8_lossy(value).into_owned()),
        Value::Array(values) => JsonValue::Array(values.iter().map(vm_value_to_json).collect()),
        Value::Map(entries) => JsonValue::Object(
            entries
                .iter()
                .map(|(key, value)| (vm_map_key_to_string(key), vm_value_to_json(value)))
                .collect(),
        ),
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn vm_map_key_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.to_string(),
        other => vm_value_to_json(other).to_string(),
    }
}

fn run_registry(kind: &str, config: JsonValue) -> JsonValue {
    let runner = registry_runner();
    let context = json_to_vm_value(&json!({
        "kind": kind,
        "config": config,
    }));
    let result = runner
        .run_with_context(context)
        .unwrap_or_else(|error| panic!("RSS tool registry {kind} failed: {error:?}"));
    vm_value_to_json(&result)
}

#[test]
fn rss_registry_exports_the_canonical_tool_order() {
    let result = run_registry("descriptors", json!({}));
    let names: Vec<_> = result["descriptors"]
        .as_array()
        .expect("RSS registry should return descriptors")
        .iter()
        .map(|descriptor| descriptor["name"].as_str().unwrap_or_default())
        .collect();

    assert_eq!(
        names,
        [
            "read_file",
            "search_files",
            "write_file",
            "patch",
            "terminal",
            "process",
        ]
    );
}

#[test]
fn rss_registry_preserves_the_current_public_descriptor_contract() {
    let result = run_registry("descriptors", json!({}));
    let descriptors = result["descriptors"]
        .as_array()
        .expect("RSS registry should return descriptors");
    let current = ToolRegistry::builtin()
        .expect("built-in registry should be valid")
        .snapshot()
        .schemas();

    assert_eq!(JsonValue::Array(descriptors.clone()), current);
}

#[test]
fn rss_registry_exports_deterministic_identity_input() {
    let first = run_registry("identity", json!({}));
    let second = run_registry("identity", json!({}));

    assert_eq!(first["ok"], json!(true));
    assert_eq!(
        first["identity"]["version"],
        json!("tool-registry-identity-v1")
    );
    assert_eq!(
        first["identity"]["descriptors"],
        run_registry("descriptors", json!({}))["descriptors"]
    );
    assert_eq!(first["identity"], second["identity"]);
}

fn extra_rss_tool() -> JsonValue {
    json!({
        "name": "echo_fixture",
        "description": "Fixture-only RSS tool",
        "toolset": "coding",
        "risk_class": "read",
        "schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"}
            },
            "required": ["text"],
            "additionalProperties": false
        }
    })
}

#[test]
fn rss_registry_accepts_an_extra_rss_only_tool_without_rust_executor_changes() {
    let config = json!({
        "extra_descriptors": [extra_rss_tool()]
    });
    let result = run_registry("descriptors", config.clone());
    let names: Vec<_> = result["descriptors"]
        .as_array()
        .expect("RSS registry should return descriptors")
        .iter()
        .map(|descriptor| descriptor["name"].as_str().unwrap_or_default())
        .collect();

    assert_eq!(
        names,
        [
            "read_file",
            "search_files",
            "write_file",
            "patch",
            "terminal",
            "process",
            "echo_fixture",
        ]
    );
    assert_eq!(result["descriptors"][6], extra_rss_tool());

    let identity = run_registry("identity", config);
    assert_ne!(
        identity["identity"],
        run_registry("identity", json!({}))["identity"]
    );
    assert_eq!(
        identity["identity"]["descriptors"][6]["name"],
        json!("echo_fixture")
    );
}

fn descriptor_names(result: &JsonValue) -> Vec<&str> {
    result["descriptors"]
        .as_array()
        .expect("RSS registry should return descriptors")
        .iter()
        .map(|descriptor| descriptor["name"].as_str().unwrap_or_default())
        .collect()
}

#[test]
fn rss_registry_filters_descriptors_by_enabled_toolsets() {
    assert_eq!(
        descriptor_names(&run_registry(
            "descriptors",
            json!({ "enabled_toolsets": ["coding"] })
        )),
        ["read_file", "search_files", "write_file", "patch"]
    );
    assert_eq!(
        descriptor_names(&run_registry(
            "descriptors",
            json!({ "enabled_toolsets": ["process"] })
        )),
        ["terminal", "process"]
    );
    assert_eq!(
        descriptor_names(&run_registry(
            "descriptors",
            json!({
                "enabled_toolsets": ["process"],
                "extra_descriptors": [extra_rss_tool()]
            })
        )),
        ["terminal", "process"]
    );
    assert_eq!(
        descriptor_names(&run_registry(
            "descriptors",
            json!({
                "enabled_toolsets": ["coding"],
                "extra_descriptors": [extra_rss_tool()]
            })
        )),
        [
            "read_file",
            "search_files",
            "write_file",
            "patch",
            "echo_fixture"
        ]
    );
}

#[test]
fn rss_registry_rejects_duplicate_names() {
    let result = run_registry(
        "validate",
        json!({
            "extra_descriptors": [extra_rss_tool(), extra_rss_tool()]
        }),
    );
    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["code"], json!("duplicate_name"));
    assert_eq!(result["name"], json!("echo_fixture"));
}

fn extra_tool_named(name: &str) -> JsonValue {
    let mut tool = extra_rss_tool();
    tool["name"] = json!(name);
    tool
}

fn extra_tools(count: usize) -> Vec<JsonValue> {
    (0..count)
        .map(|index| extra_tool_named(&format!("extra_{index}")))
        .collect()
}

#[test]
fn rss_registry_enforces_count_and_field_limits() {
    assert_eq!(run_registry("validate", json!({}))["ok"], json!(true));

    let too_many = run_registry("validate", json!({ "extra_descriptors": extra_tools(59) }));
    assert_eq!(too_many["ok"], json!(false));
    assert_eq!(too_many["code"], json!("too_many_entries"));
    assert_eq!(too_many["limit"], json!(64));

    let within_count = run_registry("validate", json!({ "extra_descriptors": extra_tools(58) }));
    assert_eq!(within_count["ok"], json!(true));

    let long_name = run_registry(
        "validate",
        json!({ "extra_descriptors": [extra_tool_named(&"a".repeat(65))] }),
    );
    assert_eq!(long_name["ok"], json!(false));
    assert_eq!(long_name["code"], json!("tool_name_too_long"));
    assert_eq!(long_name["limit"], json!(64));

    let accepted_name = run_registry(
        "validate",
        json!({ "extra_descriptors": [extra_tool_named(&"a".repeat(64))] }),
    );
    assert_eq!(accepted_name["ok"], json!(true));

    let mut empty_name = extra_rss_tool();
    empty_name["name"] = json!("");
    let empty_name = run_registry("validate", json!({ "extra_descriptors": [empty_name] }));
    assert_eq!(empty_name["ok"], json!(false));
    assert_eq!(empty_name["code"], json!("empty_name"));

    let mut long_description = extra_rss_tool();
    long_description["description"] = json!("d".repeat(4097));
    let long_description = run_registry(
        "validate",
        json!({ "extra_descriptors": [long_description] }),
    );
    assert_eq!(long_description["ok"], json!(false));
    assert_eq!(long_description["code"], json!("description_too_long"));
    assert_eq!(long_description["limit"], json!(4096));

    let mut empty_description = extra_rss_tool();
    empty_description["description"] = json!("");
    let empty_description = run_registry(
        "validate",
        json!({ "extra_descriptors": [empty_description] }),
    );
    assert_eq!(empty_description["ok"], json!(false));
    assert_eq!(empty_description["code"], json!("empty_description"));

    let mut large_schema = extra_rss_tool();
    large_schema["schema"] = json!({ "description": "x".repeat(65_537) });
    let large_schema = run_registry("validate", json!({ "extra_descriptors": [large_schema] }));
    assert_eq!(large_schema["ok"], json!(false));
    assert_eq!(large_schema["code"], json!("schema_too_large"));
    assert_eq!(large_schema["limit"], json!(65536));
}

fn run_registry_find(name: &str, config: JsonValue) -> JsonValue {
    let runner = registry_runner();
    let context = json_to_vm_value(&json!({
        "kind": "find",
        "name": name,
        "config": config,
    }));
    let result = runner
        .run_with_context(context)
        .unwrap_or_else(|error| panic!("RSS tool registry find failed: {error:?}"));
    vm_value_to_json(&result)
}

#[test]
fn rss_registry_finds_enabled_descriptors_by_name() {
    let found = run_registry_find("write_file", json!({}));
    assert_eq!(found["ok"], json!(true));
    assert_eq!(found["descriptor"]["name"], json!("write_file"));
    assert_eq!(found["descriptor"]["toolset"], json!("coding"));

    let missing = run_registry_find("echo_fixture", json!({}));
    assert_eq!(missing["ok"], json!(true));
    assert_eq!(missing["descriptor"], json!({}));

    let extra = run_registry_find(
        "echo_fixture",
        json!({ "extra_descriptors": [extra_rss_tool()] }),
    );
    assert_eq!(extra["descriptor"], extra_rss_tool());

    let disabled = run_registry_find("terminal", json!({ "enabled_toolsets": ["coding"] }));
    assert_eq!(disabled["descriptor"], json!({}));
}

#[test]
fn rss_registry_rejects_unsupported_enablement_metadata() {
    let mut unknown_toolset = extra_rss_tool();
    unknown_toolset["toolset"] = json!("browser");
    let unknown_toolset = run_registry(
        "validate",
        json!({ "extra_descriptors": [unknown_toolset] }),
    );
    assert_eq!(unknown_toolset["ok"], json!(false));
    assert_eq!(unknown_toolset["code"], json!("unsupported_toolset"));
    assert_eq!(unknown_toolset["name"], json!("echo_fixture"));

    let mut unknown_risk = extra_rss_tool();
    unknown_risk["risk_class"] = json!("network");
    let unknown_risk = run_registry("validate", json!({ "extra_descriptors": [unknown_risk] }));
    assert_eq!(unknown_risk["ok"], json!(false));
    assert_eq!(unknown_risk["code"], json!("unsupported_risk_class"));
    assert_eq!(unknown_risk["name"], json!("echo_fixture"));
}

fn generic_structural_bounds(descriptors: &[JsonValue]) -> Result<(), String> {
    const MAX_ENTRIES: usize = 64;
    const MAX_NAME_BYTES: usize = 64;
    const MAX_DESCRIPTION_BYTES: usize = 4096;
    const MAX_SCHEMA_BYTES: usize = 65536;

    if descriptors.len() > MAX_ENTRIES {
        return Err(format!(
            "tool registry exceeds the {MAX_ENTRIES}-entry limit"
        ));
    }

    let mut seen = HashSet::new();
    for descriptor in descriptors {
        let name = descriptor["name"].as_str().unwrap_or_default();
        if name.is_empty() {
            return Err("tool descriptor name must not be empty".to_string());
        }
        if name.len() > MAX_NAME_BYTES {
            return Err("tool name exceeds the byte limit".to_string());
        }
        if !seen.insert(name) {
            return Err(format!("duplicate tool name {name}"));
        }

        let description = descriptor["description"].as_str().unwrap_or_default();
        if description.is_empty() {
            return Err("tool descriptor must have a description".to_string());
        }
        if description.len() > MAX_DESCRIPTION_BYTES {
            return Err("tool description exceeds the byte limit".to_string());
        }

        let schema_bytes = serde_json::to_vec(&descriptor["schema"])
            .map_err(|error| error.to_string())?
            .len();
        if schema_bytes > MAX_SCHEMA_BYTES {
            return Err("tool schema exceeds the byte limit".to_string());
        }
    }
    Ok(())
}

#[test]
fn rust_applies_generic_structural_bounds_to_the_exported_snapshot() {
    let snapshot = run_registry("descriptors", json!({}))["descriptors"]
        .as_array()
        .cloned()
        .expect("RSS registry should return descriptors");
    generic_structural_bounds(&snapshot).expect("canonical RSS snapshot should be in bounds");

    let extra_snapshot = run_registry(
        "descriptors",
        json!({ "extra_descriptors": [extra_rss_tool()] }),
    )["descriptors"]
        .as_array()
        .cloned()
        .expect("RSS registry should return descriptors");
    generic_structural_bounds(&extra_snapshot)
        .expect("extra RSS-only tool should not require Rust executor changes");

    let invalid_snapshot = run_registry(
        "descriptors",
        json!({ "extra_descriptors": [extra_tool_named(&"a".repeat(65))] }),
    )["descriptors"]
        .as_array()
        .cloned()
        .expect("RSS registry should return descriptors");
    assert!(generic_structural_bounds(&invalid_snapshot).is_err());
}

#[test]
fn rss_registry_identity_input_changes_with_enablement_and_descriptions() {
    let all = run_registry("identity", json!({}))["identity"].clone();
    let coding =
        run_registry("identity", json!({ "enabled_toolsets": ["coding"] }))["identity"].clone();
    assert_ne!(all, coding);

    let mut changed = extra_rss_tool();
    changed["description"] = json!("Changed fixture-only RSS tool");
    let original = run_registry(
        "identity",
        json!({ "extra_descriptors": [extra_rss_tool()] }),
    )["identity"]
        .clone();
    let updated =
        run_registry("identity", json!({ "extra_descriptors": [changed] }))["identity"].clone();
    assert_ne!(original, updated);
}
