//! Parser and YAML schema must describe the same contract.
//!
//! Negative documents that the strict YAML layer rejects before JSON are
//! parser obligations. Structural negatives must fail both the schema and the
//! parser. Schema identifiers are local and are not fetched.

use std::fs;
use std::path::PathBuf;

use rustscript_agent::plugins::{
    EFFECT_KINDS, EFFECT_RECOVERY, GRAPH_LOCK_FIELDS, MANIFEST_FIELDS, PLUGIN_KINDS,
    parse_plugin_manifest, strict_yaml_to_json,
};

fn schema_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas")
}

fn load(name: &str) -> serde_json::Value {
    let text = fs::read_to_string(schema_dir().join(name))
        .unwrap_or_else(|err| panic!("missing {name}: {err}"));
    strict_yaml_to_json(&text).unwrap_or_else(|err| panic!("{name} is not strict YAML: {err:?}"))
}

fn schema_accepts(name: &str, value: &serde_json::Value) -> bool {
    let manifest = load("plugin-manifest.schema.yaml");
    let effects = load("effect-contract.schema.yaml");
    let lock = load("plugin-graph-lock.schema.yaml");
    for schema in [&manifest, &effects, &lock] {
        jsonschema::draft202012::meta::validate(schema).expect("draft 2020-12 meta");
    }
    let registry = jsonschema::Registry::new()
        .add(
            "https://schemas.rustscript.local/v1/plugin-manifest.schema.yaml",
            manifest,
        )
        .expect("register manifest")
        .add(
            "https://schemas.rustscript.local/v1/effect-contract.schema.yaml",
            effects,
        )
        .expect("register effects")
        .add(
            "https://schemas.rustscript.local/v1/plugin-graph-lock.schema.yaml",
            lock,
        )
        .expect("register lock")
        .prepare()
        .expect("local registry");
    let selected = load(name);
    let validator = jsonschema::options()
        .with_registry(&registry)
        .build(&selected)
        .expect("schema builds offline");
    validator.validate(value).is_ok()
}

fn assert_schema_and_parser(name: &str, yaml: &str, accept: bool) {
    let value = strict_yaml_to_json(yaml).expect("fixture is strict YAML");
    let schema_ok = schema_accepts(name, &value);
    let parser_ok = parse_plugin_manifest(yaml).is_ok();
    assert_eq!(schema_ok, accept, "schema acceptance drifted for {yaml}");
    assert_eq!(parser_ok, accept, "parser acceptance drifted for {yaml}");
}

#[test]
fn schema_enums_and_fields_match_the_parser_contract() {
    let manifest = load("plugin-manifest.schema.yaml");
    let properties: Vec<String> = manifest["properties"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        properties,
        MANIFEST_FIELDS
            .iter()
            .map(|item| (*item).to_string())
            .collect::<Vec<_>>()
    );
    let kinds: Vec<String> = manifest["properties"]["kind"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        kinds,
        PLUGIN_KINDS
            .iter()
            .map(|item| (*item).to_string())
            .collect::<Vec<_>>()
    );
    let effects = load("effect-contract.schema.yaml");
    let effect_kinds: Vec<String> = effects["$defs"]["effect"]["properties"]["kind"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        effect_kinds,
        EFFECT_KINDS
            .iter()
            .map(|item| (*item).to_string())
            .collect::<Vec<_>>()
    );
    let recovery: Vec<String> = effects["$defs"]["effect"]["properties"]["recovery"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        recovery,
        EFFECT_RECOVERY
            .iter()
            .map(|item| (*item).to_string())
            .collect::<Vec<_>>()
    );
    let lock = load("plugin-graph-lock.schema.yaml");
    let lock_fields: Vec<String> = lock["properties"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        lock_fields,
        GRAPH_LOCK_FIELDS
            .iter()
            .map(|item| (*item).to_string())
            .collect::<Vec<_>>()
    );
    assert!(
        fs::read_to_string(schema_dir().join("README.md"))
            .unwrap()
            .contains("not fetched")
    );
}

#[test]
fn positive_and_negative_examples_agree() {
    assert_schema_and_parser(
        "plugin-manifest.schema.yaml",
        r#"format: rustscript.plugin/v1
id: org.rustscript.lib.text
version: 1.0.0
kind: library
runtime: ">=0.1.0, <0.2.0"
contract: agent.library/v1
host_abi: agent.cap/v1
entry:
  path: normalize.rss
  export: normalize
dependencies: []
capabilities: []
effects:
  contract: agent.effects/v1
  entries:
    normalize:
      direct: []
      delegated: []
"#,
        true,
    );
    assert_schema_and_parser(
        "plugin-manifest.schema.yaml",
        r#"format: rustscript.plugin/v1
id: org.rustscript.lib.text
version: 1.0.0
kind: service
runtime: ">=0.1.0, <0.2.0"
contract: agent.library/v1
host_abi: agent.cap/v1
entry:
  path: normalize.rss
  export: normalize
dependencies: []
capabilities: []
effects:
  contract: agent.effects/v1
  entries:
    normalize:
      direct: []
      delegated: []
"#,
        false,
    );
    assert_schema_and_parser(
        "plugin-manifest.schema.yaml",
        r#"format: rustscript.plugin/v1
id: org.rustscript.tools.files
version: 1.0.0
kind: tool
runtime: ">=0.1.0, <0.2.0"
contract: agent.tool/v1
host_abi: agent.cap/v1
entry:
  path: invoke.rss
  export: invoke
dependencies: []
capabilities:
  - workspace.write
effects:
  contract: agent.effects/v1
  entries:
    invoke:
      direct:
        - kind: filesystem
          scope: bound_workspace
          recovery: none
      delegated: []
"#,
        false,
    );
}

fn tool_effect(kind: &str, scope: &str, recovery: &str, capability: &str, path: &str) -> String {
    format!(
        r#"format: rustscript.plugin/v1
id: org.rustscript.tools.sample
version: 1.0.0
kind: tool
runtime: ">=0.1.0, <0.2.0"
contract: agent.tool/v1
host_abi: agent.cap/v1
entry:
  path: {path}
  export: invoke
dependencies: []
capabilities:
  - {capability}
effects:
  contract: agent.effects/v1
  entries:
    invoke:
      direct:
        - kind: {kind}
          scope: {scope}
          recovery: {recovery}
      delegated: []
"#
    )
}

#[test]
fn recovery_scope_and_path_pairs_are_rejected_by_schema_and_parser() {
    assert_schema_and_parser(
        "plugin-manifest.schema.yaml",
        &tool_effect(
            "remote.write",
            "bound_run",
            "checkpoint",
            "remote.write",
            "invoke.rss",
        ),
        false,
    );
    assert_schema_and_parser(
        "plugin-manifest.schema.yaml",
        &tool_effect(
            "process.spawn",
            "bound_process",
            "checkpoint",
            "process.spawn",
            "invoke.rss",
        ),
        false,
    );
    assert_schema_and_parser(
        "plugin-manifest.schema.yaml",
        &tool_effect(
            "clock.read",
            "bound_run",
            "replay",
            "clock.read",
            "invoke.rss",
        ),
        false,
    );
    assert_schema_and_parser(
        "plugin-manifest.schema.yaml",
        &tool_effect(
            "workspace.fs.write",
            "bound_run",
            "checkpoint",
            "workspace.write",
            "invoke.rss",
        ),
        false,
    );
    assert_schema_and_parser(
        "plugin-manifest.schema.yaml",
        &tool_effect(
            "workspace.fs.read",
            "bound_workspace",
            "none",
            "workspace.read",
            "../secret.rss",
        ),
        false,
    );
    assert_schema_and_parser(
        "plugin-manifest.schema.yaml",
        &tool_effect(
            "remote.write",
            "bound_run",
            "none",
            "remote.write",
            "invoke.rss",
        ),
        true,
    );
    assert_schema_and_parser(
        "plugin-manifest.schema.yaml",
        &tool_effect(
            "process.spawn",
            "bound_process",
            "none",
            "process.spawn",
            "invoke.rss",
        ),
        true,
    );
    assert_schema_and_parser(
        "plugin-manifest.schema.yaml",
        &tool_effect(
            "workspace.fs.write",
            "bound_workspace",
            "checkpoint",
            "workspace.write",
            "invoke.rss",
        ),
        true,
    );
}

#[test]
fn lock_schema_requires_entry_alias_requirement_and_distinct_provenance() {
    let lock = load("plugin-graph-lock.schema.yaml");
    let required = lock["properties"]["edges"]["items"]["required"]
        .as_array()
        .unwrap();
    let fields: Vec<&str> = required.iter().map(|item| item.as_str().unwrap()).collect();
    assert!(fields.contains(&"alias"), "{fields:?}");
    assert!(fields.contains(&"from_entry"), "{fields:?}");
    assert!(fields.contains(&"to_entry"), "{fields:?}");
    assert!(fields.contains(&"version_requirement"), "{fields:?}");
    assert!(fields.contains(&"to_version"), "{fields:?}");
    let via = &lock["properties"]["closure"]["items"]["properties"]["effects"]["items"]["properties"]
        ["via"];
    let collapsed = via
        .get("enum")
        .and_then(|item| item.as_array())
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some("delegated")));
    assert!(
        !collapsed,
        "via must not collapse delegated origins to one label: {via}"
    );
}

#[test]
fn cross_field_and_malformed_constraints_stay_native_semantic_checks() {
    let mismatch = r#"format: rustscript.plugin/v1
id: org.rustscript.tools.files
version: 1.0.0
kind: tool
runtime: ">=0.1.0, <0.2.0"
contract: agent.tool/v1
host_abi: agent.cap/v1
entry:
  path: invoke.rss
  export: invoke
dependencies: []
capabilities:
  - workspace.write
effects:
  contract: agent.effects/v1
  entries:
    invoke:
      direct:
        - kind: workspace.fs.read
          scope: bound_workspace
          recovery: none
      delegated: []
"#;
    let value = strict_yaml_to_json(mismatch).unwrap();
    assert!(
        schema_accepts("plugin-manifest.schema.yaml", &value),
        "capability/effect equality is not a schema claim"
    );
    assert!(parse_plugin_manifest(mismatch).is_err());
    let bad_runtime =
        mismatch.replace("runtime: \">=0.1.0, <0.2.0\"", "runtime: \"not-a-version\"");
    let runtime_value = strict_yaml_to_json(&bad_runtime).unwrap();
    assert!(
        schema_accepts("plugin-manifest.schema.yaml", &runtime_value),
        "semver constraint satisfaction is not a schema claim"
    );
    assert!(parse_plugin_manifest(&bad_runtime).is_err());
    let bad_format = mismatch.replace(
        "format: rustscript.plugin/v1",
        "format: rustscript.plugin/v9",
    );
    assert_schema_and_parser("plugin-manifest.schema.yaml", &bad_format, false);
}

#[test]
fn canonical_snapshots_match_and_a_mutated_copy_is_rejected() {
    let dir = schema_dir().join("canonical");
    rustscript_agent::plugins::schema_snapshot_drift(&dir).expect("checked-in snapshots");
    let tmp =
        PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"));
    let drift = tmp.join(format!(
        "schema-drift-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&drift).unwrap();
    for name in [
        "plugin-manifest.schema.json",
        "effect-contract.schema.json",
        "plugin-graph-lock.schema.json",
    ] {
        fs::copy(dir.join(name), drift.join(name)).unwrap();
    }
    let mut mutated = fs::read_to_string(drift.join("plugin-manifest.schema.json")).unwrap();
    mutated.push_str(" \n");
    fs::write(drift.join("plugin-manifest.schema.json"), mutated).unwrap();
    assert!(rustscript_agent::plugins::schema_snapshot_drift(&drift).is_err());
    let _ = fs::remove_dir_all(&drift);
}
