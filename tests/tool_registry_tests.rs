use std::collections::BTreeSet;

use std::process::Command;

use rustscript_agent::registry::{MAX_SCHEMA_BYTES, MAX_SCHEMA_DEPTH};
use rustscript_agent::{
    RiskClass, ToolDescriptor, ToolRegistry, ToolRegistryEntry, ToolRegistryError, Toolset,
    bundled_tool_registry, validate_json_schema,
};
use serde_json::{Map, Value, json};

#[test]
fn builtin_registry_exposes_the_canonical_tool_order() {
    let registry = bundled_tool_registry().expect("RSS registry");
    let snapshot = registry.snapshot();

    assert_eq!(
        snapshot.names(),
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
fn descriptor_constructor_accepts_typed_policy_labels() {
    let descriptor = ToolDescriptor::new(
        "read_file",
        "Read bounded text from a workspace file",
        Toolset::Coding,
        RiskClass::Read,
        valid_schema(),
    );

    assert_eq!(descriptor.toolset, "coding");
    assert_eq!(descriptor.risk_class, "read");
}

#[test]
fn builtin_registry_descriptors_freeze_toolsets_risks_schemas_and_executors() {
    let registry = bundled_tool_registry().expect("RSS registry");
    let snapshot = registry.snapshot();

    assert_eq!(snapshot.descriptors().len(), 6);
    assert_eq!(
        snapshot
            .descriptors()
            .iter()
            .map(|descriptor| descriptor.toolset.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["coding", "process"])
    );

    let expected = [
        (
            "read_file",
            "coding",
            "read",
            "Read bounded text from a workspace file",
        ),
        (
            "search_files",
            "coding",
            "read",
            "Search workspace files with bounded results",
        ),
        (
            "write_file",
            "coding",
            "write",
            "Write complete workspace file contents",
        ),
        (
            "patch",
            "coding",
            "write",
            "Apply a bounded workspace text patch",
        ),
        (
            "terminal",
            "process",
            "execute",
            "Run one bounded argv process",
        ),
        (
            "process",
            "process",
            "execute",
            "Inspect one owned background process",
        ),
    ];

    for ((descriptor, entry), (name, toolset, risk_class, description)) in snapshot
        .descriptors()
        .iter()
        .zip(snapshot.entries())
        .zip(expected)
    {
        assert_eq!(descriptor.name, name);
        assert_eq!(descriptor.toolset, toolset);
        assert_eq!(descriptor.risk_class, risk_class);
        assert_eq!(descriptor.description, description);
        assert_eq!(descriptor.schema["type"], json!("object"));
        assert!(descriptor.schema["required"].is_array());
        assert_eq!(entry.descriptor(), descriptor);
    }

    assert_eq!(
        snapshot.schemas(),
        json!([
            {
                "name": "read_file",
                "description": "Read bounded text from a workspace file",
                "toolset": "coding",
                "risk_class": "read",
                "schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "offset": {"type": "integer", "minimum": 1},
                        "limit": {"type": "integer", "minimum": 1}
                    },
                    "required": ["path"],
                    "additionalProperties": false
                }
            },
            {
                "name": "search_files",
                "description": "Search workspace files with bounded results",
                "toolset": "coding",
                "risk_class": "read",
                "schema": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string"},
                        "path": {"type": "string"},
                        "target": {"type": "string", "enum": ["content", "files"]},
                        "file_glob": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1},
                        "offset": {"type": "integer", "minimum": 0}
                    },
                    "required": ["pattern"],
                    "additionalProperties": false
                }
            },
            {
                "name": "write_file",
                "description": "Write complete workspace file contents",
                "toolset": "coding",
                "risk_class": "write",
                "schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"}
                    },
                    "required": ["path", "content"],
                    "additionalProperties": false
                }
            },
            {
                "name": "patch",
                "description": "Apply a bounded workspace text patch",
                "toolset": "coding",
                "risk_class": "write",
                "schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "old_string": {"type": "string"},
                        "new_string": {"type": "string"},
                        "replace_all": {"type": "boolean"}
                    },
                    "required": ["path", "old_string", "new_string"],
                    "additionalProperties": false
                }
            },
            {
                "name": "terminal",
                "description": "Run one bounded argv process",
                "toolset": "process",
                "risk_class": "execute",
                "schema": {
                    "type": "object",
                    "properties": {
                        "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        "cwd": {"type": "string"},
                        "timeout_ms": {"type": "integer", "minimum": 1},
                        "max_output_bytes": {"type": "integer", "minimum": 1},
                        "stdin": {"type": "string"},
                        "background": {"type": "boolean"}
                    },
                    "required": ["argv"],
                    "additionalProperties": false
                }
            },
            {
                "name": "process",
                "description": "Inspect one owned background process",
                "toolset": "process",
                "risk_class": "execute",
                "schema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "enum": ["poll", "wait", "log", "write", "close", "kill"]},
                        "process_id": {"type": "string"},
                        "data": {"type": "string"},
                        "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 3600000},
                        "offset": {"type": "integer", "minimum": 0},
                        "limit": {"type": "integer", "minimum": 1}
                    },
                    "required": ["action", "process_id"],
                    "additionalProperties": false
                }
            }
        ])
    );
}

#[test]
fn registry_rejects_duplicate_names_and_malformed_schemas_with_typed_errors() {
    let duplicate = ToolRegistry::from_entries(vec![
        entry("read_file", valid_schema()),
        entry("read_file", valid_schema()),
    ])
    .expect_err("duplicate names must fail construction");
    assert!(matches!(
        duplicate,
        ToolRegistryError::DuplicateName { ref name } if name == "read_file"
    ));

    let malformed = ToolRegistry::from_entries(vec![entry(
        "read_file",
        json!({"type": "not-a-json-schema-type"}),
    )])
    .expect_err("malformed schemas must fail construction");
    assert!(matches!(
        malformed,
        ToolRegistryError::InvalidSchema { ref name, .. } if name == "read_file"
    ));
}

#[test]
fn registry_rejects_invalid_nested_schema_keyword_shapes() {
    for schema in [
        json!({"required": "path"}),
        json!({"properties": {"path": "string"}}),
        json!({"type": ["string", "unknown"]}),
        json!({"enum": "value"}),
    ] {
        let error = ToolRegistry::from_entries(vec![entry("read_file", schema)])
            .expect_err("invalid schema keyword shape must fail construction");
        assert!(matches!(error, ToolRegistryError::InvalidSchema { .. }));
    }
}

#[test]
fn schema_validation_rejects_malformed_standard_keyword_shapes_recursively() {
    let invalid_schemas = [
        ("$schema", json!({"$schema": true})),
        ("$id", json!({"$id": false})),
        ("$ref", json!({"$ref": 1})),
        ("$dynamicRef", json!({"$dynamicRef": 1})),
        ("$anchor", json!({"$anchor": 1})),
        ("$dynamicAnchor", json!({"$dynamicAnchor": 1})),
        ("$comment", json!({"$comment": []})),
        ("type", json!({"type": 1})),
        ("properties", json!({"properties": []})),
        ("patternProperties", json!({"patternProperties": []})),
        ("$defs", json!({"$defs": []})),
        ("definitions", json!({"definitions": []})),
        ("dependentSchemas", json!({"dependentSchemas": []})),
        ("required", json!({"required": [1]})),
        (
            "dependentRequired",
            json!({"dependentRequired": {"path": "encoding"}}),
        ),
        ("additionalProperties", json!({"additionalProperties": 1})),
        ("additionalItems", json!({"additionalItems": 1})),
        ("unevaluatedProperties", json!({"unevaluatedProperties": 1})),
        ("unevaluatedItems", json!({"unevaluatedItems": 1})),
        ("contains", json!({"contains": 1})),
        ("propertyNames", json!({"propertyNames": 1})),
        ("not", json!({"not": 1})),
        ("if", json!({"if": 1})),
        ("then", json!({"then": 1})),
        ("else", json!({"else": 1})),
        ("items", json!({"items": [1]})),
        ("prefixItems", json!({"prefixItems": [1]})),
        ("allOf", json!({"allOf": [1]})),
        ("anyOf", json!({"anyOf": [1]})),
        ("oneOf", json!({"oneOf": [1]})),
        ("enum", json!({"enum": "value"})),
        ("minProperties", json!({"minProperties": -1})),
        ("maxProperties", json!({"maxProperties": -1})),
        ("minItems", json!({"minItems": -1})),
        ("maxItems", json!({"maxItems": -1})),
        ("minLength", json!({"minLength": -1})),
        ("maxLength", json!({"maxLength": -1})),
        ("minContains", json!({"minContains": -1})),
        ("maxContains", json!({"maxContains": -1})),
        ("minimum", json!({"minimum": "zero"})),
        ("maximum", json!({"maximum": "zero"})),
        ("exclusiveMinimum", json!({"exclusiveMinimum": "zero"})),
        ("exclusiveMaximum", json!({"exclusiveMaximum": "zero"})),
        ("multipleOf", json!({"multipleOf": "zero"})),
        ("pattern", json!({"pattern": 1})),
        ("format", json!({"format": 1})),
        ("contentEncoding", json!({"contentEncoding": 1})),
        ("contentMediaType", json!({"contentMediaType": 1})),
        ("contentSchema", json!({"contentSchema": "schema"})),
        ("title", json!({"title": 1})),
        ("description", json!({"description": 1})),
        ("readOnly", json!({"readOnly": "true"})),
        ("writeOnly", json!({"writeOnly": "true"})),
        ("deprecated", json!({"deprecated": "true"})),
        ("uniqueItems", json!({"uniqueItems": "true"})),
        ("examples", json!({"examples": {"example": 1}})),
        ("dependencies", json!({"dependencies": {"path": 1}})),
        (
            "nested contentSchema",
            json!({"properties": {"payload": {"contentSchema": "schema"}}}),
        ),
    ];

    for (keyword, schema) in invalid_schemas {
        let error = validate_json_schema(&schema)
            .expect_err("malformed standard keyword shapes must be rejected");
        assert!(
            error.path.contains(keyword.trim_start_matches("nested "))
                || error
                    .message
                    .contains(keyword.trim_start_matches("nested ")),
            "error for {keyword} should identify the invalid keyword: {error}"
        );
    }
}

#[test]
fn schema_validation_accepts_empty_required_arrays() {
    validate_json_schema(&json!({"type": "object", "required": []}))
        .expect("an empty required array is valid JSON Schema");

    ToolRegistry::from_entries(vec![entry(
        "read_file",
        json!({"type": "object", "required": []}),
    )])
    .expect("an empty required array must be accepted by the registry");
}

#[test]
fn registry_identity_changes_for_descriptor_schema_and_metadata() {
    let base = ToolRegistry::from_entries(vec![entry("read_file", valid_schema())])
        .expect("base registry should be valid");

    let mut changed_descriptor = entry("read_file", valid_schema());
    changed_descriptor
        .descriptor
        .description
        .push_str(" (updated)");
    let changed_descriptor = ToolRegistry::from_entries(vec![changed_descriptor])
        .expect("descriptor change should remain valid");

    let changed_schema = ToolRegistry::from_entries(vec![entry(
        "read_file",
        json!({
            "type": "object",
            "properties": {"path": {"type": "string", "minLength": 1}},
            "required": ["path"]
        }),
    )])
    .expect("schema change should remain valid");

    let changed_metadata = ToolRegistry::from_entries(vec![entry(
        "read_file",
        json!({
            "title": "Updated tool arguments",
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"]
        }),
    )])
    .expect("schema metadata change should remain valid");

    assert_ne!(base.identity(), changed_descriptor.identity());
    assert_ne!(base.identity(), changed_schema.identity());
    assert_ne!(base.identity(), changed_metadata.identity());
}

#[test]
fn registry_identity_changes_across_sha256_padding_boundaries() {
    for length in [55, 56, 63, 64, 119, 120] {
        let mut first = entry("read_file", valid_schema());
        first.descriptor.description = "d".repeat(length);
        let mut second = entry("read_file", valid_schema());
        second.descriptor.description = format!("{}x", "d".repeat(length));

        let first = ToolRegistry::from_entries(vec![first])
            .expect("first boundary registry should be valid");
        let second = ToolRegistry::from_entries(vec![second])
            .expect("second boundary registry should be valid");
        assert_ne!(
            first.identity(),
            second.identity(),
            "descriptor identities must differ at description length {length}"
        );
    }
}

#[test]
fn registry_identity_ignores_reordered_json_object_keys() {
    let first_schema: Value = serde_json::from_str(
        r#"{
            "type": "object",
            "properties": {"path": {"type": "string", "minLength": 1}},
            "required": ["path"],
            "metadata": {"z": {"b": 2, "a": 1}, "a": true}
        }"#,
    )
    .expect("first schema JSON should parse");
    let reordered_schema: Value = serde_json::from_str(
        r#"{
            "metadata": {"a": true, "z": {"a": 1, "b": 2}},
            "required": ["path"],
            "properties": {"path": {"minLength": 1, "type": "string"}},
            "type": "object"
        }"#,
    )
    .expect("reordered schema JSON should parse");

    let first = ToolRegistry::from_entries(vec![entry("read_file", first_schema)])
        .expect("first registry should be valid");
    let reordered = ToolRegistry::from_entries(vec![entry("read_file", reordered_schema)])
        .expect("reordered registry should be valid");

    assert_eq!(first.identity(), reordered.identity());
}

#[test]
fn schema_validation_accepts_boolean_and_tuple_schemas() {
    let boolean = ToolRegistry::from_entries(vec![entry("read_file", json!(true))])
        .expect("boolean JSON schemas are valid");
    assert_eq!(boolean.descriptors()[0].schema, json!(true));

    ToolRegistry::from_entries(vec![entry(
        "read_file",
        json!({
            "type": "array",
            "items": [{"type": "string"}, {"type": "integer"}]
        }),
    )])
    .expect("tuple-style items schemas are valid");

    ToolRegistry::from_entries(vec![entry(
        "read_file",
        json!({
            "type": "object",
            "dependentRequired": {"path": ["encoding"]}
        }),
    )])
    .expect("dependentRequired maps are valid schemas");
}

#[test]
fn registry_rejects_toolsets_outside_the_initial_coding_process_pair() {
    let mut descriptor = entry("read_file", valid_schema()).descriptor;
    descriptor.toolset = "browser".to_string();
    let error = ToolRegistry::from_entries(vec![ToolRegistryEntry::new(descriptor)])
        .expect_err("the initial registry must reject unregistered toolsets");
    assert!(matches!(
        error,
        ToolRegistryError::UnsupportedToolset { ref toolset, .. } if toolset == "browser"
    ));
}

#[test]
fn registry_snapshot_identity_is_order_independent_and_immutable() {
    let forward = ToolRegistry::from_entries(vec![
        entry("process", valid_schema()),
        entry("read_file", valid_schema()),
    ])
    .expect("forward registry should be valid");
    let reverse = ToolRegistry::from_entries(vec![
        entry("read_file", valid_schema()),
        entry("process", valid_schema()),
    ])
    .expect("reverse registry should be valid");

    let forward_snapshot = forward.snapshot();
    let reverse_snapshot = reverse.snapshot();
    assert_eq!(forward_snapshot.names(), ["process", "read_file"]);
    assert_eq!(reverse_snapshot.names(), ["read_file", "process"]);
    assert_ne!(
        forward_snapshot.identity(),
        reverse_snapshot.identity(),
        "admitted descriptor order is part of the resume identity"
    );
    assert_eq!(forward_snapshot, forward.snapshot());
}

fn valid_schema() -> Value {
    json!({
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
        "additionalProperties": false
    })
}

fn entry(name: &str, schema: Value) -> ToolRegistryEntry {
    let (toolset, risk_class) = match name {
        "terminal" | "process" => ("process", "execute"),
        "write_file" | "patch" => ("coding", "write"),
        _ => ("coding", "read"),
    };
    ToolRegistryEntry::new(ToolDescriptor {
        name: name.to_string(),
        description: format!("{name} description"),
        toolset: toolset.to_string(),
        risk_class: risk_class.to_string(),
        schema,
    })
}

#[test]
fn registry_rejects_unsupported_risk_labels_with_a_typed_error() {
    let mut descriptor = entry("read_file", valid_schema()).descriptor;
    descriptor.risk_class = "admin".to_string();
    let error = ToolRegistry::from_entries(vec![ToolRegistryEntry::new(descriptor)])
        .expect_err("unsupported risk labels must fail construction");

    assert!(
        format!("{error:?}").contains("UnsupportedRiskClass"),
        "risk validation should have a dedicated typed error: {error:?}"
    );
}

#[test]
fn schema_validation_accepts_only_documented_canonical_dialect_uris() {
    for base in [
        "http://json-schema.org/draft-04/schema",
        "http://json-schema.org/draft-06/schema",
        "http://json-schema.org/draft-07/schema",
        "https://json-schema.org/draft/2019-09/schema",
        "https://json-schema.org/draft/2020-12/schema",
    ] {
        for uri in [base.to_string(), format!("{base}#")] {
            validate_json_schema(&json!({"$schema": uri, "type": "object"}))
                .unwrap_or_else(|error| panic!("known dialect {base:?} should validate: {error}"));
        }
    }
}

#[test]
fn schema_validation_rejects_noncanonical_dialect_uris() {
    for uri in [
        "https://json-schema.org/draft-04/schema",
        "https://json-schema.org/draft-06/schema#",
        "https://json-schema.org/draft-07/schema",
        "http://json-schema.org/draft/2019-09/schema#",
        "http://json-schema.org/draft/2020-12/schema",
        "https://json-schema.org/schema",
        "https://json-schema.org/draft/2020-12/schema##",
        "https://json-schema.org/draft/2020-12/schema#fragment",
        "https://json-schema.org/draft/2020-12/schema?query=1",
        "HTTPS://JSON-SCHEMA.ORG/DRAFT/2020-12/SCHEMA",
        " https://json-schema.org/draft/2020-12/schema",
        "https://json-schema.org/draft/2020-12/schema\n",
        "https://schemas.example.invalid/custom/secret-marker",
    ] {
        let error = validate_json_schema(&json!({"$schema": uri, "type": "object"}))
            .expect_err("noncanonical schema dialects must fail closed");
        assert_eq!(
            error.kind,
            rustscript_agent::SchemaValidationErrorKind::UnsupportedSchemaDialect,
            "unexpected error for dialect {uri:?}: {error}"
        );
    }
}

#[test]
fn schema_validation_rejects_legacy_tuple_items_outside_the_root() {
    let nested_schemas = [
        (
            "$defs",
            json!({"$defs": {"tuple": {"items": [{"type": "string"}]}}}),
        ),
        (
            "prefixItems",
            json!({"prefixItems": [{"items": [{"type": "string"}]}]}),
        ),
        (
            "properties",
            json!({"properties": {"payload": {"items": [{"type": "string"}]}}}),
        ),
        ("allOf", json!({"allOf": [{"items": [{"type": "string"}]}]})),
        ("anyOf", json!({"anyOf": [{"items": [{"type": "string"}]}]})),
        ("oneOf", json!({"oneOf": [{"items": [{"type": "string"}]}]})),
    ];

    for (location, schema) in nested_schemas {
        let error = validate_json_schema(&schema)
            .expect_err("legacy tuple syntax is only compatible at the root");
        assert_eq!(
            error.kind,
            rustscript_agent::SchemaValidationErrorKind::MetaSchema,
            "unexpected error for nested tuple under {location}: {error}"
        );
    }
}

#[test]
fn schema_validation_validates_every_root_legacy_tuple_member() {
    for items in [
        json!([]),
        json!([1]),
        json!([{"type": 1}]),
        json!([{"items": [1]}]),
    ] {
        let error = validate_json_schema(&json!({"items": items}))
            .expect_err("root tuple items must be a non-empty Draft 7 schema array");
        assert_eq!(
            error.kind,
            rustscript_agent::SchemaValidationErrorKind::MetaSchema,
            "unexpected root tuple error: {error}"
        );
    }
}

#[test]
fn schema_validation_rejects_unknown_dialect_uris_with_a_typed_error() {
    let error = validate_json_schema(&json!({
        "$schema": "https://schemas.example.invalid/custom/secret-marker",
        "type": "object"
    }))
    .expect_err("unknown schema dialects must fail closed");

    assert!(
        format!("{error:?}").contains("UnsupportedSchemaDialect"),
        "unknown dialects should have a dedicated typed error: {error:?}"
    );

    let registry_error = ToolRegistry::from_entries(vec![entry(
        "read_file",
        json!({
            "$schema": "https://schemas.example.invalid/custom/secret-marker",
            "type": "object"
        }),
    )])
    .expect_err("the registry must preserve the typed dialect failure");
    assert!(format!("{registry_error:?}").contains("UnsupportedSchemaDialect"));
}

#[test]
fn registry_rejects_names_outside_the_provider_safe_ascii_grammar() {
    for name in [
        "read file",
        "read\tfile",
        "read\nfile",
        "read\0file",
        "réad_file",
        "read＿file",
    ] {
        let error = ToolRegistry::from_entries(vec![entry(name, valid_schema())])
            .expect_err("provider-unsafe names must fail before uniqueness checks");
        assert!(
            format!("{error:?}").contains("InvalidToolName"),
            "invalid name {name:?} should have a typed error: {error:?}"
        );
    }
}

#[test]
fn registry_enforces_provider_name_length_at_the_boundary() {
    let accepted_name = "a".repeat(64);
    ToolRegistry::from_entries(vec![entry(&accepted_name, valid_schema())])
        .expect("a 64-byte provider-safe name is within the limit");

    let rejected_name = "a".repeat(65);
    let error = ToolRegistry::from_entries(vec![entry(&rejected_name, valid_schema())])
        .expect_err("a 65-byte provider-safe name exceeds the limit");
    assert!(format!("{error:?}").contains("ToolNameTooLong"));
}

#[test]
fn registry_enforces_description_length_at_the_boundary() {
    let accepted = ToolDescriptor::new(
        "read_file",
        "d".repeat(4096),
        "coding",
        "read",
        valid_schema(),
    );
    ToolRegistry::from_entries(vec![ToolRegistryEntry::new(accepted)])
        .expect("a 4096-byte description is within the limit");

    let rejected = ToolDescriptor::new(
        "read_file",
        "d".repeat(4097),
        "coding",
        "read",
        valid_schema(),
    );
    let error = ToolRegistry::from_entries(vec![ToolRegistryEntry::new(rejected)])
        .expect_err("a 4097-byte description exceeds the limit");
    assert!(format!("{error:?}").contains("DescriptionTooLong"));
}

#[test]
fn registry_checks_field_byte_limits_before_whitespace_scans() {
    let overlong_name = " ".repeat(65);
    let name_error = ToolRegistry::from_entries(vec![entry(&overlong_name, valid_schema())])
        .expect_err("an over-limit whitespace-only name must hit the byte limit first");
    assert!(matches!(
        name_error,
        ToolRegistryError::ToolNameTooLong { limit: 64, .. }
    ));

    let overlong_description = " ".repeat(4097);
    let description_error =
        ToolRegistry::from_entries(vec![ToolRegistryEntry::new(ToolDescriptor::new(
            "read_file",
            overlong_description,
            "coding",
            "read",
            valid_schema(),
        ))])
        .expect_err("an over-limit whitespace-only description must hit the byte limit first");
    assert!(matches!(
        description_error,
        ToolRegistryError::DescriptionTooLong { limit: 4096, .. }
    ));
}

#[test]
fn registry_enforces_utf8_byte_limits_without_splitting_diagnostics() {
    let accepted_description = "é".repeat(2048);
    ToolRegistry::from_entries(vec![ToolRegistryEntry::new(ToolDescriptor::new(
        "read_file",
        accepted_description,
        "coding",
        "read",
        valid_schema(),
    ))])
    .expect("a 4096-byte UTF-8 description is within the limit");

    let rejected_description = "é".repeat(2049);
    let error = ToolRegistry::from_entries(vec![ToolRegistryEntry::new(ToolDescriptor::new(
        "read_file",
        rejected_description,
        "coding",
        "read",
        valid_schema(),
    ))])
    .expect_err("a 4098-byte UTF-8 description exceeds the limit");
    assert!(matches!(
        error,
        ToolRegistryError::DescriptionTooLong { limit: 4096, .. }
    ));

    let too_long_unicode_name = "é".repeat(33);
    let error = ToolRegistry::from_entries(vec![entry(&too_long_unicode_name, valid_schema())])
        .expect_err("a 66-byte Unicode name must fail at the byte limit");
    assert!(matches!(
        error,
        ToolRegistryError::ToolNameTooLong { limit: 64, .. }
    ));
}

#[test]
fn registry_rejects_unbounded_risk_values_before_parsing_them() {
    let mut descriptor = entry("read_file", valid_schema()).descriptor;
    descriptor.risk_class = "risk-marker".repeat(10_000);
    let error = ToolRegistry::from_entries(vec![ToolRegistryEntry::new(descriptor)])
        .expect_err("oversized risk labels must fail as unsupported values");
    assert!(matches!(
        error,
        ToolRegistryError::UnsupportedRiskClass { ref risk_class, .. }
            if risk_class.len() <= 128
    ));
}

#[test]
fn registry_rejects_individual_schema_strings_at_their_serialized_budget_boundary() {
    let oversized = "x".repeat(MAX_SCHEMA_BYTES + 1);
    let expected_actual = oversized.len() + 2;
    let schema = json!({"description": oversized});

    let error = ToolRegistry::from_entries(vec![entry("read_file", schema)])
        .expect_err("an individual schema string that cannot fit must fail preflight");
    assert!(matches!(
        error,
        ToolRegistryError::SchemaTooLarge {
            limit: MAX_SCHEMA_BYTES,
            actual,
            ..
        } if actual == expected_actual
    ));
}

#[test]
fn registry_rejects_individual_schema_keys_at_their_serialized_budget_boundary() {
    let oversized = "k".repeat(MAX_SCHEMA_BYTES + 1);
    let expected_actual = oversized.len() + 2;
    let mut schema = Map::new();
    schema.insert(oversized, Value::Bool(true));

    let error = ToolRegistry::from_entries(vec![entry("read_file", Value::Object(schema))])
        .expect_err("an individual schema key that cannot fit must fail preflight");
    assert!(matches!(
        error,
        ToolRegistryError::SchemaTooLarge {
            limit: MAX_SCHEMA_BYTES,
            actual,
            ..
        } if actual == expected_actual
    ));
}

#[test]
fn registry_enforces_schema_serialized_size_at_the_boundary() {
    let accepted_schema = schema_with_serialized_size(65_536);
    assert_eq!(
        serde_json::to_vec(&accepted_schema)
            .expect("schema should serialize")
            .len(),
        65_536
    );
    ToolRegistry::from_entries(vec![entry("read_file", accepted_schema)])
        .expect("a 65536-byte serialized schema is within the limit");

    let rejected_schema = schema_with_serialized_size(65_537);
    let error = ToolRegistry::from_entries(vec![entry("read_file", rejected_schema)])
        .expect_err("a 65537-byte serialized schema exceeds the limit");
    assert!(format!("{error:?}").contains("SchemaTooLarge"));
}

#[test]
fn registry_enforces_schema_node_count_at_the_boundary() {
    let accepted_schema = schema_with_property_count(4_093);
    ToolRegistry::from_entries(vec![entry("read_file", accepted_schema)])
        .expect("a schema with 4096 nodes is within the limit");

    let rejected_schema = schema_with_property_count(4_094);
    let error = ToolRegistry::from_entries(vec![entry("read_file", rejected_schema)])
        .expect_err("a schema with 4097 nodes exceeds the limit");
    assert!(format!("{error:?}").contains("SchemaTooComplex"));
}

#[test]
fn registry_enforces_schema_nesting_depth_at_the_boundary() {
    let accepted_schema = nested_schema(128);
    ToolRegistry::from_entries(vec![entry("read_file", accepted_schema)])
        .expect("a schema at depth 128 is within the limit");

    let rejected_schema = nested_schema(129);
    let error = ToolRegistry::from_entries(vec![entry("read_file", rejected_schema)])
        .expect_err("a schema at depth 129 exceeds the limit");
    assert!(matches!(
        error,
        ToolRegistryError::SchemaTooDeep {
            limit: MAX_SCHEMA_DEPTH,
            actual,
            ..
        } if actual == MAX_SCHEMA_DEPTH + 1
    ));
}

#[test]
fn registry_rejects_schema_too_deep_before_recursive_serialization() {
    if std::env::var_os("RUSTSCRIPT_DEEP_SCHEMA_CHILD").is_some() {
        let schema = deeply_nested_schema(MAX_SCHEMA_DEPTH + 16_384);
        let error = validate_json_schema(&schema)
            .expect_err("a deeply nested schema must be rejected by the bounded preflight");
        assert_eq!(
            error.kind,
            rustscript_agent::SchemaValidationErrorKind::SchemaTooDeep
        );
        std::process::exit(0);
    }

    let output = Command::new(std::env::current_exe().expect("test executable path"))
        .args([
            "--exact",
            "registry_rejects_schema_too_deep_before_recursive_serialization",
            "--nocapture",
        ])
        .env("RUSTSCRIPT_DEEP_SCHEMA_CHILD", "1")
        .output()
        .expect("deep schema child should start");
    assert!(
        output.status.success(),
        "deep schema validation child failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn registry_bounds_entry_count_before_collecting_or_validating_entries() {
    let within_limit = (0..64)
        .map(|index| entry(&format!("tool_{index}"), valid_schema()))
        .collect::<Vec<_>>();
    ToolRegistry::from_entries(within_limit).expect("64 entries are within the limit");

    let over_limit = (0..65)
        .map(|index| entry(&format!("tool_{index}"), valid_schema()))
        .collect::<Vec<_>>();
    let error = ToolRegistry::from_entries(over_limit)
        .expect_err("the 65th entry must be rejected by the construction budget");
    assert!(format!("{error:?}").contains("TooManyEntries"));

    let mut invalid_after_limit = (0..64)
        .map(|index| entry(&format!("tool_{index}"), valid_schema()))
        .collect::<Vec<_>>();
    invalid_after_limit.push(entry("not provider safe", json!({"type": 1})));
    let error = ToolRegistry::from_entries(invalid_after_limit)
        .expect_err("the entry cap must run before validating a later entry");
    assert!(matches!(error, ToolRegistryError::TooManyEntries { .. }));
}

#[test]
fn invalid_schema_diagnostics_are_bounded_and_redacted() {
    let marker = "SCHEMA_SECRET_MARKER";
    let schema = json!({
        "type": {"marker": marker, "large": "x".repeat(20_000)}
    });
    let error = ToolRegistry::from_entries(vec![entry("read_file", schema)])
        .expect_err("the malformed schema must be rejected");
    let rendered = format!("{error}");

    assert!(!rendered.contains(marker));
    assert!(
        rendered.len() <= 512,
        "diagnostic was too large: {}",
        rendered.len()
    );
    assert!(
        rendered.contains("keyword=type"),
        "diagnostic should identify the malformed keyword: {rendered}"
    );
    assert!(
        rendered.contains("path=/type"),
        "diagnostic should identify the schema pointer: {rendered}"
    );
}

#[test]
fn snapshot_identity_uses_a_digest_with_executor_contract_metadata() {
    let snapshot = bundled_tool_registry().expect("RSS registry").snapshot();
    assert!(snapshot.identity().starts_with("sha256:"));
    assert_eq!(snapshot.identity().len(), 71);
}

fn schema_with_serialized_size(target: usize) -> Value {
    let empty_schema = json!({"description": ""});
    let overhead = serde_json::to_vec(&empty_schema)
        .expect("schema should serialize")
        .len();
    assert!(target >= overhead, "target must fit the schema envelope");

    let schema = json!({"description": "x".repeat(target - overhead)});
    assert_eq!(
        serde_json::to_vec(&schema)
            .expect("schema should serialize")
            .len(),
        target
    );
    schema
}

fn schema_with_property_count(count: usize) -> Value {
    let properties: serde_json::Map<String, Value> = (0..count)
        .map(|index| (format!("p{index}"), json!({})))
        .collect();
    json!({"type": "object", "properties": properties})
}

fn deeply_nested_schema(depth: usize) -> Value {
    let mut schema = Value::Object(Map::new());
    for _ in 0..depth {
        let mut parent = Map::new();
        parent.insert("x".to_string(), schema);
        schema = Value::Object(parent);
    }
    schema
}

fn nested_schema(depth: usize) -> Value {
    let mut schema = json!({});
    for _ in 0..depth {
        schema = json!({"x": schema});
    }
    schema
}
