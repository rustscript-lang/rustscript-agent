//! Current managed schemas and the same strict Native named decoder.
use super::*;

fn referenced_document(uri: &str) -> Value {
    let name = uri.rsplit('/').next().unwrap_or("");
    let text = match name {
        "plugin-graph-lock.schema.yaml" => {
            include_str!("../../schemas/plugin-graph-lock.schema.yaml")
        }
        "managed-checkpoint.schema.yaml" => {
            include_str!("../../schemas/managed-checkpoint.schema.yaml")
        }
        other => panic!("unregistered local schema reference {other}"),
    };
    crate::plugins::strict_yaml_to_json(text).expect("referenced schema is strict YAML")
}

fn sample(schema: &Value, body: &Value) -> Value {
    if let Some(path) = body["$ref"].as_str() {
        if let Some((uri, fragment)) = path.split_once('#')
            && !uri.is_empty()
        {
            let document = referenced_document(uri);
            return sample(
                &document,
                document
                    .pointer(fragment)
                    .expect("registered schema pointer"),
            );
        }
        return sample(
            schema,
            schema.pointer(path.trim_start_matches('#')).unwrap(),
        );
    }
    if let Some(value) = body.get("const") {
        return value.clone();
    }
    if let Some(values) = body["enum"].as_array() {
        return values[0].clone();
    }
    for union in ["anyOf", "oneOf"] {
        if let Some(values) = body[union].as_array() {
            return sample(schema, &values[0]);
        }
    }
    match body["type"].as_str().unwrap() {
        "object" => Value::Object(
            body["properties"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| (key.clone(), sample(schema, value)))
                .collect(),
        ),
        "array" => json!([]),
        "boolean" => json!(false),
        "integer" => body.get("minimum").cloned().unwrap_or(json!(0)),
        "number" => json!(0.25),
        "null" => Value::Null,
        "string" => {
            let pattern = body["pattern"].as_str().unwrap_or("");
            if pattern.starts_with("^[0-9a-fA-F]{8}") {
                return json!("00000000-0000-4000-8000-000000000001");
            }
            if let Some((prefix, _)) = pattern.strip_prefix('^').and_then(|p| p.split_once("-[")) {
                return json!(format!("{prefix}-{}", "0".repeat(32)));
            }
            if pattern == "^[0-9]+$" {
                return json!("0");
            }
            json!("x")
        }
        kind => panic!("uncovered schema type {kind}"),
    }
}
fn load_schema(name: &str) -> Value {
    let text = match name {
        "managed-checkpoint.schema.yaml" => {
            include_str!("../../schemas/managed-checkpoint.schema.yaml")
        }
        "managed-restore.schema.yaml" => include_str!("../../schemas/managed-restore.schema.yaml"),
        _ => panic!("unknown managed test schema"),
    };
    serde_json::from_str(text).unwrap()
}
fn assert_named<T: for<'de> Deserialize<'de> + Serialize>(name: &str, definition: &str) {
    let schema = load_schema(name);
    let value = sample(&schema, &schema["$defs"][definition]);
    crate::plugins::validate_managed_maintenance(name, definition, &value)
        .unwrap_or_else(|e| panic!("{definition}: {e}"));
    let typed: T =
        serde_json::from_value(value.clone()).unwrap_or_else(|e| panic!("{definition}: {e}"));
    let produced = serde_json::to_value(typed).unwrap();
    crate::plugins::validate_managed_maintenance(name, definition, &produced).unwrap();
    if let Some(fields) = value.as_object() {
        let mut unknown = value.clone();
        unknown["unrecognized_authority"] = json!(true);
        assert!(crate::plugins::validate_managed_maintenance(name, definition, &unknown).is_err());
        assert!(serde_json::from_value::<T>(unknown).is_err());
        for key in fields.keys() {
            let property = &schema["$defs"][definition]["properties"][key];
            let mut omitted = value.clone();
            omitted.as_object_mut().unwrap().remove(key);
            let required = schema["$defs"][definition]["required"]
                .as_array()
                .unwrap()
                .contains(&json!(key));
            assert_eq!(
                crate::plugins::validate_managed_maintenance(name, definition, &omitted).is_err(),
                required,
                "{definition}.{key} required"
            );
            let mut null = value.clone();
            null[key] = Value::Null;
            let nullable = property["anyOf"]
                .as_array()
                .is_some_and(|items| items.iter().any(|p| p["type"] == "null"));
            assert_eq!(
                crate::plugins::validate_managed_maintenance(name, definition, &null).is_ok(),
                nullable,
                "{definition}.{key} null"
            );
            if property["type"] == "boolean" || property.get("const").is_some_and(Value::is_boolean)
            {
                let mut wrong = value.clone();
                wrong[key] = json!("false");
                assert!(
                    crate::plugins::validate_managed_maintenance(name, definition, &wrong).is_err()
                );
                assert!(serde_json::from_value::<T>(wrong).is_err());
            }
        }
    }
}
#[test]
fn managed_every_named_producer_and_schema_agree_on_fields_bool_null_and_optional_rules() {
    macro_rules! checkpoint { ($($ty:ty),+ $(,)?) => { $(assert_named::<$ty>("managed-checkpoint.schema.yaml",stringify!($ty));)+ }; }
    macro_rules! restore { ($($ty:ty),+ $(,)?) => { $(assert_named::<$ty>("managed-restore.schema.yaml",stringify!($ty));)+ }; }
    checkpoint!(
        ManagedCheckpointCreateRequest,
        ManagedCheckpointReceipt,
        ManagedCheckpointRef,
        ManagedSourceCas,
        ManagedClosedOutputRef,
        ManagedFrozenHistoryRef,
        ManagedCheckpointGraphRef,
        ManagedCheckpointPublicConfig,
        ManagedPublicConfigRef,
        ManagedPluginStateRootRef,
        ManagedExternalHighWater,
        ManagedCheckpointArtifactRef,
        ManagedExternalBoundary,
        ManagedFrozenMessage,
        ManagedFrozenCompaction,
        ManagedFrozenProviderOptions,
        ManagedFrozenExecutionConfig,
        ManagedCheckpointContext,
        ManagedCheckpointCommitInput,
        ManagedCheckpointLookup
    );
    restore!(
        ManagedRestoreRunInput,
        ManagedRestoreAndAdmitRequest,
        ManagedRestoreAndAdmitResult,
        ManagedRestoreExecutionEnvelope,
        ManagedAdmissionPin,
        ManagedRollbackFacts,
        ManagedBranchPublication
    );
}
#[test]
fn managed_public_parsers_reject_duplicates_aliases_tags_unknown_and_enum_drift() {
    let schema = load_schema("managed-restore.schema.yaml");
    let request = sample(&schema, &schema["$defs"]["ManagedRestoreAndAdmitRequest"]);
    let text = request.to_string();
    parse_managed_restore_request_yaml(&text).unwrap();
    for invalid in [
        text.replacen("{", "{\"request_id\":\"duplicate\",", 1),
        text.replacen("checkpoint_exact", "active_default", 1),
        text.replacen("true", "false", 1),
        text.replacen("{", "{\"claims\":{},", 1),
        "request_id: &anchor value\nworkspace_id: *anchor\n".into(),
        "request_id: !!str value\n".into(),
        "request_id: a\nrequest_id: b\n".into(),
    ] {
        assert!(parse_managed_restore_request_yaml(&invalid).is_err());
    }
    let schema = load_schema("managed-checkpoint.schema.yaml");
    let receipt = sample(&schema, &schema["$defs"]["ManagedCheckpointReceipt"]);
    parse_managed_checkpoint_yaml(&receipt.to_string()).unwrap();
    let mut state = receipt.clone();
    state["checkpoint"]["plugin_state"]["manifest_state_absent"] = json!(false);
    assert!(parse_managed_checkpoint_yaml(&state.to_string()).is_err());
    let mut roots = receipt.clone();
    roots["checkpoint"]["plugin_state"]["roots"] = json!([sample(
        &schema,
        &schema["$defs"]["ManagedPluginStateRootRef"]
    )]);
    assert!(parse_managed_checkpoint_yaml(&roots.to_string()).is_err());
    let mut artifacts = receipt;
    artifacts["checkpoint"]["external_boundary"]["artifact_refs"] = json!([sample(
        &schema,
        &schema["$defs"]["ManagedCheckpointArtifactRef"]
    )]);
    assert!(parse_managed_checkpoint_yaml(&artifacts.to_string()).is_err());
}

#[test]
fn managed_publish_request_receipt_and_publication_reject_unknown_missing_and_status_drift() {
    let schema = load_schema("managed-checkpoint.schema.yaml");
    for definition in [
        "ManagedPublishRequest",
        "ManagedPublishReceipt",
        "ManagedWorkspacePublication",
    ] {
        let value = sample(&schema, &schema["$defs"][definition]);
        crate::plugins::validate_managed_maintenance(
            "managed-checkpoint.schema.yaml",
            definition,
            &value,
        )
        .unwrap_or_else(|e| panic!("{definition}: {e}"));
        let mut unknown = value.clone();
        unknown["unrecognized_authority"] = json!(true);
        assert!(
            crate::plugins::validate_managed_maintenance(
                "managed-checkpoint.schema.yaml",
                definition,
                &unknown
            )
            .is_err(),
            "{definition} unknown"
        );
        let required = schema["$defs"][definition]["required"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(!required.is_empty(), "{definition} required");
        let key = required[0].as_str().unwrap();
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            crate::plugins::validate_managed_maintenance(
                "managed-checkpoint.schema.yaml",
                definition,
                &missing
            )
            .is_err(),
            "{definition}.{key} missing"
        );
    }
    let receipt = sample(&schema, &schema["$defs"]["ManagedPublishReceipt"]);
    assert_eq!(receipt["status"], json!("committed"));
    let mut drifted = receipt.clone();
    drifted["status"] = json!("staged");
    assert!(
        crate::plugins::validate_managed_maintenance(
            "managed-checkpoint.schema.yaml",
            "ManagedPublishReceipt",
            &drifted
        )
        .is_err(),
        "receipt status drift"
    );
    let request = sample(&schema, &schema["$defs"]["ManagedPublishRequest"]);
    let mut head_missing = request.clone();
    head_missing["expected_head"]
        .as_object_mut()
        .unwrap()
        .remove("head_object_id");
    assert!(
        crate::plugins::validate_managed_maintenance(
            "managed-checkpoint.schema.yaml",
            "ManagedPublishRequest",
            &head_missing
        )
        .is_err(),
        "request expected_head missing member"
    );
    let mut head_drift = request.clone();
    head_drift["expected_head"]["epoch"] = json!(0);
    assert!(
        crate::plugins::validate_managed_maintenance(
            "managed-checkpoint.schema.yaml",
            "ManagedPublishRequest",
            &head_drift
        )
        .is_err(),
        "request expected_head bound drift"
    );
    let publication = sample(&schema, &schema["$defs"]["ManagedWorkspacePublication"]);
    let mut request_unknown = request.clone();
    request_unknown["claimed_authority"] = json!(true);
    let mut receipt_unknown = receipt.clone();
    receipt_unknown["claimed_authority"] = json!(true);
    let mut publication_unknown = publication.clone();
    publication_unknown["claimed_authority"] = json!(true);
    assert!(validate_maintenance_value::<ManagedPublishRequest>(&request).is_ok());
    assert!(validate_maintenance_value::<ManagedPublishReceipt>(&receipt).is_ok());
    assert!(validate_maintenance_value::<ManagedWorkspacePublication>(&publication).is_ok());
    assert!(validate_maintenance_value::<ManagedPublishRequest>(&request_unknown).is_err());
    assert!(validate_maintenance_value::<ManagedPublishReceipt>(&receipt_unknown).is_err());
    assert!(
        validate_maintenance_value::<ManagedWorkspacePublication>(&publication_unknown).is_err()
    );
    assert!(validate_maintenance_value::<ManagedPublishRequest>(&head_missing).is_err());
    assert!(validate_maintenance_value::<ManagedPublishRequest>(&head_drift).is_err());
    assert!(validate_maintenance_value::<ManagedPublishReceipt>(&drifted).is_err());
    assert!(serde_json::from_value::<ManagedPublishRequest>(request_unknown).is_err());
    assert!(serde_json::from_value::<ManagedPublishReceipt>(receipt_unknown).is_err());
    assert!(serde_json::from_value::<ManagedWorkspacePublication>(publication_unknown).is_err());
}
