use super::*;
fn validator(name: &str) -> jsonschema::Validator {
    let docs = rustscript_agent::plugins::canonical_schema_documents().unwrap();
    let mut registry = jsonschema::Registry::new();
    let mut selected = None;
    for (filename, text) in docs {
        let schema: Value = serde_json::from_str(&text).unwrap();
        jsonschema::draft202012::meta::validate(&schema).unwrap();
        let id = schema["$id"].as_str().unwrap().to_string();
        if filename == name {
            selected = Some(schema.clone());
        }
        registry = registry.add(id, schema).unwrap();
    }
    let registry = registry.prepare().unwrap();
    jsonschema::options()
        .with_registry(&registry)
        .build(&selected.unwrap())
        .unwrap()
}
#[tokio::test(flavor = "multi_thread")]
async fn managed_live_producers_match_exact_yaml_validators_and_strict_parsers_for_positive_and_negative_documents()
 {
    use rustscript_agent::effects::{
        ManagedWorkspaceRecord, parse_managed_effect_yaml, parse_managed_workspace_yaml,
    };
    let fixture = ManagedFixture::new(|_| {});
    let run=fixture.calls(vec![json!({"id":"schema","name":"write_file","arguments":{"path":"schema.txt","content":"real production consumer"}})]).await;
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&ManagedFixture::request(&run, "schema"))
        .unwrap()
        .unwrap();
    let document = serde_json::to_value(&record).unwrap();
    let effect = validator("managed-effect.schema.json");
    assert!(effect.is_valid(&document));
    assert_eq!(
        parse_managed_effect_yaml(&document.to_string()).unwrap(),
        record
    );
    assert!(effect.is_valid(&serde_json::to_value(record.prepared.as_ref().unwrap()).unwrap()));
    let mut variants = Vec::new();
    for (field, value) in [
        ("format", json!("agent.managed-effect/v2")),
        ("schemaVersion", json!(2)),
        ("execution_token", json!("guest-ref")),
        ("unexpected", json!(true)),
    ] {
        let mut wrong = document.clone();
        wrong[field] = value;
        variants.push(wrong);
    }
    let mut wrong = document.clone();
    wrong["identity"]["code"]["authority"] = json!("guest");
    variants.push(wrong);
    let mut wrong = document.clone();
    wrong["identity"]["expected_head_version"] = json!(0);
    variants.push(wrong);
    for wrong in variants {
        assert!(!effect.is_valid(&wrong));
        assert!(parse_managed_effect_yaml(&wrong.to_string()).is_err());
    }
    for raw in [
        document
            .to_string()
            .replacen('{', "{\"format\":\"agent.managed-effect/v1\",", 1),
        format!("!authority {}", document),
        "format: &alias agent.managed-effect/v1\nother: *alias\n".into(),
    ] {
        assert!(parse_managed_effect_yaml(&raw).is_err());
    }
    let workspace = ManagedWorkspaceRecord {
        format: "agent.managed-workspace/v1".into(),
        schema_version: 1,
        identity: record.identity.workspace.clone(),
        profile: "gateway".into(),
        seed_root: record.prepared.as_ref().unwrap().parent_root.clone(),
        max_entries: 1000,
        max_bytes: 1048576,
        max_depth: 16,
    };
    let value = serde_json::to_value(&workspace).unwrap();
    let schema = validator("managed-workspace.schema.json");
    assert!(schema.is_valid(&value));
    assert_eq!(
        parse_managed_workspace_yaml(&value.to_string()).unwrap(),
        workspace
    );
    for field in ["schemaVersion", "format", "authority"] {
        let mut wrong = value.clone();
        wrong[field] = json!("invalid");
        assert!(!schema.is_valid(&wrong));
        assert!(parse_managed_workspace_yaml(&wrong.to_string()).is_err());
    }
    fixture.state.service().shutdown().await.unwrap();
}
#[test]
fn managed_snapshot_mutations_fail_exact_drift_while_checkpoint_v1_is_unchanged() {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap()).join(format!(
        "managed-schema-drift-{}",
        uuid::Uuid::new_v4().simple()
    ));
    fs::create_dir(&root).unwrap();
    let docs = rustscript_agent::plugins::canonical_schema_documents().unwrap();
    for (name, text) in &docs {
        fs::write(root.join(name), text).unwrap();
    }
    rustscript_agent::plugins::schema_snapshot_drift(&root).unwrap();
    for name in [
        "managed-effect.schema.json",
        "managed-workspace.schema.json",
    ] {
        let original = &docs[name];
        fs::write(root.join(name), format!("{original} \n")).unwrap();
        let error = rustscript_agent::plugins::schema_snapshot_drift(&root).unwrap_err();
        assert!(
            error.contains(name),
            "the changed managed snapshot itself must trigger drift"
        );
        fs::write(root.join(name), original).unwrap();
    }
    assert_eq!(
        docs["checkpoint.schema.json"],
        fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/canonical/checkpoint.schema.json")
        )
        .unwrap()
    );
    rustscript_agent::plugins::schema_snapshot_drift(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
}
