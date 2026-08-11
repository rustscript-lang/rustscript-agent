use std::fs;

use serde_json::Value;

const FIXTURES: &[(&str, &str)] = &[
    ("inbound_envelope.json", "platform"),
    ("llm_request.json", "model"),
    ("llm_event.json", "type"),
    ("tool_call.json", "name"),
    ("run_event.json", "type"),
];

#[test]
fn canonical_contract_fixtures_are_valid_json_with_required_discriminators() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("contracts");
    for (file, discriminator) in FIXTURES {
        let path = root.join(file);
        let source = fs::read_to_string(&path).expect("contract fixture should be readable");
        let value: Value = serde_json::from_str(&source).expect("contract fixture should be JSON");
        assert!(value.is_object(), "{file} must contain a JSON object");
        assert!(
            value.get(*discriminator).is_some(),
            "{file} must contain its {discriminator} discriminator"
        );
    }
}
