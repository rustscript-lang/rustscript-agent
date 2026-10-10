//! RSS source selection through the production AgentRunner.

use rustscript_agent::{AgentConfig, AgentRunner};
use rustscript_vm::Value as VmValue;
use serde_json::{Value as JsonValue, json};
use std::path::PathBuf;

fn json_to_vm(value: &JsonValue) -> VmValue {
    match value {
        JsonValue::Null => VmValue::Null,
        JsonValue::Bool(value) => VmValue::Bool(*value),
        JsonValue::Number(value) => {
            if let Some(value) = value.as_i64() {
                VmValue::Int(value)
            } else {
                VmValue::Float(value.as_f64().expect("JSON number should be finite"))
            }
        }
        JsonValue::String(value) => VmValue::string(value),
        JsonValue::Array(values) => {
            VmValue::Array(values.iter().map(json_to_vm).collect::<Vec<_>>().into())
        }
        JsonValue::Object(entries) => VmValue::map(
            entries
                .iter()
                .map(|(key, value)| (VmValue::string(key), json_to_vm(value)))
                .collect(),
        ),
    }
}

fn vm_to_json(value: &VmValue) -> JsonValue {
    match value {
        VmValue::Null => JsonValue::Null,
        VmValue::Bool(value) => json!(value),
        VmValue::Int(value) => json!(value),
        VmValue::Float(value) => serde_json::Number::from_f64(*value)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        VmValue::String(value) => JsonValue::String(value.to_string()),
        VmValue::Bytes(value) => JsonValue::String(String::from_utf8_lossy(value).into_owned()),
        VmValue::Array(values) => JsonValue::Array(values.iter().map(vm_to_json).collect()),
        VmValue::Map(entries) => JsonValue::Object(
            entries
                .iter()
                .map(|(key, value)| {
                    let key = match key {
                        VmValue::String(key) => key.to_string(),
                        other => vm_to_json(other).to_string(),
                    };
                    (key, vm_to_json(value))
                })
                .collect(),
        ),
        VmValue::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn decide(context: JsonValue) -> JsonValue {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/source_policy.rss");
    let runner = AgentRunner::from_file(source, AgentConfig::default())
        .unwrap_or_else(|error| panic!("compile source policy RSS: {error}"));
    let result = runner
        .run_with_context(json_to_vm(&context))
        .unwrap_or_else(|error| panic!("run source policy RSS: {error:?}"));
    vm_to_json(&result)
}

fn failure(code: &str, message: &str) -> JsonValue {
    json!({
        "ok": false,
        "deprecated_override": false,
        "error": {"code": code, "message": message}
    })
}

fn bundled_success() -> JsonValue {
    json!({
        "ok": true,
        "source": "bundled:coding",
        "descriptor": {"kind": "bundled", "resource": "coding"},
        "deprecated_override": false
    })
}

fn file_success(source: &str, path: &str, deprecated_override: bool) -> JsonValue {
    json!({
        "ok": true,
        "source": source,
        "descriptor": {"kind": "file", "path": path},
        "deprecated_override": deprecated_override
    })
}

#[test]
fn absent_and_null_source_select_bundled_coding() {
    let expected = bundled_success();

    assert_eq!(decide(json!({})), expected);
    assert_eq!(
        decide(json!({"source": null, "legacy_script": null})),
        expected
    );
}

#[test]
fn explicit_bundled_source_is_selected() {
    assert_eq!(
        decide(json!({"source": "bundled:coding"})),
        bundled_success()
    );
}

#[test]
fn explicit_file_source_is_selected() {
    assert_eq!(
        decide(json!({"source": "file:/tmp/agent.rss"})),
        file_success("file:/tmp/agent.rss", "/tmp/agent.rss", false)
    );
}

#[test]
fn explicit_file_source_preserves_spaces_and_unicode() {
    let path = "/srv/エージェント dir/my agent.rss";
    assert_eq!(
        decide(json!({
            "source": format!("file:{path}"),
            "legacy_script": "/legacy/agent.rss"
        })),
        file_success(&format!("file:{path}"), path, false)
    );
}

#[test]
fn explicit_bundled_source_beats_valid_legacy() {
    assert_eq!(
        decide(json!({"source": "bundled:coding", "legacy_script": "/legacy/agent.rss"})),
        bundled_success()
    );
}

#[test]
fn explicit_file_source_beats_valid_legacy() {
    assert_eq!(
        decide(json!({"source": "file:/tmp/agent.rss", "legacy_script": "/legacy/agent.rss"})),
        file_success("file:/tmp/agent.rss", "/tmp/agent.rss", false)
    );
}

#[test]
fn legacy_absolute_raw_path_migrates_to_file_source() {
    let raw = "/legacy/エージェント dir/agent.rss";
    assert_eq!(
        decide(json!({"legacy_script": raw})),
        file_success(&format!("file:{raw}"), raw, true)
    );
}

#[test]
fn null_source_falls_back_to_valid_legacy() {
    assert_eq!(
        decide(json!({"source": null, "legacy_script": "/legacy/agent.rss"})),
        file_success("file:/legacy/agent.rss", "/legacy/agent.rss", true)
    );
}

#[test]
fn explicit_non_string_source_is_invalid_without_fallback() {
    let legacy = "/legacy/agent.rss";
    let expected = failure("invalid_agent_source", "agent source is invalid");
    assert_eq!(
        decide(json!({"source": 12, "legacy_script": legacy})),
        expected
    );
    assert_eq!(
        decide(json!({"source": true, "legacy_script": legacy})),
        expected
    );
}

#[test]
fn explicit_empty_or_control_or_relative_file_source_is_invalid_without_fallback() {
    let legacy = "/legacy/agent.rss";
    let expected = failure("invalid_agent_source", "agent source is invalid");
    assert_eq!(
        decide(json!({"source": "", "legacy_script": legacy})),
        expected
    );
    assert_eq!(
        decide(json!({"source": "bundled:\n", "legacy_script": legacy})),
        expected
    );
    assert_eq!(
        decide(json!({"source": "file:relative/agent.rss", "legacy_script": legacy})),
        expected
    );
    assert_eq!(
        decide(json!({"source": "file:/", "legacy_script": legacy})),
        expected
    );
}

#[test]
fn explicit_unsupported_source_is_unsupported_without_fallback() {
    let legacy = "/legacy/agent.rss";
    let expected = failure("unsupported_agent_source", "agent source is unsupported");
    assert_eq!(
        decide(json!({"source": "other:thing", "legacy_script": legacy})),
        expected
    );
    assert_eq!(
        decide(json!({"source": "bundled:other", "legacy_script": legacy})),
        expected
    );
    assert_eq!(
        decide(json!({"source": "/bare/path/agent.rss", "legacy_script": legacy})),
        expected
    );
}

#[test]
fn oversized_explicit_source_is_invalid() {
    let oversized = format!("bundled:{}", "a".repeat(4096));
    assert!(oversized.chars().count() > 4096);
    assert_eq!(
        decide(json!({"source": oversized})),
        failure("invalid_agent_source", "agent source is invalid")
    );
    for scalar in ["a", "界"] {
        let source = format!("file:/{}", scalar.repeat(4091));
        assert_eq!(source.chars().count(), 4097);
        assert_eq!(
            decide(json!({"source": source})),
            failure("invalid_agent_source", "agent source is invalid")
        );
    }
}

#[test]
fn explicit_file_source_at_scalar_limit_is_accepted() {
    for scalar in ["a", "界"] {
        let path = format!("/{}", scalar.repeat(4090));
        let source = format!("file:{path}");
        assert_eq!(source.chars().count(), 4096);
        if scalar == "界" {
            assert!(source.len() > 4096);
        }
        assert_eq!(
            decide(json!({"source": source})),
            file_success(&format!("file:{path}"), &path, false)
        );
    }
}

#[test]
fn invalid_legacy_without_explicit_source_is_reported() {
    let expected = failure(
        "invalid_legacy_agent_source",
        "legacy agent source is invalid",
    );
    assert_eq!(decide(json!({"legacy_script": 12})), expected);
    assert_eq!(decide(json!({"legacy_script": ""})), expected);
    assert_eq!(
        decide(json!({"legacy_script": "relative/agent.rss"})),
        expected
    );
    assert_eq!(decide(json!({"legacy_script": "/"})), expected);
    assert_eq!(decide(json!({"legacy_script": "/legacy\n.rss"})), expected);
}

#[test]
fn failure_output_does_not_echo_hostile_input() {
    let hostile = "<script>alert(1)</script>?source=\u{0}evil";
    let result = decide(json!({"source": hostile}));
    assert_eq!(
        result,
        failure("invalid_agent_source", "agent source is invalid")
    );
    let encoded = result.to_string();
    assert!(!encoded.contains(hostile));
    assert!(!encoded.contains("script"));
    assert!(!encoded.contains("evil"));
    assert!(
        !result
            .as_object()
            .expect("failure is an object")
            .contains_key("source")
    );
}
