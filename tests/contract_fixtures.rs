use std::fs;

use rustscript_agent::domain::{
    AgentEventEnvelope, InboundEnvelope, LlmEvent, LlmRequest, LlmResponse, ProviderError,
    ToolDescriptor, Usage,
};
use rustscript_agent::{AgentConfig, AgentRunner, RunContext};
use serde_json::Value;

const FIXTURES: &[(&str, &str)] = &[
    ("inbound_envelope.json", "platform"),
    ("llm_request.json", "model"),
    ("llm_event.json", "type"),
    ("llm_response.json", "id"),
    ("provider_error.json", "code"),
    ("tool_call.json", "name"),
    ("run_event.json", "type"),
    ("run_context.json", "run_id"),
    ("usage.json", "input_tokens"),
];

fn fixtures_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("contracts")
}

#[test]
fn canonical_contract_fixtures_are_valid_json_with_required_discriminators() {
    for (file, discriminator) in FIXTURES {
        let path = fixtures_root().join(file);
        let source = fs::read_to_string(&path).expect("contract fixture should be readable");
        let value: Value = serde_json::from_str(&source).expect("contract fixture should be JSON");
        assert!(value.is_object(), "{file} must contain a JSON object");
        assert!(
            value.get(*discriminator).is_some(),
            "{file} must contain its {discriminator} discriminator"
        );
    }
}

#[test]
fn canonical_fixtures_deserialize_into_the_frozen_typed_contracts() {
    let inbound: InboundEnvelope = read_fixture("inbound_envelope.json");
    assert_eq!(inbound.platform, "api_server");
    assert_eq!(inbound.profile, "default");
    assert_eq!(inbound.account_id, "account-test");
    assert_eq!(inbound.content, "hello");
    assert!(inbound.attachments.is_empty());

    let run_context: RunContext = read_fixture("run_context.json");
    assert_eq!(run_context.run_id, "run-fixture");
    assert_eq!(run_context.platform, "api_server");
    assert_eq!(
        run_context.input,
        Value::String("hello from fixture".to_string())
    );
    assert_eq!(run_context.tool_schemas, Value::Array(vec![]));
    assert_eq!(run_context.limits["max_events"], 8192);

    let request: LlmRequest = read_fixture("llm_request.json");
    assert_eq!(request.model, "test-model");
    assert_eq!(request.messages[0].role, "user");
    assert_eq!(
        request.messages[0].content[0].text.as_deref(),
        Some("hello")
    );
    assert_eq!(request.max_output_tokens, Some(128));
    assert!(!request.stream);

    let event: LlmEvent = read_fixture("llm_event.json");
    let tool_call = event.tool_call.expect("llm event must carry the tool call");
    assert_eq!(tool_call.name, "read_file");
    assert_eq!(tool_call.id, "call-test");
    assert_eq!(event.sequence, 3);

    let tool: ToolDescriptor = read_fixture("tool_call.json");
    assert_eq!(tool.name, "read_file");
    assert_eq!(tool.risk_class, "read");
    assert_eq!(tool.toolset, "file");
    assert!(tool.schema.get("required").is_some());

    let run_event: AgentEventEnvelope = read_fixture("run_event.json");
    assert_eq!(run_event.event_type, "run.completed");
    assert_eq!(run_event.status, "completed");
    assert_eq!(run_event.sequence, 4);
    assert!(run_event.error.is_none());

    let usage: Usage = read_fixture("usage.json");
    assert_eq!(usage.input_tokens, 5);
    assert_eq!(usage.output_tokens, 7);
    assert_eq!(usage.total_tokens, 12);

    let response: LlmResponse = read_fixture("llm_response.json");
    assert_eq!(response.id, "resp-test");
    assert_eq!(response.model, "test-model");
    assert_eq!(
        response.content[0].text.as_deref(),
        Some("hello from the provider")
    );
    assert!(response.tool_calls.is_empty());
    assert_eq!(response.usage.total_tokens, 12);
    assert_eq!(response.finish_reason.as_deref(), Some("stop"));

    let provider_error: ProviderError = read_fixture("provider_error.json");
    assert_eq!(provider_error.code, "rate_limited");
    assert!(provider_error.retryable);
    assert_eq!(provider_error.status_code, Some(429));
    assert!(provider_error.raw.get("error").is_some());
}

#[test]
fn run_context_fixture_is_executed_through_the_exported_entry_unchanged() {
    // The A0 run-context fixture is executable: it drives a real RSS run, and
    // the exported `run(context)` must receive the exact structured context.
    let context: RunContext = read_fixture("run_context.json");
    let runner = AgentRunner::from_source(
        "pub fn run(input: map) -> map { input; }",
        AgentConfig::default(),
    )
    .expect("fixture agent should compile");
    let result = runner
        .run_with_context(context.to_vm_value())
        .expect("fixture context should run through the exported entry");
    assert_eq!(
        result,
        context.to_vm_value(),
        "the exact structured fixture context must reach run(context) unchanged"
    );
}

fn read_fixture<T: serde::de::DeserializeOwned>(file: &str) -> T {
    let path = fixtures_root().join(file);
    let source = fs::read_to_string(&path).expect("contract fixture should be readable");
    serde_json::from_str(&source)
        .unwrap_or_else(|error| panic!("{file} must deserialize into its typed contract: {error}"))
}
