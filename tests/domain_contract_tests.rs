use rustscript_agent::RunContext;
use rustscript_agent::domain::{self, LlmContentBlock, LlmMessage, LlmRequest, Sampling};
use rustscript_agent::tools::ToolDescriptor;
use rustscript_vm::Value as VmValue;
use serde_json::{Value, json};

#[test]
fn domain_and_tools_paths_expose_one_descriptor_type() {
    let descriptor = ToolDescriptor::new(
        "read_file",
        "Read bounded text from a workspace file",
        "coding",
        "read",
        json!({
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}}
        }),
    );

    let domain_descriptor: domain::ToolDescriptor = descriptor.clone();
    let tools_descriptor: ToolDescriptor = domain_descriptor;
    assert_eq!(tools_descriptor, descriptor);
}

#[test]
fn provider_request_serialization_keeps_the_existing_descriptor_wire_shape() {
    let request = LlmRequest {
        model: "test-model".to_string(),
        messages: vec![LlmMessage {
            role: "user".to_string(),
            content: vec![LlmContentBlock {
                block_type: "text".to_string(),
                text: Some("hello".to_string()),
                ..Default::default()
            }],
        }],
        tools: vec![ToolDescriptor::new(
            "read_file",
            "Read bounded text from a workspace file",
            "coding",
            "read",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {"path": {"type": "string"}}
            }),
        )],
        tool_choice: None,
        reasoning: None,
        sampling: Some(Sampling {
            temperature: None,
            top_p: None,
        }),
        max_output_tokens: Some(128),
        stream: false,
        provider_options: Value::Object(Default::default()),
    };

    let wire = serde_json::to_value(request).expect("request should serialize");
    assert_eq!(wire["tools"][0]["name"], json!("read_file"));
    assert_eq!(wire["tools"][0]["toolset"], json!("coding"));
    assert_eq!(wire["tools"][0]["risk_class"], json!("read"));
    assert_eq!(wire["tools"][0]["schema"]["required"], json!(["path"]));
}

fn sample_run_context(coding_system_prompt: Option<&str>) -> RunContext {
    RunContext {
        run_id: "run-fixture".to_string(),
        session_id: "session-fixture".to_string(),
        parent_run_id: None,
        platform: "api_server".to_string(),
        input: json!({"message": "hello"}),
        messages: json!([{
            "role": "user",
            "content": [{"type": "text", "text": "hello"}]
        }]),
        system_prompt: None,
        model: "test-model".to_string(),
        provider: Some("openai".to_string()),
        provider_options: json!({}),
        tool_schemas: json!([]),
        limits: json!({"max_turns": 3}),
        metadata: json!({}),
        coding_system_prompt: coding_system_prompt.map(str::to_string),
    }
}

fn vm_field<'a>(value: &'a VmValue, key: &str) -> Option<&'a VmValue> {
    let VmValue::Map(entries) = value else {
        panic!("run context vm value should be a map");
    };
    entries.iter().find_map(|(name, field)| match name {
        VmValue::String(name) if name.to_string() == key => Some(field),
        _ => None,
    })
}

#[test]
fn to_vm_value_includes_optional_coding_system_prompt() {
    let frozen = "FROZEN-CODING-PROMPT-v1\nExact bytes.";
    let rendered = sample_run_context(Some(frozen)).to_vm_value();
    match vm_field(&rendered, "coding_system_prompt") {
        Some(VmValue::String(text)) => assert_eq!(text.as_bytes(), frozen.as_bytes()),
        other => panic!("coding_system_prompt should be a string, got {other:?}"),
    }

    match vm_field(
        &sample_run_context(None).to_vm_value(),
        "coding_system_prompt",
    ) {
        Some(VmValue::Null) => {}
        other => panic!("absent coding_system_prompt should render as null, got {other:?}"),
    }

    match vm_field(
        &sample_run_context(Some("")).to_vm_value(),
        "coding_system_prompt",
    ) {
        Some(VmValue::String(text)) => assert_eq!(text.as_bytes(), b""),
        other => panic!("empty coding_system_prompt should render as empty string, got {other:?}"),
    }
}

#[test]
fn reconstructed_persisted_run_context_retains_frozen_coding_prompt() {
    let frozen = "FROZEN-CODING-PROMPT-v1\nExact bytes.";
    let original = sample_run_context(Some(frozen));
    let restored: RunContext = serde_json::from_value(
        serde_json::to_value(&original).expect("run context should serialize"),
    )
    .expect("run context should deserialize");
    assert_eq!(restored.coding_system_prompt.as_deref(), Some(frozen));
    match vm_field(&restored.to_vm_value(), "coding_system_prompt") {
        Some(VmValue::String(text)) => assert_eq!(text.as_bytes(), frozen.as_bytes()),
        other => panic!("restored coding_system_prompt should reach the vm map, got {other:?}"),
    }
}
