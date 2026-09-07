use rustscript_agent::domain::{self, LlmContentBlock, LlmMessage, LlmRequest, Sampling};
use rustscript_agent::tools::ToolDescriptor;
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
