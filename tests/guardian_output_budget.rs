#![cfg(feature = "config-fixture")]

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustscript_agent::auth::{
    host::AuthHost,
    oauth::{
        OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
        ScriptedHttpsTransport,
    },
};
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner, RunCancellation};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

const REVIEW_ENTRY: &str = r#"use super::agent::guardian;

pub fn run(context: map) -> map {
    let input: string = context["input"];
    let coding_prompt: string = context["coding_system_prompt"];
    let system_prompt: string = context["system_prompt"];
    let provider: string = context["provider"];
    let model: string = context["model"];
    let credential_id: string = context["credential_id"];
    let limits: map = context["limits"].copy();
    let review_context: map = {
        input: input,
        coding_system_prompt: coding_prompt,
        system_prompt: system_prompt,
        provider: provider,
        model: model,
        credential_id: credential_id,
        reasoning: "",
        sampling: {},
        limits: limits
    };
    let action: map = {
        tool_name: "terminal",
        risk_class: "medium",
        arguments: { argv: ["ls"] },
        arguments_json: "{\"argv\":[\"ls\"]}",
        _provider_step_key: "review:guardian-approval:budget-run:budget-call"
    };
    guardian::review(review_context, action)
}
"#;

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new() -> Self {
        let root = assigned_tmp();
        let home = root.join(format!("guardian-budget-home-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&home).expect("create private fixture home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        let config = fs::read_to_string(fixture.join("config.yaml"))
            .expect("read config fixture")
            .replace("openai-codex", "openai")
            .replace(
                "https://chatgpt.com/backend-api/codex",
                "https://api.openai.com/v1",
            )
            .replace("fixture-codex", "synthetic-openai");
        fs::write(home.join("config.yaml"), config).expect("write private config fixture");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read auth fixture")
            .replace("1788440000000", "1900003600000")
            .replace("openai-codex", "openai")
            .replace("fixture-codex", "synthetic-openai")
            .replace("SYNTHETIC_ACCESS_TOKEN", "SYNTHETIC_OPENAI_ACCESS");
        fs::write(home.join("auth.yaml"), auth).expect("write private auth fixture");
        #[cfg(unix)]
        {
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                    .expect("fixture file mode");
            }
        }
        Self(home)
    }
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ReviewModules {
    root: PathBuf,
    entry: PathBuf,
}

impl ReviewModules {
    fn new() -> Self {
        let production = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/guardian.rss");
        let source = fs::read(&production).expect("read production guardian.rss");
        let root = assigned_tmp().join(format!("guardian-budget-modules-{}", uuid::Uuid::new_v4()));
        let agent = root.join("rss").join("agent");
        fs::create_dir_all(&agent).expect("create review module tree");
        let copied = agent.join("guardian.rss");
        fs::write(&copied, &source).expect("write production guardian bytes");
        assert_eq!(
            fs::read(&copied).expect("reread copied guardian"),
            fs::read(&production).expect("reread production guardian"),
            "review must execute the current production guardian.rss bytes"
        );
        let entry = agent.join("entry.rss");
        fs::write(&entry, REVIEW_ENTRY).expect("write review entry");
        Self { root, entry }
    }
}

impl Drop for ReviewModules {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assigned_tmp() -> PathBuf {
    PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture temp"))
}

fn review_runner(
    home: &FixtureHome,
    modules: &ReviewModules,
    transport: Arc<ScriptedHttpsTransport>,
) -> AgentRunner {
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        clock,
        Arc::new(ScriptedCancel::new()),
    ));
    let home_path = home.0.clone();
    let factory = Arc::new(move |cancellation: RunCancellation| {
        AuthHost::new(home_path.clone(), cancellation)
            .map(|host| host.with_oauth_host(Arc::clone(&oauth)))
    });
    let bridges = AgentHostBridges {
        auth_host_factory: Some(factory),
        ..AgentHostBridges::default()
    };
    AgentRunner::from_file(&modules.entry, AgentConfig::default())
        .expect("compile production guardian review entry")
        .with_host(bridges)
        .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)))
}

fn json_to_vm_value(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(value) => Value::Bool(*value),
        JsonValue::Number(value) => {
            if let Some(value) = value.as_i64() {
                Value::Int(value)
            } else {
                Value::Float(value.as_f64().expect("finite JSON number"))
            }
        }
        JsonValue::String(value) => Value::string(value),
        JsonValue::Array(values) => {
            Value::Array(Arc::new(values.iter().map(json_to_vm_value).collect()))
        }
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
                .filter_map(|(key, value)| match key {
                    Value::String(key) => Some((key.to_string(), vm_value_to_json(value))),
                    _ => None,
                })
                .collect(),
        ),
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn review_context_with(input: &str) -> Value {
    json_to_vm_value(&json!({
        "input": input,
        "coding_system_prompt": "Coding contract: use the admitted terminal tool for the requested directory listing.",
        "system_prompt": "Constraints: do not widen the admitted action.",
        "provider": "openai",
        "model": "guardian-review-model",
        "credential_id": "synthetic-openai",
        "limits": {
            "max_turns": 8,
            "max_tool_calls": 32,
            "max_tool_output_bytes": 4096,
            "workspace_root": assigned_tmp().join("guardian-budget-workspace").to_string_lossy().into_owned()
        }
    }))
}

fn review_context() -> Value {
    review_context_with("List the current directory.")
}

fn allow_assessment() -> JsonValue {
    json!({
        "id": "chatcmpl-guardian-budget",
        "choices": [{
            "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": "{\"outcome\":\"allow\",\"risk_level\":\"low\",\"user_authorization\":\"high\",\"rationale\":\"directory listing is explicitly requested\"}"
            }
        }],
        "usage": {"prompt_tokens": 20, "completion_tokens": 18, "total_tokens": 38}
    })
}

#[test]
fn production_guardian_review_wires_output_budget_1024() {
    let home = FixtureHome::new();
    let modules = ReviewModules::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, allow_assessment());
    let runner = review_runner(&home, &modules, Arc::clone(&transport));
    let outcome = vm_value_to_json(
        &runner
            .run_with_context(review_context())
            .expect("production guardian::review should reach the opaque provider"),
    );
    assert_eq!(
        outcome["code"],
        json!("guardian_allowed"),
        "scripted allow assessment should satisfy the fixed policy, got {outcome}"
    );

    let sent = transport.take_sent();
    assert_eq!(
        sent.len(),
        1,
        "reviewer_request sends one buffered completion"
    );
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("wire body is JSON");
    let system = wire["messages"][0]["content"]
        .as_str()
        .expect("production system text");
    assert!(
        system.starts_with("You are Guardian, reviewing one proposed tool action."),
        "wire system text must be the production Guardian policy"
    );
    let user = wire["messages"][1]["content"][0]["text"]
        .as_str()
        .expect("production user text");
    assert!(
        user.contains("List the current directory."),
        "wire user text must keep the admitted user request"
    );
    assert!(
        user.contains("Coding contract: use the admitted terminal tool"),
        "wire user text must keep the coding prompt framing"
    );
    assert!(
        wire.get("tools").is_none(),
        "reviewer_request must not offer tools"
    );
    assert_eq!(
        wire["max_tokens"],
        json!(1024),
        "production reviewer_request wire max_tokens must be the bounded Guardian output budget"
    );
}

fn chat_text(text: &str) -> JsonValue {
    json!({
        "id": "chatcmpl-control",
        "choices": [{
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": text}
        }],
        "usage": {"prompt_tokens": 12, "completion_tokens": 9, "total_tokens": 21}
    })
}

fn assert_closed(outcome: &JsonValue, code: &str) {
    assert_eq!(
        outcome["ok"],
        json!(false),
        "fail-closed review must not allow, got {outcome}"
    );
    assert_eq!(
        outcome["code"],
        json!(code),
        "typed failure must stay on the existing code, got {outcome}"
    );
}

fn assert_review_wires(sent: &[rustscript_agent::auth::oauth::PreparedHttpsRequest], count: usize) {
    assert_eq!(sent.len(), count, "provider call count");
    for request in sent {
        assert_eq!(request.method, "POST");
        assert_eq!(request.url, "https://api.openai.com/v1/chat/completions");
        let wire: JsonValue = serde_json::from_str(&request.body).expect("wire body is JSON");
        assert!(
            wire.get("tools").is_none(),
            "failure path must not offer tools"
        );
        assert_eq!(wire["max_tokens"], json!(1024));
    }
}

fn run_scripted(
    responses: Vec<JsonValue>,
    context: Value,
) -> (
    JsonValue,
    Vec<rustscript_agent::auth::oauth::PreparedHttpsRequest>,
) {
    let home = FixtureHome::new();
    let modules = ReviewModules::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    for response in responses {
        transport.push_json(200, response);
    }
    let runner = review_runner(&home, &modules, Arc::clone(&transport));
    let outcome = vm_value_to_json(
        &runner
            .run_with_context(context)
            .expect("production guardian::review"),
    );
    (outcome, transport.take_sent())
}

#[test]
fn production_guardian_review_denies_without_starting_tools() {
    let (outcome, sent) = run_scripted(
        vec![chat_text(
            "{\"outcome\":\"deny\",\"risk_level\":\"high\",\"user_authorization\":\"low\",\"rationale\":\"the requested action is outside the admitted directory listing\"}",
        )],
        review_context(),
    );
    assert_closed(&outcome, "guardian_denied");
    assert_review_wires(&sent, 1);
}

#[test]
fn production_guardian_review_policy_denies_critical_risk() {
    let (outcome, sent) = run_scripted(
        vec![chat_text(
            "{\"outcome\":\"allow\",\"risk_level\":\"critical\",\"user_authorization\":\"high\",\"rationale\":\"critical risk stays denied by the fixed policy\"}",
        )],
        review_context(),
    );
    assert_closed(&outcome, "guardian_policy_denied");
    assert_review_wires(&sent, 1);
}

#[test]
fn production_guardian_review_malformed_assessment_fails_closed() {
    let (outcome, sent) = run_scripted(vec![chat_text("not an assessment"); 3], review_context());
    assert_closed(&outcome, "guardian_malformed_assessment");
    assert_review_wires(&sent, 3);
}

#[test]
fn production_guardian_review_empty_choices_fail_closed() {
    let (outcome, sent) = run_scripted(
        vec![json!({
            "id": "chatcmpl-empty",
            "choices": [],
            "usage": {"prompt_tokens": 40, "completion_tokens": 1024, "total_tokens": 1064}
        })],
        review_context(),
    );
    assert_closed(&outcome, "guardian_provider_failed");
    assert_review_wires(&sent, 1);
}

#[test]
fn production_guardian_review_missing_input_does_not_call_provider() {
    let (outcome, sent) = run_scripted(Vec::new(), review_context_with(""));
    assert_closed(&outcome, "guardian_context_unavailable");
    assert!(
        sent.is_empty(),
        "unavailable context must not start a provider call"
    );
}
