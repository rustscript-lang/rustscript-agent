//! Production Responses/tool-loop recovery, with fixture HTTP and real tools.
#![cfg(feature = "config-fixture")]
#[path = "support/opaque_chat_stream.rs"]
#[allow(dead_code)]
mod opaque_chat_stream;
#[path = "support/provider_opaque_fixture.rs"]
#[allow(dead_code)]
mod provider_opaque_fixture;
use opaque_chat_stream::StreamTransport;
use provider_opaque_fixture::FixtureHome;
use rustscript_agent::auth::oauth::{
    BoundedHttpsStream, BoundedHttpsTransport, OAuthError, OAuthIoContext, PreparedHttpsRequest,
    RawHttpsResponse,
};
use rustscript_agent::config::ProviderProfile;
use rustscript_agent::{AdmitRunRequest, AgentGatewayConfig, AgentGatewayState};
use serde_json::{Value, json};
use std::{
    collections::{HashSet, VecDeque},
    fs,
    sync::{Arc, Mutex},
    time::Duration,
};

const PROVIDER: &str = "openai-codex";
const BASE: &str = "https://chatgpt.com/backend-api/codex";
struct TranscriptTransport {
    replies: Mutex<VecDeque<Arc<StreamTransport>>>,
    sent: Mutex<Vec<Value>>,
    violations: Mutex<Vec<String>>,
}
impl BoundedHttpsTransport for TranscriptTransport {
    fn send(
        &self,
        _: &PreparedHttpsRequest,
        _: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        panic!("Responses must stream")
    }
    fn start_stream(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<Box<dyn BoundedHttpsStream>, OAuthError> {
        let wire: Value = serde_json::from_str(&request.body).unwrap();
        let input = wire["input"].as_array().unwrap();
        let mut calls = HashSet::new();
        let mut outputs = HashSet::new();
        for item in input {
            if item["type"] == "function_call" {
                assert!(calls.insert(item["call_id"].as_str().unwrap().to_string()));
            }
            if item["type"] == "function_call_output" {
                assert!(outputs.insert(item["call_id"].as_str().unwrap().to_string()));
            }
        }
        self.sent.lock().unwrap().push(wire);
        if calls != outputs {
            self.violations
                .lock()
                .unwrap()
                .push("orphaned function call in actual outgoing input".into());
            return Err(OAuthError::Transport {
                message: "unpaired function call".into(),
            });
        }
        let next = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("no unintended provider request");
        next.start_stream(request, context)
    }
}
fn reply(output: Value) -> Arc<StreamTransport> {
    let response = json!({"id":"resp_fixture", "status":"completed", "model":"fixture-model", "output":output, "usage":{"input_tokens":2,"output_tokens":2,"total_tokens":4}});
    let frame = format!(
        "data: {}\n\n",
        json!({"type":"response.completed","response":response})
    );
    Arc::new(StreamTransport::new(
        200,
        "text/event-stream",
        vec![frame.into_bytes()],
        true,
    ))
}
fn call(id: &str, name: &str, args: Value) -> Arc<StreamTransport> {
    reply(
        json!([{"type":"function_call","id":format!("fc_{id}"),"call_id":id,"name":name,"arguments":args.to_string()}]),
    )
}
fn text(s: &str) -> Arc<StreamTransport> {
    reply(
        json!([{"type":"message","id":"msg_fixture","status":"completed","role":"assistant","content":[{"type":"output_text","text":s}]}]),
    )
}
struct Root(std::path::PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn validation_failure_has_durable_output_before_next_responses_turn() {
    let root = Root(
        std::path::PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
            .join(format!("real-continuation-{}", uuid::Uuid::new_v4())),
    );
    let project = root.0.join("project");
    let config_home = root.0.join("workspace-home");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&config_home).unwrap();
    let config = format!(
        "version: 1\nmodel:\n  provider: {PROVIDER}\n  model: fixture-model\nproviders:\n  {PROVIDER}:\n    protocol: codex-responses\n    base_url: '{BASE}'\nworkspaces:\n  allowed_roots: ['{}']\n  default: '{}'\n",
        project.display(),
        project.display()
    );
    fs::write(config_home.join("config.yaml"), config).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            config_home.join("config.yaml"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let allow = r#"{"outcome":"allow","risk_level":"low","user_authorization":"high","rationale":"explicit bounded task"}"#;
    let transport = Arc::new(TranscriptTransport {
        replies: Mutex::new(VecDeque::from([
            call(
                "bad-search",
                "search_files",
                json!({"pattern":"*","target":"files","path":"."}),
            ),
            call(
                "write",
                "write_file",
                json!({"path":"note.txt","content":"REAL_TOOL_VALUE"}),
            ),
            text(allow),
            call("read", "read_file", json!({"path":"note.txt"})),
            Arc::new(
                StreamTransport::new(200, "text/event-stream", vec![], true)
                    .with_read_error("synthetic transient read failure"),
            ),
            call("process", "terminal", json!({"argv":["/bin/pwd"],"cwd":""})),
            text(allow),
            text("TASK_FINISHED"),
        ])),
        sent: Mutex::new(vec![]),
        violations: Mutex::new(vec![]),
    });
    let home = FixtureHome::for_profile(
        "real-continuation",
        PROVIDER,
        BASE,
        "fixture-access",
        "SYNTHETIC_ACCESS",
    );
    let state = AgentGatewayState::with_agent_file_and_sqlite(
        AgentGatewayConfig {
            provider: Some(PROVIDER.into()),
            model: "fixture-model".into(),
            run_timeout: Duration::from_secs(30),
            ..Default::default()
        },
        rustscript_agent::bundled_agent_main_path(),
        root.0.join("agent.sqlite"),
    )
    .unwrap()
    .with_workspace_home(config_home);
    let service = state.service();
    service.set_auth_host_factory(home.auth_factory(transport.clone()));
    service
        .set_tool_registry(rustscript_agent::bundled_tool_registry().unwrap())
        .unwrap();
    service.upsert_provider_profile(ProviderProfile::new(PROVIDER,json!({"profile":PROVIDER,"protocol":"codex-responses","base_url":BASE,"credential_id":"fixture-access"})).unwrap());
    let run=service.admit(AdmitRunRequest{input:json!("Create note.txt with REAL_TOOL_VALUE, read it, and run pwd in the workspace. Recover from invalid arguments."),provider:Some(PROVIDER.into()),model:Some("fixture-model".into()),..Default::default()}).await.unwrap();
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    let events = service.run_events(&run.run_id);
    assert!(
        transport.violations.lock().unwrap().is_empty(),
        "wire pairing violations: {:?}",
        transport.violations.lock().unwrap()
    );
    assert!(
        events.iter().any(|e| e["event"] == "run.completed"),
        "{events:?}"
    );
    assert_eq!(
        fs::read_to_string(project.join("note.txt")).unwrap(),
        "REAL_TOOL_VALUE"
    );
    let sent = transport.sent.lock().unwrap();
    assert_eq!(sent.len(), 8);
    let contract = sent[0]["instructions"].as_str().unwrap();
    assert!(
        contract.contains("workspace-relative")
            && contract.contains("empty environment")
            && contract.contains("nonempty pattern")
    );
    assert_eq!(
        sent[4], sent[5],
        "retry reuses the same provider turn and does not repeat completed tools"
    );
    let output = sent[1]["input"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["type"] == "function_call_output" && item["call_id"] == "bad-search")
        .unwrap();
    assert!(
        output["output"].as_str().unwrap().contains("path_denied"),
        "error must reach model: {output}"
    );
    let messages = service.session_messages(&run.session_id);
    assert_eq!(
        messages
            .iter()
            .filter(|m| m["tool_call_id"] == "bad-search")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e["event"] == "tool.started" && e["data"]["tool_call_id"] == "bad-search")
            .count(),
        0,
        "validation failure must not mint an execution token"
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e["event"] == "tool.completed")
            .count(),
        3
    );
    drop(sent);
    drop(service);
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(
        AgentGatewayConfig::default(),
        root.0.join("agent.sqlite"),
    )
    .unwrap();
    let restored = reopened.service().session_messages(&run.session_id);
    assert_eq!(
        restored
            .iter()
            .filter(|m| m["tool_call_id"] == "bad-search")
            .count(),
        1,
        "rejection survives real SDK restart"
    );
}
