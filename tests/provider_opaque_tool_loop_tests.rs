//! Authenticated real RSS tool follow-up and retry without re-execution.
#![cfg(feature = "config-fixture")]
#[path = "support/provider_opaque_fixture.rs"]
#[allow(dead_code)]
mod provider_opaque_fixture;
use parking_lot::Mutex;
use provider_opaque_fixture::{FixtureHome, json_to_vm_value, vm_value_to_json};
use rustscript_agent::auth::oauth::ScriptedHttpsTransport;
use rustscript_agent::capabilities::{
    AllowAllApproval, ArtifactCapability, ArtifactLimits, CapabilityLifecycle, CapabilityOwner,
    DurableStarted, DurableToolLifecycle, FilesystemCapability, FilesystemLimits, LifecycleClock,
    LifecycleError, LifecycleLimits, NeverCancelled, ProcessCapability, ProcessLimits, SystemClock,
    TokenIssuer, UuidIssuer,
};
use rustscript_agent::{
    AgentConfig, AgentHostBridges, AgentRunner, RunCancellation, bundled_tool_registry,
};
use serde_json::{Value as JsonValue, json};
use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
const ID: &str = "synthetic-openai";
const ACCESS: &str = "SYNTHETIC_TOOL_LOOP_ACCESS";
const NOTE: &str = "actual filesystem result through authenticated followup";
#[derive(Default)]
struct ReadLifecycle {
    starts: AtomicU64,
    commits: AtomicU64,
    results: Mutex<HashMap<String, JsonValue>>,
}
impl DurableToolLifecycle for ReadLifecycle {
    fn assert_active_run(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn prepare_parent(&self, _: &str, _: &str, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn replay_result(
        &self,
        _: &str,
        call_id: &str,
        _: &str,
    ) -> Result<Option<JsonValue>, LifecycleError> {
        Ok(self.results.lock().get(call_id).cloned())
    }
    fn commit_started(&self, record: &DurableStarted) -> Result<(), LifecycleError> {
        assert_eq!(record.tool_name, "read_file");
        self.starts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn commit_result(
        &self,
        call_id: &str,
        result: &JsonValue,
    ) -> Result<JsonValue, LifecycleError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        self.results
            .lock()
            .insert(call_id.to_string(), result.clone());
        Ok(json!({"ok": true, "kind": "committed", "call_id": call_id, "result": result}))
    }
    fn interrupt(&self, _: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}
struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let root = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"),
        )
        .join(format!("authenticated-tool-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("confined test workspace");
        fs::write(root.join("note.txt"), NOTE).expect("seed real file");
        Self(root)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn tool_host(workspace: &Workspace, durable: Arc<ReadLifecycle>) -> AgentHostBridges {
    let owner = CapabilityOwner::new("profile-loop", "session-loop", "run-loop").expect("owner");
    let identity = bundled_tool_registry()
        .expect("actual RSS registry")
        .identity()
        .to_string();
    let clock = Arc::new(SystemClock);
    let deadline_ms = clock.now_ms() + 30_000;
    let lifecycle = Arc::new(
        CapabilityLifecycle::builder()
            .owner(owner.clone())
            .registry_identity(identity)
            .workspace(&workspace.0)
            .limits(LifecycleLimits {
                max_tool_calls: 8,
                max_output_bytes: 64 * 1024,
                max_summary_bytes: 256,
            })
            .deadline_ms(deadline_ms)
            .clock(clock)
            .tokens(Arc::new(UuidIssuer) as Arc<dyn TokenIssuer>)
            .durable(durable)
            .approval(Arc::new(AllowAllApproval))
            .cancellation(Arc::new(NeverCancelled))
            .build()
            .expect("native capability lifecycle"),
    );
    let filesystem = Arc::new(
        FilesystemCapability::new(
            lifecycle.as_ref().clone(),
            owner.clone(),
            FilesystemLimits::default(),
        )
        .expect("real filesystem"),
    );
    let processes = Arc::new(
        ProcessCapability::new(
            lifecycle.as_ref().clone(),
            owner.clone(),
            ProcessLimits::default(),
        )
        .expect("real process capability"),
    );
    let artifacts = Arc::new(
        ArtifactCapability::new(
            lifecycle.as_ref().clone(),
            owner.clone(),
            ArtifactLimits {
                max_object_bytes: 8 * 1024 * 1024,
                max_total_bytes: 64 * 1024 * 1024,
                max_objects: 64,
            },
        )
        .expect("real artifact capability"),
    );
    AgentHostBridges {
        lifecycle: Some(lifecycle),
        capability_owner: Some(owner),
        filesystem: Some(filesystem),
        processes: Some(processes),
        artifacts: Some(artifacts),
        ..AgentHostBridges::default()
    }
}
fn run_tool_followup(retry: bool) {
    let home = FixtureHome::for_profile(
        "tool-followup",
        "openai",
        "https://api.openai.com/v1",
        ID,
        ACCESS,
    );
    let workspace = Workspace::new();
    let durable = Arc::new(ReadLifecycle::default());
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, json!({"id": "tool-model", "choices": [{"finish_reason": "tool_calls", "message": {
        "role": "assistant", "content": null, "tool_calls": [{"id": "read-1", "type": "function",
            "function": {"name": "read_file", "arguments": "{\"path\":\"note.txt\"}"}}]
    }}]}));
    if retry {
        transport.push_json(429, json!({"error": {"message": "rate limit", "type": "rate_limit_error", "code": "rate_limit_exceeded"}}));
    }
    transport.push_json(
        200,
        json!({"id": "done-model", "choices": [{"finish_reason": "stop", "message": {
            "role": "assistant", "content": "tool-followup answer"
        }}]}),
    );
    let mut bridges = tool_host(&workspace, durable.clone());
    bridges.auth_host_factory = Some(home.auth_factory(transport.clone()));
    let runner = AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/main.rss"),
        AgentConfig::default(),
    )
    .expect("compile real main")
    .with_host(bridges)
    .with_skip_sleep(true)
    .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)));
    let tools = bundled_tool_registry()
        .expect("real tool registry")
        .snapshot()
        .schemas();
    let decision = vm_value_to_json(&runner.run_with_context(json_to_vm_value(&json!({
        "profile_id": "profile-loop", "session_id": "session-loop", "run_id": "run-loop",
        "metadata": {"registry_identity": bundled_tool_registry().expect("real admitted registry").identity()},
        "credential_id": ID, "provider": "openai", "model": "request-model", "tools": tools,
        "input": {"message": "read note.txt"}, "config": {"max_retries": 2},
        "limits": {"max_turns": 8, "max_tool_calls": 8}
    }))).expect("actual tool loop decision"));
    assert_eq!(
        decision["kind"],
        json!("run.completed"),
        "public decision: {decision}"
    );
    assert_eq!(decision["answer"], json!("tool-followup answer"));
    assert_eq!(
        durable.starts.load(Ordering::SeqCst),
        1,
        "one actual admitted tool start; public decision: {decision}"
    );
    assert_eq!(
        durable.commits.load(Ordering::SeqCst),
        1,
        "one actual tool result committed"
    );
    let sent = transport.take_sent();
    assert_eq!(sent.len(), if retry { 3 } else { 2 });
    for request in &sent {
        assert_eq!(request.url, "https://api.openai.com/v1/chat/completions");
        assert_eq!(request.method, "POST");
        assert!(
            request
                .headers
                .get("authorization")
                .is_some_and(|v| v == &format!("Bearer {ACCESS}")),
            "native auth on every request"
        );
        assert!(
            !request.body.contains(ACCESS),
            "public wire must not contain access token"
        );
    }
    let followup: JsonValue = serde_json::from_str(&sent[1].body).expect("public followup JSON");
    let messages = followup["messages"].as_array().expect("followup messages");
    let results: Vec<_> = messages.iter().filter(|m| m["role"] == "tool").collect();
    assert_eq!(results.len(), 1, "one tool result in followup history");
    assert_eq!(results[0]["tool_call_id"], json!("read-1"));
    assert!(
        results[0]["content"]
            .as_str()
            .is_some_and(|v| v.contains(NOTE)),
        "real filesystem output forwarded"
    );
    let assistants: Vec<_> = messages
        .iter()
        .filter(|m| m["tool_calls"].is_array())
        .collect();
    assert_eq!(
        assistants.len(),
        1,
        "exactly one assistant tool-call entry in followup history"
    );
    let assistant = assistants[0];
    assert_eq!(assistant["role"], json!("assistant"));
    assert_eq!(
        assistant["tool_calls"]
            .as_array()
            .expect("tool calls array")
            .len(),
        1,
        "single tool call preserved"
    );
    assert_eq!(assistant["tool_calls"][0]["id"], json!("read-1"));
    assert_eq!(
        assistant["tool_calls"][0]["function"]["name"],
        json!("read_file")
    );
    for request in &sent {
        let wire: JsonValue = serde_json::from_str(&request.body).expect("public request JSON");
        assert_eq!(
            wire["model"],
            json!("request-model"),
            "requested model intent retained on every send"
        );
    }
    assert_ne!(
        sent[0].body, sent[1].body,
        "completed tool updates provider history"
    );
    if retry {
        assert_eq!(
            sent[1].body, sent[2].body,
            "retry retains exact completed tool history"
        );
    }
    for secret in [ACCESS, "SYNTHETIC_REFRESH_TOKEN", "host_home"] {
        assert!(
            !decision.to_string().contains(secret),
            "public decision must be sanitized"
        );
    }
}
#[test]
fn authenticated_tool_read_reaches_real_provider_followup() {
    run_tool_followup(false);
}
#[test]
fn rate_limited_followup_keeps_tool_result_without_reexecution() {
    run_tool_followup(true);
}
