//! Task 10: production `AgentService` worker + bundled RSS loop + real native tools.
//!
//! `ScriptedProvider` is the model transport only. Native tools execute against
//! a generated git workspace. Provider-host injection stays in this file
//! because a parallel Task 9 change may alter that API.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustscript_agent::config::{ProviderProfile, RunLimits};
use rustscript_agent::{
    AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, AgentProviderHost, AgentService,
    LlmContentBlock, RunCancellation, ScriptedProvider, decode_message_blocks,
};
use serde_json::{Value as JsonValue, json};

const GUIDANCE_MARKER: &str = "E2E-CODING-GUIDANCE-MARKER";
const SOURCE_RELATIVE: &str = "src/value.txt";
const TEST_SCRIPT_RELATIVE: &str = "test/test_value.sh";
const BROKEN_SOURCE: &[u8] = b"41\n";
const FIXED_SOURCE: &[u8] = b"42\n";
const CALL_READ: &str = "call-read";
const CALL_PATCH: &str = "call-patch";
const CALL_TEST: &str = "call-test";
const TEMP_ROOT: &str = "/mnt/TEMP/workspace/rustscript-agent/tmp/coding-t10-main-e2e-72b06ca2";

static FIXTURE_SEQ: AtomicU64 = AtomicU64::new(0);

struct WorkspaceFixture {
    root: PathBuf,
    workspace: PathBuf,
}

impl WorkspaceFixture {
    fn new() -> Self {
        fs::create_dir_all(TEMP_ROOT).expect("task temp root should be creatable");
        let seq = FIXTURE_SEQ.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(TEMP_ROOT).join(format!("e2e-{}-{seq}", std::process::id()));
        if root.exists() {
            let _ = fs::remove_dir_all(&root);
        }
        let workspace = root.join("workspace");
        fs::create_dir_all(workspace.join("src")).expect("source dir");
        fs::create_dir_all(workspace.join("test")).expect("test dir");
        fs::write(
            workspace.join("AGENTS.md"),
            format!(
                "{GUIDANCE_MARKER}\n\nFix `{SOURCE_RELATIVE}` so it contains exactly `42`.\nAfter the edit, run `/bin/sh {TEST_SCRIPT_RELATIVE}`.\n"
            ),
        )
        .expect("write AGENTS.md");
        fs::write(workspace.join(SOURCE_RELATIVE), BROKEN_SOURCE).expect("write broken source");
        fs::write(
            workspace.join(TEST_SCRIPT_RELATIVE),
            "#!/bin/sh\nvalue=$(cat src/value.txt)\ntest \"$value\" = \"42\"\n",
        )
        .expect("write failing test");
        init_git_repo(&workspace);
        assert_eq!(
            fs::read(workspace.join(SOURCE_RELATIVE)).expect("read source"),
            BROKEN_SOURCE
        );
        assert!(
            !run_targeted_test(&workspace).success(),
            "fixture test must fail before the agent runs"
        );
        Self { root, workspace }
    }

    fn source_path(&self) -> PathBuf {
        self.workspace.join(SOURCE_RELATIVE)
    }
}

impl Drop for WorkspaceFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn init_git_repo(workspace: &Path) {
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(workspace)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "e2e")
            .env("GIT_AUTHOR_EMAIL", "e2e@example.test")
            .env("GIT_COMMITTER_NAME", "e2e")
            .env("GIT_COMMITTER_EMAIL", "e2e@example.test")
            .output()
            .unwrap_or_else(|error| panic!("git {args:?} failed to spawn: {error}"));
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init"]);
    git(&["add", "."]);
    git(&[
        "-c",
        "user.name=e2e",
        "-c",
        "user.email=e2e@example.test",
        "commit",
        "-m",
        "fixture",
    ]);
}

fn run_targeted_test(workspace: &Path) -> std::process::ExitStatus {
    Command::new("/bin/sh")
        .arg(TEST_SCRIPT_RELATIVE)
        .current_dir(workspace)
        .status()
        .expect("targeted test should spawn")
}

fn agent_loop_source() -> String {
    fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/main.rss"))
        .expect("bundled rss/agent/main.rss should be readable")
}

fn text_response(text: &str) -> JsonValue {
    json!({
        "text": text,
        "tool_calls": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "stop"
    })
}

fn tool_response(text: &str, tool_calls: JsonValue) -> JsonValue {
    json!({
        "text": text,
        "tool_calls": tool_calls,
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    })
}

/// Model transport plus localized durable-parent commit.
///
/// Production dispatch requires a durable assistant `tool_call` parent before
/// native tools run. The bundled RSS loop does not call `commit_provider_step`;
/// this wrapper does so the E2E still uses real tools. If Task 9 later commits
/// provider steps inside the host, this wrapper can become a passthrough.
struct ScriptedModelTransport {
    inner: ScriptedProvider,
    service: Arc<AgentService>,
    run_id: String,
    turn: AtomicU64,
}

impl ScriptedModelTransport {
    fn new(inner: ScriptedProvider, service: Arc<AgentService>, run_id: String) -> Self {
        Self {
            inner,
            service,
            run_id,
            turn: AtomicU64::new(0),
        }
    }

    fn commit_response(&self, response: &JsonValue) {
        let turn = self.turn.fetch_add(1, Ordering::SeqCst) + 1;
        let blocks = blocks_from_provider_response(response);
        if blocks.is_empty() {
            return;
        }
        let parent_message_id = self
            .service
            .session_messages(
                &self
                    .service
                    .run_context(&self.run_id)
                    .expect("run context")
                    .session_id,
            )
            .last()
            .and_then(|message| message.get("id").and_then(JsonValue::as_str))
            .map(str::to_string);
        let finish_reason = if response
            .get("tool_calls")
            .and_then(JsonValue::as_array)
            .is_some_and(|calls| !calls.is_empty())
        {
            Some("tool_calls")
        } else {
            Some("stop")
        };
        self.service
            .commit_provider_step(
                &self.run_id,
                turn,
                &blocks,
                None,
                finish_reason,
                Some("local-agent"),
                Some("local-agent"),
                parent_message_id.as_deref(),
            )
            .unwrap_or_else(|error| {
                panic!("commit_provider_step turn {turn} should succeed: {error:?}")
            });
    }
}

impl AgentProviderHost for ScriptedModelTransport {
    fn call(&self, request: &JsonValue, cancellation: &RunCancellation) -> JsonValue {
        let envelope = self.inner.call(request, cancellation);
        if envelope.get("ok") == Some(&JsonValue::Bool(true))
            && let Some(response) = envelope.get("response")
        {
            self.commit_response(response);
        }
        envelope
    }
}

fn blocks_from_provider_response(response: &JsonValue) -> Vec<LlmContentBlock> {
    let mut blocks = Vec::new();
    if let Some(text) = response.get("text").and_then(JsonValue::as_str)
        && !text.is_empty()
    {
        blocks.push(LlmContentBlock {
            block_type: "text".to_string(),
            text: Some(text.to_string()),
            ..LlmContentBlock::default()
        });
    }
    if let Some(calls) = response.get("tool_calls").and_then(JsonValue::as_array) {
        for call in calls {
            blocks.push(LlmContentBlock {
                block_type: "tool_call".to_string(),
                tool_call_id: call
                    .get("id")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string),
                name: call
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string),
                arguments_json: call.get("arguments").map(|arguments| arguments.to_string()),
                ..LlmContentBlock::default()
            });
        }
    }
    blocks
}

/// Localized injection point: Task 9 may rename/replace `inject_provider_host`.
fn inject_scripted_model_transport(
    service: &Arc<AgentService>,
    provider: ScriptedProvider,
    run_id: &str,
) {
    service.inject_provider_host(Arc::new(ScriptedModelTransport::new(
        provider,
        Arc::clone(service),
        run_id.to_string(),
    )));
}

async fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    false
}

fn json_str<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("missing string field {key}: {value}"))
}

fn tool_call_id_of(event: &JsonValue) -> Option<&str> {
    event
        .pointer("/data/tool_call_id")
        .and_then(JsonValue::as_str)
        .or_else(|| {
            event
                .pointer("/data/tool_call/id")
                .and_then(JsonValue::as_str)
        })
}

fn event_types_for(events: &[JsonValue], call_id: &str) -> Vec<String> {
    events
        .iter()
        .filter(|event| tool_call_id_of(event) == Some(call_id))
        .filter_map(|event| event.get("event").and_then(JsonValue::as_str))
        .map(str::to_string)
        .collect()
}

fn message_text(message: &JsonValue) -> Option<&str> {
    message
        .pointer("/content/0/text")
        .and_then(JsonValue::as_str)
        .or_else(|| message.get("content").and_then(JsonValue::as_str))
}

fn request_system_prompts(request: &JsonValue) -> Vec<&str> {
    request
        .get("messages")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter(|message| message.get("role").and_then(JsonValue::as_str) == Some("system"))
        .filter_map(message_text)
        .collect()
}

fn content_blocks(message: &JsonValue) -> &[JsonValue] {
    message
        .get("content")
        .and_then(JsonValue::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn follow_up_has_tool_pair(request: &JsonValue, call_id: &str, name: &str) -> bool {
    let messages = request
        .get("messages")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();
    let has_assistant = messages.iter().any(|message| {
        message.get("role").and_then(JsonValue::as_str) == Some("assistant")
            && content_blocks(message).iter().any(|block| {
                block.get("type").and_then(JsonValue::as_str) == Some("tool_call")
                    && block.get("tool_call_id").and_then(JsonValue::as_str) == Some(call_id)
                    && block.get("name").and_then(JsonValue::as_str) == Some(name)
            })
    });
    let has_result = messages.iter().any(|message| {
        message.get("role").and_then(JsonValue::as_str) == Some("user")
            && content_blocks(message).iter().any(|block| {
                block.get("type").and_then(JsonValue::as_str) == Some("tool_result")
                    && block.get("tool_call_id").and_then(JsonValue::as_str) == Some(call_id)
            })
    });
    has_assistant && has_result
}

#[tokio::test(flavor = "multi_thread")]
async fn real_coding_workflow_reads_patches_and_runs_the_targeted_test() {
    let fixture = WorkspaceFixture::new();
    let source = agent_loop_source();
    assert!(
        source.contains("agent::provider_call") && source.contains("agent::tool_dispatch"),
        "E2E must compile the real bundled RSS loop"
    );

    let state = AgentGatewayState::with_agent_source(AgentGatewayConfig::default(), source)
        .expect("bundled RSS agent should compile");
    let service = state.service();
    assert_eq!(service.config().provider.as_deref(), Some("local-agent"));

    service
        .set_run_limits(
            RunLimits::new(8, 8, 64 * 1024, &fixture.workspace)
                .expect("workspace run limits should validate"),
        )
        .expect("run limits should apply before admission");
    service
        .set_provider_profile(
            ProviderProfile::builtin("local-agent").expect("local-agent profile should validate"),
        )
        .expect("local-agent profile should apply");

    let registry_before = service.tool_registry_snapshot();
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_response(
        "reading the failing source",
        json!([{
            "id": CALL_READ,
            "name": "read_file",
            "arguments": {"path": SOURCE_RELATIVE}
        }]),
    ));
    provider.push_ok(tool_response(
        "applying a minimal patch",
        json!([{
            "id": CALL_PATCH,
            "name": "patch",
            "arguments": {
                "path": SOURCE_RELATIVE,
                "old_string": "41",
                "new_string": "42"
            }
        }]),
    ));
    provider.push_ok(tool_response(
        "running the targeted test",
        json!([{
            "id": CALL_TEST,
            "name": "terminal",
            "arguments": {
                "argv": ["/bin/sh", TEST_SCRIPT_RELATIVE]
            }
        }]),
    ));
    provider.push_ok(text_response(
        "Fixed src/value.txt to 42 and the targeted test passed.",
    ));

    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"message": "Fix the failing test using workspace guidance."}),
            platform: "coding_agent_e2e_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("admission should succeed");

    let context = service
        .run_context(&admitted.run_id)
        .expect("admitted context should be retained");
    let frozen_prompt = context
        .coding_system_prompt
        .as_deref()
        .expect("admission must freeze the coding system prompt")
        .to_string();
    assert!(
        frozen_prompt.contains(GUIDANCE_MARKER),
        "frozen prompt must include AGENTS.md guidance"
    );
    assert_eq!(
        context.metadata["registry_identity"],
        registry_before.identity()
    );
    assert_eq!(context.metadata["toolset_hash"], registry_before.identity());
    assert_eq!(context.metadata["provider_profile"], "local-agent");
    assert_eq!(
        context.provider_options["protocol"], "local-agent",
        "the E2E must not select an openai-compatible protocol"
    );

    inject_scripted_model_transport(&service, provider.clone(), &admitted.run_id);
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    assert!(
        wait_until(Duration::from_secs(30), || {
            service.run_events(&admitted.run_id).iter().any(|event| {
                event.get("event").and_then(JsonValue::as_str) == Some("run.completed")
            })
        })
        .await,
        "final run state must be completed: {:?}",
        service.run_events(&admitted.run_id)
    );

    assert_eq!(
        fs::read(fixture.source_path()).expect("read patched source"),
        FIXED_SOURCE,
        "source bytes must change exactly from 41 to 42"
    );
    let independent = run_targeted_test(&fixture.workspace);
    assert!(
        independent.success(),
        "targeted test must exit 0 after the agent patch"
    );

    let events = service.run_events(&admitted.run_id);
    for call_id in [CALL_READ, CALL_PATCH, CALL_TEST] {
        assert_eq!(
            event_types_for(&events, call_id),
            [
                "tool.requested".to_string(),
                "tool.started".to_string(),
                "tool.output".to_string(),
                "tool.completed".to_string()
            ],
            "canonical tool lifecycle for {call_id}: {events:?}"
        );
    }

    let messages = service.session_messages(&admitted.session_id);
    assert_canonical_durable_chain(&messages, &admitted.run_id);

    let terminal_result = messages
        .iter()
        .find(|message| {
            json_str(message, "role") == "user"
                && message.get("tool_call_id").and_then(JsonValue::as_str) == Some(CALL_TEST)
        })
        .expect("terminal tool_result should be durable");
    let terminal_blocks = decode_message_blocks(&terminal_result["content"]);
    let exit_code = terminal_blocks
        .iter()
        .find_map(|block| block.result.as_ref())
        .and_then(|result| result.get("exit_code"))
        .and_then(JsonValue::as_i64);
    assert_eq!(exit_code, Some(0), "actual terminal tool exit_code");

    let requests = provider.requests();
    assert_eq!(provider.call_count(), 4);
    assert_eq!(requests.len(), 4);
    let mut seen_prompt: Option<String> = None;
    for (index, request) in requests.iter().enumerate() {
        let systems = request_system_prompts(request);
        assert_eq!(
            systems.len(),
            1,
            "frozen prompt must appear exactly once on request {index}"
        );
        assert_eq!(systems[0], frozen_prompt);
        match &seen_prompt {
            None => seen_prompt = Some(systems[0].to_string()),
            Some(previous) => assert_eq!(systems[0], previous),
        }
    }
    assert!(
        frozen_prompt.contains(GUIDANCE_MARKER),
        "first model request must see AGENTS.md guidance"
    );
    assert!(
        follow_up_has_tool_pair(&requests[1], CALL_READ, "read_file"),
        "second provider request must include the read_file follow-up: {}",
        requests[1]
    );
    assert!(
        follow_up_has_tool_pair(&requests[2], CALL_PATCH, "patch"),
        "third provider request must include the patch follow-up: {}",
        requests[2]
    );
    assert!(
        follow_up_has_tool_pair(&requests[3], CALL_TEST, "terminal"),
        "final provider request must include the terminal follow-up: {}",
        requests[3]
    );

    let registry_after = service.tool_registry_snapshot();
    assert_eq!(registry_after.identity(), registry_before.identity());
    assert_eq!(
        service
            .run_context(&admitted.run_id)
            .expect("completed context")
            .metadata["registry_identity"],
        registry_before.identity()
    );

    let metrics = service.metrics().snapshot();
    assert_eq!(metrics.model_calls, 4);
    assert_eq!(metrics.tool_calls, 3);
    assert_eq!(metrics.tool_failures, 0);
    assert_eq!(metrics.turns, 4);
    assert_eq!(metrics.truncations, 0);

    assert_eq!(
        service.process_owner_count(&admitted.run_id),
        0,
        "process table owner must be zero after completion"
    );
}

fn assert_canonical_durable_chain(messages: &[JsonValue], run_id: &str) {
    let run_messages: Vec<&JsonValue> = messages
        .iter()
        .filter(|message| message.get("run_id").and_then(JsonValue::as_str) == Some(run_id))
        .collect();
    assert!(
        run_messages.len() >= 6,
        "durable chain should include three tool pairs, got {run_messages:?}"
    );

    let mut ordinals = Vec::new();
    let mut last_id: Option<String> = None;
    let expected = [
        ("assistant", Some(CALL_READ), "tool_call"),
        ("user", Some(CALL_READ), "tool_result"),
        ("assistant", Some(CALL_PATCH), "tool_call"),
        ("user", Some(CALL_PATCH), "tool_result"),
        ("assistant", Some(CALL_TEST), "tool_call"),
        ("user", Some(CALL_TEST), "tool_result"),
    ];
    let mut matched = 0usize;
    for message in &run_messages {
        if let Some(ordinal) = message.get("ordinal").and_then(JsonValue::as_i64) {
            if let Some(previous) = ordinals.last() {
                assert!(ordinal > *previous, "ordinals must increase: {ordinals:?}");
            }
            ordinals.push(ordinal);
        }
        if matched >= expected.len() {
            last_id = message
                .get("id")
                .and_then(JsonValue::as_str)
                .map(str::to_string);
            continue;
        }
        let (role, call_id, block_type) = expected[matched];
        if json_str(message, "role") != role {
            last_id = message
                .get("id")
                .and_then(JsonValue::as_str)
                .map(str::to_string);
            continue;
        }
        let blocks = decode_message_blocks(&message["content"]);
        let Some(block) = blocks.iter().find(|block| block.block_type == block_type) else {
            last_id = message
                .get("id")
                .and_then(JsonValue::as_str)
                .map(str::to_string);
            continue;
        };
        assert_eq!(block.tool_call_id.as_deref(), call_id);
        if role == "user" {
            assert_eq!(
                message.get("parent_message_id").and_then(JsonValue::as_str),
                last_id.as_deref(),
                "tool_result parent must be the assistant tool_call"
            );
            assert_eq!(
                message.get("tool_call_id").and_then(JsonValue::as_str),
                call_id
            );
        } else {
            assert!(
                message
                    .get("parent_message_id")
                    .and_then(JsonValue::as_str)
                    .is_some(),
                "assistant tool_call should have a parent"
            );
        }
        last_id = message
            .get("id")
            .and_then(JsonValue::as_str)
            .map(str::to_string);
        matched += 1;
    }
    assert_eq!(
        matched,
        expected.len(),
        "durable assistant tool_call + user tool_result chain in {run_messages:?}"
    );
}

#[test]
fn docs_name_the_local_coding_e2e_command() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let command = "cargo test --test coding_agent_e2e_tests";
    for relative in ["README.md", "docs/configuration.md"] {
        let text = fs::read_to_string(root.join(relative)).expect(relative);
        assert!(
            text.contains(command),
            "{relative} must document the exact local E2E command {command}"
        );
        assert!(
            !text.contains("openai-compatible inference path is implemented"),
            "{relative} must not claim an unsupported OpenAI-compatible path"
        );
    }
}
