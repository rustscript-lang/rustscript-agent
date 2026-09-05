//! Task 10: production `AgentService` worker + bundled RSS loop + real native tools.
//!
//! `ScriptedProvider` is injected as the inner model transport. Production
//! `DurableProviderHost` owns provider-step durability, replay, and recovery.
//! Native tools execute against a generated git workspace.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustscript_agent::config::{ProviderProfile, RunLimits};
use rustscript_agent::{
    AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, ScriptedProvider, decode_message_blocks,
};
use serde_json::{Value as JsonValue, json};
use uuid::Uuid;

const GUIDANCE_MARKER: &str = "E2E-CODING-GUIDANCE-MARKER";
const SOURCE_RELATIVE: &str = "src/value.txt";
const TEST_SCRIPT_RELATIVE: &str = "test/test_value.sh";
const BROKEN_SOURCE: &[u8] = b"41\n";
const FIXED_SOURCE: &[u8] = b"42\n";
const CALL_READ: &str = "call-read";
const CALL_PATCH: &str = "call-patch";
const CALL_TEST: &str = "call-test";

static FIXTURE_SEQ: AtomicU64 = AtomicU64::new(0);

fn test_temp_root() -> PathBuf {
    std::env::var_os("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

fn lookup_in_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths).find_map(|dir| {
        let candidate = dir.join(name);
        candidate.is_file().then_some(candidate)
    })
}

fn locate_sh() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        for candidate in ["/bin/sh", "/usr/bin/sh"] {
            let path = PathBuf::from(candidate);
            if path.is_file() {
                return Some(path);
            }
        }
        lookup_in_path("sh")
    }
    #[cfg(not(unix))]
    {
        None
    }
}

struct WorkspaceFixture {
    root: PathBuf,
    workspace: PathBuf,
    cleaned: bool,
}

impl WorkspaceFixture {
    fn new(sh: &Path) -> Self {
        let seq = FIXTURE_SEQ.fetch_add(1, Ordering::Relaxed);
        let root = test_temp_root().join(format!(
            "coding-e2e-{}-{seq}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        if root.exists() {
            fs::remove_dir_all(&root).expect("stale fixture root should be removable");
        }
        let workspace = root.join("workspace");
        fs::create_dir_all(workspace.join("src")).expect("source dir");
        fs::create_dir_all(workspace.join("test")).expect("test dir");
        fs::write(
            workspace.join("AGENTS.md"),
            format!(
                "{GUIDANCE_MARKER}\n\nFix `{SOURCE_RELATIVE}` so it contains exactly `42`.\nAfter the edit, run the targeted test script `{TEST_SCRIPT_RELATIVE}`.\n"
            ),
        )
        .expect("write AGENTS.md");
        fs::write(workspace.join(SOURCE_RELATIVE), BROKEN_SOURCE).expect("write broken source");
        fs::write(
            workspace.join(TEST_SCRIPT_RELATIVE),
            "value=$(cat src/value.txt)\ntest \"$value\" = \"42\"\n",
        )
        .expect("write failing test");
        init_git_repo(&workspace);
        assert_eq!(
            fs::read(workspace.join(SOURCE_RELATIVE)).expect("read source"),
            BROKEN_SOURCE
        );
        assert!(
            !run_targeted_test(sh, &workspace).success(),
            "fixture test must fail before the agent runs"
        );
        Self {
            root,
            workspace,
            cleaned: false,
        }
    }

    fn source_path(&self) -> PathBuf {
        self.workspace.join(SOURCE_RELATIVE)
    }

    fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        if self.root.exists() {
            fs::remove_dir_all(&self.root)
                .unwrap_or_else(|error| panic!("fixture cleanup {}: {error}", self.root.display()));
        }
        assert!(
            !self.root.exists(),
            "fixture root must be removed: {}",
            self.root.display()
        );
        self.cleaned = true;
    }
}

impl Drop for WorkspaceFixture {
    fn drop(&mut self) {
        if !self.cleaned && self.root.exists() {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn init_git_repo(workspace: &Path) {
    let empty_config = workspace
        .parent()
        .expect("workspace parent")
        .join("empty.gitconfig");
    fs::write(&empty_config, "").expect("empty gitconfig");
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(workspace)
            .env("GIT_CONFIG_GLOBAL", &empty_config)
            .env("GIT_CONFIG_SYSTEM", &empty_config)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "e2e")
            .env("GIT_AUTHOR_EMAIL", "e2e@example.test")
            .env("GIT_COMMITTER_NAME", "e2e")
            .env("GIT_COMMITTER_EMAIL", "e2e@example.test")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
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

fn run_targeted_test(sh: &Path, workspace: &Path) -> std::process::ExitStatus {
    Command::new(sh)
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

fn json_opt_str<'a>(value: &'a JsonValue, key: &str) -> Option<&'a str> {
    value.get(key).and_then(JsonValue::as_str)
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
    let Some(sh) = locate_sh() else {
        #[cfg(unix)]
        panic!("unix coding e2e requires sh at /bin/sh, /usr/bin/sh, or PATH");
        #[cfg(not(unix))]
        {
            eprintln!("skipping coding e2e without POSIX sh");
            return;
        }
    };
    let sh_arg = sh.to_str().expect("sh path should be utf-8").to_string();
    let mut fixture = WorkspaceFixture::new(&sh);
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
                "argv": [sh_arg, TEST_SCRIPT_RELATIVE]
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

    service.inject_provider_host(Arc::new(provider.clone()));
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
    let independent = run_targeted_test(&sh, &fixture.workspace);
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
    fixture.cleanup();
}

#[derive(Debug)]
enum ExpectedParent {
    None,
    Index(usize),
}

struct ExpectedDurable {
    role: &'static str,
    name: Option<&'static str>,
    tool_call_id: Option<&'static str>,
    block_type: &'static str,
    block_name: Option<&'static str>,
    block_tool_call_id: Option<&'static str>,
    parent: ExpectedParent,
    ordinal: Option<i64>,
}

fn message_id(message: &JsonValue) -> &str {
    json_str(message, "id")
}

fn summarize_chain(messages: &[&JsonValue]) -> String {
    messages
        .iter()
        .enumerate()
        .map(|(index, message)| {
            let blocks = decode_message_blocks(&message["content"]);
            let block_desc: Vec<String> = blocks
                .iter()
                .map(|block| {
                    format!(
                        "{}:{:?}:{:?}",
                        block.block_type, block.name, block.tool_call_id
                    )
                })
                .collect();
            format!(
                "{index}: role={} name={:?} tool_call_id={:?} parent={:?} ordinal={:?} blocks={block_desc:?}",
                json_str(message, "role"),
                json_opt_str(message, "name"),
                json_opt_str(message, "tool_call_id"),
                json_opt_str(message, "parent_message_id"),
                message.get("ordinal").and_then(JsonValue::as_i64),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_canonical_durable_chain(messages: &[JsonValue], run_id: &str) {
    let run_messages: Vec<&JsonValue> = messages
        .iter()
        .filter(|message| message.get("run_id").and_then(JsonValue::as_str) == Some(run_id))
        .collect();
    let expected = [
        ExpectedDurable {
            role: "user",
            name: None,
            tool_call_id: None,
            block_type: "text",
            block_name: None,
            block_tool_call_id: None,
            parent: ExpectedParent::None,
            ordinal: None,
        },
        ExpectedDurable {
            role: "assistant",
            name: None,
            tool_call_id: None,
            block_type: "tool_call",
            block_name: Some("read_file"),
            block_tool_call_id: Some(CALL_READ),
            parent: ExpectedParent::Index(0),
            ordinal: Some(2),
        },
        ExpectedDurable {
            role: "user",
            name: Some("read_file"),
            tool_call_id: Some(CALL_READ),
            block_type: "tool_result",
            block_name: None,
            block_tool_call_id: Some(CALL_READ),
            parent: ExpectedParent::Index(1),
            ordinal: Some(3),
        },
        ExpectedDurable {
            role: "assistant",
            name: None,
            tool_call_id: None,
            block_type: "tool_call",
            block_name: Some("patch"),
            block_tool_call_id: Some(CALL_PATCH),
            parent: ExpectedParent::Index(2),
            ordinal: Some(4),
        },
        ExpectedDurable {
            role: "user",
            name: Some("patch"),
            tool_call_id: Some(CALL_PATCH),
            block_type: "tool_result",
            block_name: None,
            block_tool_call_id: Some(CALL_PATCH),
            parent: ExpectedParent::Index(3),
            ordinal: Some(5),
        },
        ExpectedDurable {
            role: "assistant",
            name: None,
            tool_call_id: None,
            block_type: "tool_call",
            block_name: Some("terminal"),
            block_tool_call_id: Some(CALL_TEST),
            parent: ExpectedParent::Index(4),
            ordinal: Some(6),
        },
        ExpectedDurable {
            role: "user",
            name: Some("terminal"),
            tool_call_id: Some(CALL_TEST),
            block_type: "tool_result",
            block_name: None,
            block_tool_call_id: Some(CALL_TEST),
            parent: ExpectedParent::Index(5),
            ordinal: Some(7),
        },
        ExpectedDurable {
            role: "assistant",
            name: None,
            tool_call_id: None,
            block_type: "text",
            block_name: None,
            block_tool_call_id: None,
            parent: ExpectedParent::Index(6),
            ordinal: Some(8),
        },
    ];
    assert_eq!(
        run_messages.len(),
        expected.len(),
        "durable chain must match exact count/order, got:\n{}",
        summarize_chain(&run_messages)
    );

    for (index, (message, spec)) in run_messages.iter().zip(expected.iter()).enumerate() {
        let summary = summarize_chain(&run_messages);
        assert_eq!(
            json_str(message, "role"),
            spec.role,
            "role at {index}:\n{summary}"
        );
        assert_eq!(
            json_opt_str(message, "name"),
            spec.name,
            "name at {index}:\n{summary}"
        );
        assert_eq!(
            json_opt_str(message, "tool_call_id"),
            spec.tool_call_id,
            "tool_call_id at {index}:\n{summary}"
        );
        assert_eq!(
            message.get("ordinal").and_then(JsonValue::as_i64),
            spec.ordinal,
            "ordinal at {index}:\n{summary}"
        );
        let expected_parent = match spec.parent {
            ExpectedParent::None => None,
            ExpectedParent::Index(previous) => Some(message_id(run_messages[previous])),
        };
        assert_eq!(
            json_opt_str(message, "parent_message_id"),
            expected_parent,
            "parent at {index}:\n{summary}"
        );
        let blocks = decode_message_blocks(&message["content"]);
        let block = blocks
            .iter()
            .find(|block| block.block_type == spec.block_type)
            .unwrap_or_else(|| {
                panic!(
                    "missing {} block at {index}: {blocks:?}\n{summary}",
                    spec.block_type
                )
            });
        assert_eq!(
            block.name.as_deref(),
            spec.block_name,
            "block name at {index}:\n{summary}"
        );
        assert_eq!(
            block.tool_call_id.as_deref(),
            spec.block_tool_call_id,
            "block tool_call_id at {index}:\n{summary}"
        );
    }
}

#[test]
fn docs_name_the_local_coding_e2e_command() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let commands = [
        "cargo test --test coding_agent_e2e_tests",
        "cargo test --test coding_agent_edge_e2e_tests",
    ];
    for relative in ["README.md", "docs/configuration.md"] {
        let text = fs::read_to_string(root.join(relative)).expect(relative);
        for command in commands {
            assert!(
                text.contains(command),
                "{relative} must document the exact local E2E command {command}"
            );
        }
        assert!(
            !text.contains("openai-compatible inference path is implemented"),
            "{relative} must not claim an unsupported OpenAI-compatible path"
        );
        assert!(
            !text.contains("does not cover stop-during-output"),
            "{relative} must not claim stop-during-output is uncovered"
        );
    }
}
