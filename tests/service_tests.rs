use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use rustscript_agent::config::{
    ADMISSION_QUERY_RESULT_LIMIT_BYTES, ADMISSION_RUN_COL_INPUT_JSON, AdmissionSqliteCellLens,
    MAX_IDEMPOTENCY_KEY_BYTES, MAX_MODEL_NAME_BYTES, MAX_PROVIDER_NAME_BYTES,
    MAX_PROVIDER_OPTIONS_BYTES, MAX_RUN_CONTEXT_STORAGE_BYTES, ProviderProfile, RunLimits,
    estimate_admission_query_bytes,
};
use rustscript_agent::tools::ToolResult;
use rustscript_agent::{
    AdmitError, AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, LlmContentBlock,
    ProviderPendingDecision, ScriptedProvider, ToolCall, ToolDescriptor, ToolRegistry,
    ToolRegistryEntry, Toolset, encode_message_content, provider_pending_may_retry,
};
use serde_json::{Value, json};
use uuid::Uuid;

fn test_source() -> &'static str {
    "pub fn run(context: map) -> map { context; }"
}

fn admit_request(provider: Option<&str>) -> AdmitRunRequest {
    AdmitRunRequest {
        input: json!({"message": "hello"}),
        provider: provider.map(str::to_string),
        platform: "service_tests".to_string(),
        ..AdmitRunRequest::default()
    }
}

fn admit_request_with_instructions(instructions: Option<String>) -> AdmitRunRequest {
    AdmitRunRequest {
        instructions,
        ..admit_request(None)
    }
}

const TEST_REQUEST_HASH: &str = "fnv64:0123456789abcdef";

fn admit_request_with_idempotency_key(key: String) -> AdmitRunRequest {
    AdmitRunRequest {
        idempotency_key: Some(key),
        idempotency_hash: Some(TEST_REQUEST_HASH.to_string()),
        ..admit_request(None)
    }
}

fn utf8_key_with_exact_bytes(byte_limit: usize) -> String {
    let mut key = String::new();
    while key.len() + '界'.len_utf8() <= byte_limit {
        key.push('界');
    }
    while key.len() < byte_limit {
        key.push('a');
    }
    assert_eq!(key.len(), byte_limit);
    key
}

fn serialized_context_envelope_bytes(context: &rustscript_agent::RunContext) -> usize {
    let mut snapshot = serde_json::to_value(context).expect("run context should serialize");
    snapshot["messages"] = json!([]);
    serde_json::to_vec(&json!({
        "schema_version": 1,
        "run_context": snapshot,
    }))
    .expect("run context envelope should serialize")
    .len()
}

fn padded_instructions_for_run_query_budget(
    mut context: rustscript_agent::RunContext,
    provider: &str,
    model: &str,
    key: &str,
    target_run_bytes: usize,
) -> String {
    context.provider = if provider.is_empty() {
        None
    } else {
        Some(provider.to_string())
    };
    context.model = model.to_string();
    context.system_prompt = Some(String::new());
    let empty_prompt_bytes = serialized_context_envelope_bytes(&context);
    let mut lens = AdmissionSqliteCellLens::for_tests();
    lens.input_json = empty_prompt_bytes;
    lens.provider = provider.len();
    lens.model = model.len();
    lens.idempotency_key = key.len();
    lens.has_idempotency = !key.is_empty();
    lens.platform = context.platform.len();
    lens.system_prompt = 0;
    let estimate = estimate_admission_query_bytes(lens)
        .expect("empty-prompt query estimate must be computable");
    let prompt_len = target_run_bytes
        .checked_sub(estimate.run_bytes)
        .expect("fixed query cells must fit below the sqlite::query budget");
    "i".repeat(prompt_len)
}

fn custom_registry() -> ToolRegistry {
    custom_registry_with_description("A later registry snapshot")
}

fn custom_registry_with_description(description: &str) -> ToolRegistry {
    let mut entry = rustscript_agent::builtin_entries()
        .into_iter()
        .next()
        .expect("the built-in registry has a read tool");
    entry.descriptor = ToolDescriptor::new(
        "read_file",
        description,
        Toolset::CODING,
        "read",
        entry.descriptor.schema,
    );
    ToolRegistry::new([entry]).expect("the custom registry should validate")
}

#[test]
fn provider_profile_rejects_unknown_and_credential_bearing_options() {
    let safe = ProviderProfile::new(
        "safe-profile",
        json!({
            "profile": "safe-profile",
            "protocol": "local-agent",
            "temperature": 0.2,
            "base_url": "https://api.example.test/v1"
        }),
    )
    .expect("explicitly safe provider options should be accepted");
    assert_eq!(safe.options()["temperature"], 0.2);

    for (label, options) in [
        ("unknown option", json!({"profile": "p", "custom": true})),
        ("api key", json!({"profile": "p", "api_key": "secret"})),
        ("bare key", json!({"profile": "p", "key": "secret"})),
        (
            "header blob",
            json!({"profile": "p", "headers": {"authorization": "Bearer secret"}}),
        ),
        (
            "URL credentials",
            json!({"profile": "p", "base_url": "https://user:pass@example.test"}),
        ),
        (
            "URL query secret",
            json!({"profile": "p", "base_url": "https://api.example.test?v=secret"}),
        ),
    ] {
        assert!(
            ProviderProfile::new("unsafe-profile", options).is_err(),
            "{label} must not be retained in a run snapshot"
        );
    }
}

#[tokio::test]
async fn empty_tool_registry_is_rejected_by_the_service_setter() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default())
        .expect("default gateway configuration should validate");
    let service = state.service();
    let original_identity = service.tool_registry_snapshot().identity().to_string();
    let empty = ToolRegistry::new(std::iter::empty::<ToolRegistryEntry>())
        .expect("an empty registry is structurally constructible for this boundary test");

    let error = service
        .set_tool_registry(empty)
        .expect_err("the service must reject an empty registry");
    assert!(error.contains("empty"));
    assert_eq!(
        service.tool_registry_snapshot().identity(),
        original_identity,
        "rejecting an empty registry must preserve the active registry"
    );
}

fn temporary_db_path() -> PathBuf {
    let root = std::env::var_os("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "rustscript-agent-service-tests-{}",
                std::process::id()
            ))
        });
    std::fs::create_dir_all(&root).expect("test database directory should exist");
    let path = root.join(format!("{}.db", Uuid::new_v4()));
    assert_temp_db_is_lease_safe(&path);
    path
}

fn assert_temp_db_is_lease_safe(path: &Path) {
    if let Some(test_tmpdir) = std::env::var_os("TEST_TMPDIR") {
        let root = PathBuf::from(test_tmpdir);
        assert!(
            path.starts_with(&root),
            "test databases must stay under TEST_TMPDIR ({}); got {}",
            root.display(),
            path.display()
        );
        return;
    }
    let rendered = path.to_string_lossy();
    assert!(
        path.starts_with(std::env::temp_dir()),
        "test databases must use std::env::temp_dir when TEST_TMPDIR is unset: {rendered}"
    );
    assert!(
        !rendered.contains("/worktrees/")
            && !rendered.contains("/mnt/TEMP/workspace/rustscript-agent/tmp/"),
        "test databases must not write into a hardcoded sibling lease path: {rendered}"
    );
}

fn replace_persisted_run_input(path: &Path, run_id: &str, input: &Value) {
    let script = r#"
import sqlite3
import sys
connection = sqlite3.connect(sys.argv[1])
connection.execute("UPDATE runs SET input_json = ? WHERE id = ?", (sys.argv[3], sys.argv[2]))
connection.commit()
connection.close()
"#;
    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str()
                .expect("temporary database path should be UTF-8"),
            run_id,
            &input.to_string(),
        ])
        .output()
        .expect("python3 should be available for the SQLite fault-injection test");
    assert!(
        output.status.success(),
        "SQLite run-input rewrite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn sqlite_admission_table_counts(path: &Path) -> Vec<i64> {
    let script = r#"
import sqlite3
import sys
connection = sqlite3.connect(sys.argv[1])
for table in ("sessions", "messages", "runs", "idempotency_records", "run_events"):
    print(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
connection.close()
"#;
    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str()
                .expect("temporary database path should be UTF-8"),
        ])
        .output()
        .expect("python3 should be available for the SQLite residue assertion");
    assert!(
        output.status.success(),
        "SQLite residue query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("SQLite residue counts should be UTF-8")
        .lines()
        .map(|line| {
            line.parse()
                .expect("SQLite residue count should be an integer")
        })
        .collect()
}

#[tokio::test]
async fn admission_captures_real_registry_provider_options_limits_and_metadata() {
    let state = AgentGatewayState::with_agent_source(AgentGatewayConfig::default(), test_source())
        .expect("agent source should compile");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admission should succeed");

    let context = service
        .run_context(&admitted.run_id)
        .expect("admission should capture a context");
    let schemas = context
        .tool_schemas
        .as_array()
        .expect("tool schemas should be an array");
    assert!(!schemas.is_empty(), "the coding registry must expose tools");
    assert!(schemas.iter().any(|schema| schema["name"] == "read_file"));

    let metadata = context
        .metadata
        .as_object()
        .expect("context metadata should be an object");
    let registry_snapshot = service
        .run_registry_snapshot(&admitted.run_id)
        .expect("the registry executor snapshot should be retained");
    assert_eq!(registry_snapshot.identity(), metadata["registry_identity"]);
    assert_eq!(metadata["schema_version"], 1);
    assert_eq!(metadata["registry_identity"], metadata["toolset_hash"]);
    assert!(metadata["registry_identity"].as_str().is_some_and(|value| {
        value.starts_with("sha256:") && value.len() == "sha256:".len() + 64
    }));

    let provider_options = context
        .provider_options
        .as_object()
        .expect("provider options should be an object");
    assert!(!provider_options.is_empty());
    assert_eq!(provider_options["profile"], "local-agent");
    assert!(!context.limits["max_turns"].is_null());
    assert!(!context.limits["max_tool_calls"].is_null());
    assert!(!context.limits["max_tool_output_bytes"].is_null());
    let workspace = context.limits["workspace_root"]
        .as_str()
        .expect("workspace root should be serialized as a path");
    assert!(Path::new(workspace).is_absolute());
    assert!(Path::new(workspace).is_dir());
}

#[tokio::test]
async fn an_admitted_run_keeps_its_snapshot_when_later_runs_change_defaults() {
    let state = AgentGatewayState::with_agent_source(AgentGatewayConfig::default(), test_source())
        .expect("agent source should compile");
    let service = state.service();
    let first = service
        .admit(admit_request(None))
        .await
        .expect("first admission should succeed");
    let first_context = service
        .run_context(&first.run_id)
        .expect("first context should exist");

    let later_limits = RunLimits::new(9, 11, 32 * 1024, std::env::current_dir().unwrap())
        .expect("later limits should validate");
    service
        .set_tool_registry(custom_registry())
        .expect("tool registry should be accepted");
    service
        .set_provider_profile(
            ProviderProfile::new(
                "local-agent",
                json!({"profile": "later-profile", "temperature": 0.2}),
            )
            .expect("provider profile should validate"),
        )
        .expect("provider profile should be accepted");
    service
        .set_run_limits(later_limits)
        .expect("later limits should be accepted");

    assert_eq!(
        service
            .run_context(&first.run_id)
            .expect("first context should remain available"),
        first_context,
        "changing service defaults must not mutate an admitted run"
    );

    let second = service
        .admit(admit_request(Some("local-agent")))
        .await
        .expect("second admission should succeed");
    let second_context = service
        .run_context(&second.run_id)
        .expect("second context should exist");
    assert_ne!(
        second_context.metadata["registry_identity"],
        first_context.metadata["registry_identity"]
    );
    assert_eq!(second_context.provider_options["profile"], "later-profile");
    assert_eq!(second_context.limits["max_turns"], 9);
    assert_eq!(second_context.limits["max_tool_calls"], 11);
    assert_eq!(second_context.limits["max_tool_output_bytes"], 32 * 1024);
}

#[tokio::test]
async fn persisted_run_context_is_authoritative_across_same_session_registry_changes() {
    let path = temporary_db_path();
    let workspace_a = std::env::current_dir().expect("the test workspace should exist");
    let workspace_b = PathBuf::from("/tmp");
    let registry_a = custom_registry_with_description("registry A");
    let registry_b = custom_registry_with_description("registry B");
    let profile_a = ProviderProfile::new(
        "provider-a",
        json!({
            "profile": "profile-a",
            "protocol": "local-agent",
            "temperature": 0.1
        }),
    )
    .expect("provider A options should validate");
    let profile_b = ProviderProfile::new(
        "provider-b",
        json!({
            "profile": "profile-b",
            "protocol": "local-agent",
            "temperature": 0.9
        }),
    )
    .expect("provider B options should validate");
    let limits_a = RunLimits::new(3, 4, 4096, &workspace_a).expect("limits A should validate");
    let limits_b = RunLimits::new(8, 9, 8192, &workspace_b).expect("limits B should validate");

    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    service
        .set_tool_registry(registry_a)
        .expect("tool registry should be accepted");
    service
        .set_provider_profile(profile_a)
        .expect("provider A should be accepted");
    service
        .set_run_limits(limits_a)
        .expect("limits A should be accepted");

    let first = service
        .admit(AdmitRunRequest {
            input: json!({"message": "run A", "marker": "immutable-A"}),
            model: Some("model-A".to_string()),
            provider: Some("provider-a".to_string()),
            instructions: Some("system prompt A".to_string()),
            platform: "platform-A".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("run A admission should succeed");
    let first_context = service
        .run_context(&first.run_id)
        .expect("run A context should exist");

    service
        .set_tool_registry(registry_b)
        .expect("tool registry should be accepted");
    service
        .set_provider_profile(profile_b)
        .expect("provider B should be accepted");
    service
        .set_run_limits(limits_b)
        .expect("limits B should be accepted");
    let second = service
        .admit(AdmitRunRequest {
            input: json!({"message": "run B", "marker": "immutable-B"}),
            session_id: Some(first.session_id.clone()),
            model: Some("model-B".to_string()),
            provider: Some("provider-b".to_string()),
            instructions: Some("system prompt B".to_string()),
            platform: "platform-B".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("run B admission should succeed");
    let second_context = service
        .run_context(&second.run_id)
        .expect("run B context should exist");
    assert_ne!(
        first_context.metadata["registry_identity"],
        second_context.metadata["registry_identity"]
    );
    assert_eq!(second_context.input["marker"], "immutable-B");

    let persistence = state
        .persistence()
        .expect("persistence should be configured");
    persistence
        .session_touch(&json!({
            "session_id": first.session_id,
            "status": "active",
            "generation": 0,
            "system_prompt": "session touch prompt",
            "model": "session touch model",
            "provider": "session touch provider",
            "toolset_hash": "session-touch-registry",
            "metadata_json": "{}",
            "title": "session touch",
            "end_reason": "",
            "now_ms": 2
        }))
        .expect("an ordinary session touch should succeed");
    drop(persistence);
    drop(state);

    let resumed = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("the persisted gateway should reopen");
    let resumed_service = resumed.service();
    resumed_service
        .set_tool_registry(custom_registry_with_description("registry B"))
        .expect("tool registry should be accepted");
    resumed_service
        .set_provider_profile(
            ProviderProfile::new(
                "provider-b",
                json!({
                    "profile": "profile-b-current",
                    "protocol": "local-agent",
                    "temperature": 0.8
                }),
            )
            .expect("the current provider should validate"),
        )
        .expect("the current provider should be accepted");
    resumed_service
        .set_run_limits(RunLimits::new(20, 21, 16384, &workspace_b).expect("current limits"))
        .expect("the current limits should be accepted");

    let resumed_first = resumed_service
        .resume_context(&first.run_id)
        .expect("run A must remain resumable after run B and a session touch");
    assert_eq!(resumed_first, first_context);
    let resumed_second = resumed_service
        .resume_context(&second.run_id)
        .expect("run B should also resume");
    assert_eq!(resumed_second, second_context);
    assert!(matches!(
        resumed_service.verify_run_context(&second.run_id),
        Ok(())
    ));
    assert!(matches!(
        resumed_service.verify_run_context(&first.run_id),
        Err(rustscript_agent::service::RunContextError::RegistryMismatch { .. })
    ));
    drop(resumed);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn admission_persistence_failure_is_typed_and_leaves_no_residue() {
    let path = temporary_db_path();
    let request = AdmitRunRequest {
        input: json!({"message": "fault-injected"}),
        platform: "service_tests".to_string(),
        idempotency_key: Some("atomic-admission-key".to_string()),
        idempotency_hash: Some(TEST_REQUEST_HASH.to_string()),
        ..AdmitRunRequest::default()
    };
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    state
        .persistence()
        .expect("persistence should be configured")
        .shutdown();
    let error = state
        .service()
        .admit(request.clone())
        .await
        .expect_err("a closed persistence worker must reject admission");
    assert!(matches!(error, AdmitError::Persistence(_)));
    assert_eq!(state.service().handle_count(), 0);
    drop(state);

    let reopened = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("the SQLite gateway should reopen after the injected fault");
    let admitted = reopened
        .service()
        .admit(request)
        .await
        .expect("the same idempotency key should be available after the failed transaction");
    assert!(
        !admitted.replayed,
        "the failed admission must leave no replay record"
    );
    drop(reopened);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn maximum_provider_options_and_messages_remain_admissible() {
    let state = AgentGatewayState::with_agent_source(AgentGatewayConfig::default(), test_source())
        .expect("agent source should compile");
    let service = state.service();
    let provider_profile = ProviderProfile::new(
        "large-provider",
        json!({
            "base_url": format!("https://example.test/{}", "x".repeat(4059)),
            "profile": "p".repeat(4080),
            "protocol": "q".repeat(4080),
            "reasoning_effort": "r".repeat(4080),
        }),
    )
    .expect("a provider option payload at the configured maximum should validate");
    assert_eq!(
        serde_json::to_vec(provider_profile.options())
            .expect("provider options should serialize")
            .len(),
        MAX_PROVIDER_OPTIONS_BYTES
    );
    service
        .set_provider_profile(provider_profile.clone())
        .expect("the maximum provider option payload should be retained");

    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"message": "m".repeat(2048)}),
            provider: Some("large-provider".to_string()),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("maximum provider options with a normal maximum message should admit");
    let context = service
        .run_context(&admitted.run_id)
        .expect("the admitted context should be retained");
    assert_eq!(context.provider_options, *provider_profile.options());
    assert!(serialized_context_envelope_bytes(&context) <= MAX_RUN_CONTEXT_STORAGE_BYTES);
}

#[tokio::test]
async fn admission_query_budget_accepts_exact_select_and_rejects_one_byte_over() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let baseline = service
        .admit(admit_request(None))
        .await
        .expect("baseline admission should succeed");
    let sizing_context = service
        .run_context(&baseline.run_id)
        .expect("baseline context should exist");
    let provider = sizing_context.provider.clone().unwrap_or_default();
    let model = sizing_context.model.clone();
    let exact_instructions = padded_instructions_for_run_query_budget(
        sizing_context.clone(),
        &provider,
        &model,
        "",
        ADMISSION_QUERY_RESULT_LIMIT_BYTES,
    );
    let over_instructions = padded_instructions_for_run_query_budget(
        sizing_context,
        &provider,
        &model,
        "",
        ADMISSION_QUERY_RESULT_LIMIT_BYTES + 1,
    );

    let admitted = service
        .admit(admit_request_with_instructions(Some(
            exact_instructions.clone(),
        )))
        .await
        .expect("a context at the sqlite::query budget should succeed");
    let admitted_context = service
        .run_context(&admitted.run_id)
        .expect("the boundary context should be retained");
    assert!(serialized_context_envelope_bytes(&admitted_context) <= MAX_RUN_CONTEXT_STORAGE_BYTES);

    let error = service
        .admit(admit_request_with_instructions(Some(over_instructions)))
        .await
        .expect_err("one byte beyond the sqlite::query budget must be rejected");
    assert!(matches!(
        error,
        AdmitError::Invalid(message) if message.contains("sqlite::query") || message.contains("SELECT estimate")
    ));
    drop(service);
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn oversized_context_is_rejected_before_atomic_admission_and_leaves_no_residue() {
    let path = temporary_db_path();
    let request = AdmitRunRequest {
        input: json!({"message": "x".repeat(100_000)}),
        platform: "service_tests".to_string(),
        idempotency_key: Some("oversized-context-key".to_string()),
        idempotency_hash: Some(TEST_REQUEST_HASH.to_string()),
        ..AdmitRunRequest::default()
    };
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let error = service
        .admit(request)
        .await
        .expect_err("an oversized context must be rejected before admission persistence");
    assert!(
        matches!(
            error,
            AdmitError::Invalid(ref message) if message.contains("run context")
        ),
        "oversized context should fail validation, got {error:?}"
    );
    assert_eq!(service.handle_count(), 0);
    drop(service);
    drop(state);

    assert_eq!(
        sqlite_admission_table_counts(&path),
        vec![0, 0, 0, 0, 0],
        "a rejected context must leave no durable admission rows"
    );
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn exact_max_idempotency_key_is_admitted_and_resumes() {
    let path = temporary_db_path();
    let key = "k".repeat(MAX_IDEMPOTENCY_KEY_BYTES);
    let request = admit_request_with_idempotency_key(key);
    let expected_input = request.input.clone();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(request.clone())
        .await
        .expect("an idempotency key at the byte limit should be admitted");
    let run_id = admitted.run_id.clone();
    let session_id = admitted.session_id.clone();
    drop(service);
    drop(state);

    let reopened = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("the SQLite gateway should reopen");
    let reopened_service = reopened.service();
    let resumed = reopened_service
        .resume_context(&run_id)
        .expect("the exact-limit admission context should resume");
    assert_eq!(resumed.run_id, run_id);
    assert_eq!(resumed.session_id, session_id);
    assert_eq!(resumed.input, expected_input);

    let replayed = reopened_service
        .admit(request)
        .await
        .expect("the exact-limit idempotency key should replay after restart");
    assert!(replayed.replayed);
    assert_eq!(replayed.run_id, run_id);
    assert_eq!(replayed.session_id, session_id);
    drop(reopened_service);
    drop(reopened);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn multibyte_idempotency_key_boundary_counts_utf8_bytes() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let key = utf8_key_with_exact_bytes(MAX_IDEMPOTENCY_KEY_BYTES);
    assert!(
        key.chars().count() < key.len(),
        "the boundary fixture must contain multibyte UTF-8 characters"
    );
    service
        .admit(admit_request_with_idempotency_key(key.clone()))
        .await
        .expect("a valid UTF-8 key at the byte limit should be admitted");

    let error = service
        .admit(admit_request_with_idempotency_key(format!("{key}a")))
        .await
        .expect_err("one additional UTF-8 byte must exceed the byte limit");
    assert!(matches!(
        error,
        AdmitError::Invalid(message) if message.contains("idempotency key")
    ));
    drop(service);
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn idempotency_key_one_byte_over_limit_is_typed_invalid_and_leaves_no_residue() {
    let path = temporary_db_path();
    let request = admit_request_with_idempotency_key("k".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1));
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let error = service
        .admit(request)
        .await
        .expect_err("one byte beyond the idempotency key limit must be rejected");
    assert!(matches!(
        error,
        AdmitError::Invalid(message) if message.contains("idempotency key")
    ));
    assert_eq!(service.handle_count(), 0);
    drop(service);
    drop(state);

    assert_eq!(
        sqlite_admission_table_counts(&path),
        vec![0, 0, 0, 0, 0],
        "a rejected idempotency key must leave no durable admission rows"
    );
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn idempotency_key_grammar_rejects_empty_whitespace_and_control_values() {
    let state = AgentGatewayState::with_agent_source(AgentGatewayConfig::default(), test_source())
        .expect("agent source should compile");
    let service = state.service();
    for key in [
        "",
        "contains space",
        "contains\nnewline",
        "contains\u{7f}control",
    ] {
        let error = service
            .admit(admit_request_with_idempotency_key(key.to_string()))
            .await
            .expect_err("invalid idempotency-key grammar must be rejected");
        assert!(
            matches!(error, AdmitError::Invalid(message) if message.contains("idempotency key"))
        );
    }
}

#[tokio::test]
async fn maximum_key_and_provider_context_remain_below_the_admission_output_bound() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let provider_profile = ProviderProfile::new(
        "large-provider-with-key",
        json!({
            "base_url": format!("https://example.test/{}", "x".repeat(4059)),
            "profile": "p".repeat(4080),
            "protocol": "q".repeat(4080),
            "reasoning_effort": "r".repeat(4080),
        }),
    )
    .expect("the maximum provider option payload should validate");
    service
        .set_provider_profile(provider_profile)
        .expect("the provider profile should be retained");
    let key = "k".repeat(MAX_IDEMPOTENCY_KEY_BYTES);
    let admitted = service
        .admit(AdmitRunRequest {
            input: json!({"message": "m".repeat(2048)}),
            provider: Some("large-provider-with-key".to_string()),
            idempotency_key: Some(key.clone()),
            idempotency_hash: Some(TEST_REQUEST_HASH.to_string()),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("the maximum key and provider context should fit the RSS result bound");
    let context = service
        .run_context(&admitted.run_id)
        .expect("the admitted context should be retained");
    let context_bytes = serialized_context_envelope_bytes(&context);
    assert!(context_bytes <= MAX_RUN_CONTEXT_STORAGE_BYTES);
    let mut lens = AdmissionSqliteCellLens::for_tests();
    lens.input_json = context_bytes;
    lens.provider = "large-provider-with-key".len();
    lens.model = context.model.len();
    lens.idempotency_key = key.len();
    lens.has_idempotency = true;
    lens.platform = context.platform.len();
    lens.system_prompt = context.system_prompt.as_deref().unwrap_or("").len();
    estimate_admission_query_bytes(lens)
        .expect("the maximum key and provider context must be estimable")
        .ensure_fits()
        .expect("the maximum key and provider context must fit the sqlite::query budget");
    drop(service);
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

fn max_provider_name() -> String {
    "p".repeat(MAX_PROVIDER_NAME_BYTES)
}

fn max_model_name() -> String {
    "m".repeat(MAX_MODEL_NAME_BYTES)
}

fn register_named_provider(service: &rustscript_agent::AgentService, name: &str) {
    service
        .set_provider_profile(
            ProviderProfile::new(
                name.to_string(),
                json!({"profile": "p", "protocol": "local-agent"}),
            )
            .expect("a bounded provider name should validate"),
        )
        .expect("the provider profile should be retained");
}

#[tokio::test]
async fn model_and_provider_bounds_reject_one_byte_over_and_leave_no_residue() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let model_error = service
        .admit(AdmitRunRequest {
            model: Some(format!("{}x", max_model_name())),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect_err("one byte beyond the model bound must be rejected");
    assert!(matches!(
        model_error,
        AdmitError::Invalid(message) if message.contains("model")
    ));
    let provider_error = service
        .admit(AdmitRunRequest {
            provider: Some(format!("{}x", max_provider_name())),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect_err("one byte beyond the provider bound must be rejected");
    assert!(matches!(
        provider_error,
        AdmitError::Invalid(message) if message.contains("provider")
    ));
    assert_eq!(service.handle_count(), 0);
    drop(service);
    drop(state);
    assert_eq!(
        sqlite_admission_table_counts(&path),
        vec![0, 0, 0, 0, 0],
        "rejected model/provider names must leave no durable admission rows"
    );
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn model_and_provider_grammar_rejects_empty_whitespace_and_controls() {
    let state = AgentGatewayState::with_agent_source(AgentGatewayConfig::default(), test_source())
        .expect("agent source should compile");
    let service = state.service();
    for value in [
        "",
        "contains space",
        "contains\nnewline",
        "contains\u{7f}control",
    ] {
        let model_error = service
            .admit(AdmitRunRequest {
                model: Some(value.to_string()),
                platform: "service_tests".to_string(),
                ..AdmitRunRequest::default()
            })
            .await
            .expect_err("invalid model grammar must be rejected");
        assert!(matches!(
            model_error,
            AdmitError::Invalid(message) if message.contains("model")
        ));
        if !value.is_empty() {
            let provider_error = service
                .admit(AdmitRunRequest {
                    provider: Some(value.to_string()),
                    platform: "service_tests".to_string(),
                    ..AdmitRunRequest::default()
                })
                .await
                .expect_err("invalid provider grammar must be rejected");
            assert!(matches!(
                provider_error,
                AdmitError::Invalid(message) if message.contains("provider")
            ));
        }
    }
}

#[tokio::test]
async fn multibyte_model_boundary_counts_utf8_bytes() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let model = utf8_key_with_exact_bytes(MAX_MODEL_NAME_BYTES);
    assert!(
        model.chars().count() < model.len(),
        "the boundary fixture must contain multibyte UTF-8 characters"
    );
    service
        .admit(AdmitRunRequest {
            model: Some(model.clone()),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("a valid UTF-8 model at the byte limit should be admitted");
    let error = service
        .admit(AdmitRunRequest {
            model: Some(format!("{model}a")),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect_err("one additional UTF-8 byte must exceed the model bound");
    assert!(matches!(
        error,
        AdmitError::Invalid(message) if message.contains("model")
    ));
    drop(service);
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn model_padded_max_combination_admits_at_query_budget_and_resumes() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let provider = max_provider_name();
    let model = max_model_name();
    let key = "k".repeat(MAX_IDEMPOTENCY_KEY_BYTES);
    register_named_provider(&service, &provider);
    let baseline = service
        .admit(AdmitRunRequest {
            model: Some(model.clone()),
            provider: Some(provider.clone()),
            idempotency_key: Some(key.clone()),
            idempotency_hash: Some(TEST_REQUEST_HASH.to_string()),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("the max model/provider/key combination should admit a small context");
    let sizing_context = service
        .run_context(&baseline.run_id)
        .expect("baseline context should exist");
    let instructions = padded_instructions_for_run_query_budget(
        sizing_context,
        &provider,
        &model,
        &key,
        ADMISSION_QUERY_RESULT_LIMIT_BYTES,
    );
    let admitted = service
        .admit(AdmitRunRequest {
            instructions: Some(instructions),
            model: Some(model.clone()),
            provider: Some(provider.clone()),
            idempotency_key: Some("e".repeat(MAX_IDEMPOTENCY_KEY_BYTES)),
            idempotency_hash: Some("fnv64:0123456789abcdee".to_string()),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("a model-padded envelope at the sqlite::query budget should admit");
    let run_id = admitted.run_id.clone();
    let session_id = admitted.session_id.clone();
    drop(service);
    drop(state);

    let reopened = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("the SQLite gateway should reopen");
    let reopened_service = reopened.service();
    register_named_provider(&reopened_service, &provider);
    let resumed = reopened_service
        .resume_context(&run_id)
        .expect("the model-padded admission must not omit the post-commit run row");
    assert_eq!(resumed.run_id, run_id);
    assert_eq!(resumed.session_id, session_id);
    drop(reopened_service);
    drop(reopened);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn model_padded_query_budget_one_byte_over_leaves_no_residue() {
    let sizing_state =
        AgentGatewayState::with_agent_source(AgentGatewayConfig::default(), test_source())
            .expect("agent source should compile");
    let sizing_service = sizing_state.service();
    let provider = max_provider_name();
    let model = max_model_name();
    let key = "k".repeat(MAX_IDEMPOTENCY_KEY_BYTES);
    register_named_provider(&sizing_service, &provider);
    let baseline = sizing_service
        .admit(AdmitRunRequest {
            model: Some(model.clone()),
            provider: Some(provider.clone()),
            idempotency_key: Some(key.clone()),
            idempotency_hash: Some(TEST_REQUEST_HASH.to_string()),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("sizing admission should succeed");
    let sizing_context = sizing_service
        .run_context(&baseline.run_id)
        .expect("sizing context should exist");
    let instructions = padded_instructions_for_run_query_budget(
        sizing_context,
        &provider,
        &model,
        &key,
        ADMISSION_QUERY_RESULT_LIMIT_BYTES + 1,
    );
    drop(sizing_service);
    drop(sizing_state);

    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    register_named_provider(&service, &provider);
    let error = service
        .admit(AdmitRunRequest {
            instructions: Some(instructions),
            model: Some(model),
            provider: Some(provider),
            idempotency_key: Some(key),
            idempotency_hash: Some(TEST_REQUEST_HASH.to_string()),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect_err("a model-padded envelope one byte over the query budget must be rejected");
    assert!(matches!(
        error,
        AdmitError::Invalid(message) if message.contains("sqlite::query") || message.contains("SELECT estimate")
    ));
    assert_eq!(service.handle_count(), 0);
    drop(service);
    drop(state);
    assert_eq!(
        sqlite_admission_table_counts(&path),
        vec![0, 0, 0, 0, 0],
        "a rejected query-budget admission must leave no durable rows"
    );
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn empty_persisted_schema_snapshot_is_rejected_on_resume() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admission should succeed");
    let mut context = serde_json::to_value(
        service
            .run_context(&admitted.run_id)
            .expect("the captured context should exist"),
    )
    .expect("run context should serialize");
    context["tool_schemas"] = json!([]);
    let envelope = json!({"schema_version": 1, "run_context": context});
    drop(state);
    replace_persisted_run_input(&path, &admitted.run_id, &envelope);

    let reopened = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("the SQLite gateway should reopen");
    let error = reopened
        .service()
        .resume_context(&admitted.run_id)
        .expect_err("an empty persisted schema snapshot must be rejected");
    assert!(matches!(
        error,
        rustscript_agent::service::RunContextError::InvalidMetadata { .. }
    ));
    drop(reopened);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn session_metadata_replacement_cannot_block_run_scoped_admission() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let first = service
        .admit(admit_request(None))
        .await
        .expect("first admission should succeed");
    let persistence = state
        .persistence()
        .expect("persistence should be configured");
    persistence
        .session_touch(&json!({
            "session_id": first.session_id,
            "status": "active",
            "generation": 0,
            "system_prompt": "replaced",
            "model": "replaced",
            "provider": "replaced",
            "toolset_hash": "replaced",
            "metadata_json": "[]",
            "title": "replaced",
            "end_reason": "",
            "now_ms": 2
        }))
        .expect("session touch should succeed");
    drop(persistence);
    drop(state);

    let reopened = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("the SQLite gateway should reopen");
    let second = reopened
        .service()
        .admit(AdmitRunRequest {
            input: json!({"message": "after touch"}),
            session_id: Some(first.session_id),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("session-level metadata replacement must not block admission");
    assert!(!second.replayed);
    drop(reopened);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn terminal_contexts_and_registries_are_cleaned_by_the_lifecycle_janitor() {
    let config = AgentGatewayConfig {
        terminal_run_ttl: Duration::from_millis(20),
        janitor_interval: Duration::from_millis(5),
        ..AgentGatewayConfig::default()
    };
    let state = AgentGatewayState::with_agent_source(config, test_source())
        .expect("agent source should compile");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admission should succeed");
    assert!(service.run_context(&admitted.run_id).is_some());
    assert!(service.run_registry_snapshot(&admitted.run_id).is_some());
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if service.run_context(&admitted.run_id).is_none()
                && service.run_registry_snapshot(&admitted.run_id).is_none()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the janitor should release terminal context state");
    assert_eq!(service.context_cache_counts(), (0, 0));
}

#[test]
fn run_limits_validate_zero_overflow_and_workspace_paths_and_serialize_deterministically() {
    let workspace = std::env::current_dir().expect("the test workspace should exist");
    assert!(RunLimits::new(0, 1, 1, &workspace).is_err());
    assert!(RunLimits::new(1, 0, 1, &workspace).is_err());
    assert!(RunLimits::new(1, 1, 0, &workspace).is_err());
    assert!(RunLimits::new(u64::MAX, 1, 1, &workspace).is_err());
    assert!(RunLimits::new(1, 1, 1, Path::new("relative-workspace")).is_err());
    assert!(RunLimits::new(1, 1, 1, Path::new("/path/that/does/not/exist")).is_err());

    let limits = RunLimits::new(3, 4, 1024, &workspace).expect("valid limits should pass");
    assert_eq!(
        limits.to_json().to_string(),
        format!(
            "{{\"max_tool_calls\":4,\"max_tool_output_bytes\":1024,\"max_turns\":3,\"workspace_root\":\"{}\"}}",
            workspace.display()
        )
    );
}

#[test]
fn provider_profile_bounds_and_persists_only_explicit_safe_options() {
    let profile = ProviderProfile::new(
        "test-profile",
        json!({
            "profile": "test-profile",
            "protocol": "local-agent",
            "temperature": 0.2,
        }),
    )
    .expect("explicitly safe provider options should be accepted");
    assert_eq!(profile.options()["profile"], "test-profile");
    assert!(!profile.to_json().to_string().contains("[REDACTED]"));

    let oversized = ProviderProfile::new("too-large", json!({"profile": "x".repeat(20_000)}));
    assert!(
        oversized.is_err(),
        "provider option strings need a serialized size bound"
    );
}

#[tokio::test]
async fn persisted_snapshot_resumes_with_same_identity_and_rejects_registry_mismatch() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admission should succeed");
    let original = service
        .run_context(&admitted.run_id)
        .expect("original context should exist");
    let identity = original.metadata["registry_identity"]
        .as_str()
        .expect("registry identity");
    let persistence = state
        .persistence()
        .expect("persistence should be configured");
    let run_data = persistence
        .run_get(&admitted.run_id)
        .expect("run context should be durable");
    let run_row = run_data["rows"]
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(Value::as_array)
        .expect("run row should be returned");
    let envelope: Value = serde_json::from_str(
        run_row[ADMISSION_RUN_COL_INPUT_JSON]
            .as_str()
            .expect("run input should contain the context envelope"),
    )
    .expect("run context envelope should parse");
    assert_eq!(
        envelope["run_context"]["metadata"]["registry_identity"],
        identity
    );
    drop(persistence);
    drop(state);

    let resumed = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("the persisted gateway should resume");
    let resumed_service = resumed.service();
    let resumed_context = resumed_service
        .resume_context(&admitted.run_id)
        .expect("the persisted context should resume");
    assert_eq!(resumed_context.metadata["registry_identity"], identity);

    resumed_service
        .set_tool_registry(custom_registry())
        .expect("tool registry should be accepted");
    let mismatch = resumed_service
        .verify_run_context(&admitted.run_id)
        .expect_err("a changed registry must fail closed");
    assert!(matches!(
        mismatch,
        rustscript_agent::service::RunContextError::RegistryMismatch { .. }
    ));
    drop(resumed);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn registry_mismatch_is_typed_and_stops_execution_before_rss_entry() {
    let state = AgentGatewayState::with_agent_source(
        AgentGatewayConfig::default(),
        "pub fn run(context: map) -> string { \"executed\"; }",
    )
    .expect("agent source should compile");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admission should succeed");
    service
        .set_tool_registry(custom_registry())
        .expect("tool registry should be accepted");
    assert!(matches!(
        service.verify_run_context(&admitted.run_id),
        Err(rustscript_agent::service::RunContextError::RegistryMismatch { .. })
    ));
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    let context = service
        .run_context(&admitted.run_id)
        .expect("context should remain inspectable after fail-closed execution");
    assert_eq!(
        context.metadata["registry_identity"],
        context.metadata["toolset_hash"]
    );
}

#[tokio::test]
async fn invalid_request_hash_is_rejected_before_admission() {
    let service =
        AgentGatewayState::with_agent_source(AgentGatewayConfig::default(), test_source())
            .expect("agent source should compile")
            .service();
    let error = service
        .admit(AdmitRunRequest {
            idempotency_key: Some("valid-key".to_string()),
            idempotency_hash: Some("service-test-request-hash".to_string()),
            ..admit_request(None)
        })
        .await
        .expect_err("an invalid request hash must be rejected");
    assert!(matches!(error, AdmitError::Invalid(_)));
}

#[tokio::test]
async fn idempotent_replay_returns_original_run_after_live_registry_change() {
    let service =
        AgentGatewayState::with_agent_source(AgentGatewayConfig::default(), test_source())
            .expect("agent source should compile")
            .service();
    let first = service
        .admit(admit_request_with_idempotency_key(
            "replay-after-registry".to_string(),
        ))
        .await
        .expect("first admission should succeed");
    let original = service
        .run_context(&first.run_id)
        .expect("the original context should exist");
    service
        .set_tool_registry(custom_registry())
        .expect("the changed registry should be accepted");
    let replayed = service
        .admit(admit_request_with_idempotency_key(
            "replay-after-registry".to_string(),
        ))
        .await
        .expect("replay must not compare the snapshot against the live registry");
    assert!(replayed.replayed);
    assert_eq!(replayed.run_id, first.run_id);
    assert_eq!(replayed.session_id, first.session_id);
    let replayed_context = service
        .run_context(&replayed.run_id)
        .expect("the original context should remain cached");
    assert_eq!(replayed_context, original);
    let mismatch = service
        .verify_run_context(&first.run_id)
        .expect_err("worker execution must still fail closed against the admitted snapshot");
    assert!(matches!(
        mismatch,
        rustscript_agent::service::RunContextError::RegistryMismatch { .. }
    ));
}

#[tokio::test]
async fn durable_restart_replay_returns_original_run_after_registry_change() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let first = service
        .admit(admit_request_with_idempotency_key(
            "durable-replay-after-registry".to_string(),
        ))
        .await
        .expect("first admission should succeed");
    let original = service
        .run_context(&first.run_id)
        .expect("the original context should exist");
    drop(state);

    let resumed = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("the persisted gateway should resume");
    let resumed_service = resumed.service();
    resumed_service
        .set_tool_registry(custom_registry())
        .expect("the changed registry should be accepted");
    let replayed = resumed_service
        .admit(admit_request_with_idempotency_key(
            "durable-replay-after-registry".to_string(),
        ))
        .await
        .expect("durable replay must return the original admitted run");
    assert!(replayed.replayed);
    assert_eq!(replayed.run_id, first.run_id);
    let restored = resumed_service
        .resume_context(&first.run_id)
        .expect("the original snapshot should restore");
    assert_eq!(restored.messages, original.messages);
    assert_eq!(
        restored.metadata["registry_identity"],
        original.metadata["registry_identity"]
    );
    let mismatch = resumed_service
        .verify_run_context(&first.run_id)
        .expect_err("worker execution must still fail closed after restart");
    assert!(matches!(
        mismatch,
        rustscript_agent::service::RunContextError::RegistryMismatch { .. }
    ));
    drop(resumed);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn compact_durable_envelope_does_not_embed_prior_history() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let first = service
        .admit(AdmitRunRequest {
            input: json!({"message": "UNIQUE_TURN_1_HISTORY"}),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("first turn should admit");
    let first_context = service
        .run_context(&first.run_id)
        .expect("first context should exist");
    let second = service
        .admit(AdmitRunRequest {
            session_id: Some(first.session_id.clone()),
            input: json!({"message": "UNIQUE_TURN_2"}),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("second turn should admit");
    let second_context = service
        .run_context(&second.run_id)
        .expect("second context should exist");
    assert!(
        second_context
            .messages
            .to_string()
            .contains("UNIQUE_TURN_1_HISTORY"),
        "in-memory context must still include prior history"
    );
    let persistence = state
        .persistence()
        .expect("persistence should be configured");
    let run_data = persistence
        .run_get(&second.run_id)
        .expect("second run should be durable");
    let run_row = run_data["rows"]
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(Value::as_array)
        .expect("run row should be returned");
    let envelope: Value = serde_json::from_str(
        run_row[ADMISSION_RUN_COL_INPUT_JSON]
            .as_str()
            .expect("run input should contain the compact envelope"),
    )
    .expect("run context envelope should parse");
    let persisted = &envelope["run_context"];
    assert_eq!(persisted["messages"], json!([]));
    assert_eq!(persisted["input"], json!({"message": "UNIQUE_TURN_2"}));
    assert!(persisted["metadata"].get("tool_schemas").is_none());
    assert!(persisted["metadata"].get("provider_options").is_none());
    assert!(persisted["metadata"].get("limits").is_none());
    assert!(persisted["metadata"].get("input").is_none());
    let serialized = serde_json::to_string(persisted).expect("compact payload should serialize");
    assert!(
        !serialized.contains("UNIQUE_TURN_1_HISTORY"),
        "prior history must not be recursively embedded in the durable envelope"
    );
    drop(persistence);
    drop(state);

    let resumed = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("the persisted gateway should resume");
    let resumed_service = resumed.service();
    let restored_first = resumed_service
        .resume_context(&first.run_id)
        .expect("first turn should restore without later history");
    assert_eq!(restored_first.messages, first_context.messages);
    let restored_second = resumed_service
        .resume_context(&second.run_id)
        .expect("second turn should reconstruct history from durable rows");
    assert_eq!(restored_second.messages, second_context.messages);
    drop(resumed);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn small_followup_turn_does_not_fail_budget_because_of_old_history() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let first = service
        .admit(AdmitRunRequest {
            input: json!({"message": "x".repeat(8 * 1024)}),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("large first turn should admit");
    let second = service
        .admit(AdmitRunRequest {
            session_id: Some(first.session_id.clone()),
            input: json!({"message": "tiny"}),
            platform: "service_tests".to_string(),
            ..AdmitRunRequest::default()
        })
        .await
        .expect("a small follow-up must not inherit the previous envelope budget");
    assert!(!second.replayed);
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[test]
fn provider_pending_retry_requires_no_response_idempotent_and_no_effect() {
    assert!(provider_pending_may_retry(false, true, false));
    assert!(
        !provider_pending_may_retry(true, true, false),
        "a completed provider response is replayed, never retried"
    );
    assert!(
        !provider_pending_may_retry(false, false, false),
        "non-idempotent provider requests are not retried"
    );
    assert!(
        !provider_pending_may_retry(false, true, true),
        "provider requests that already produced an effect are not retried"
    );
}

#[tokio::test]
async fn tool_step_commits_message_before_live_and_replays_without_reexecution() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    let call = ToolCall {
        id: "call-echo".to_string(),
        name: "not_a_real_tool".to_string(),
        arguments: json!({}),
    };
    service
        .commit_provider_step(
            &admitted.run_id,
            1,
            &[LlmContentBlock {
                block_type: "tool_call".to_string(),
                tool_call_id: Some(call.id.clone()),
                name: Some(call.name.clone()),
                arguments_json: Some("{}".to_string()),
                ..LlmContentBlock::default()
            }],
            None,
            Some("tool_calls"),
            None,
            None,
            None,
        )
        .expect("assistant tool-call parent must be durable first");
    let first = service
        .dispatch_tools(&admitted.run_id, std::slice::from_ref(&call))
        .expect("first dispatch should run");
    assert_eq!(first.len(), 1);
    assert!(!first[0].ok);
    let events = service.run_events(&admitted.run_id);
    let tool_failed = events
        .iter()
        .filter(|event| event["event"] == "tool.failed")
        .count();
    assert_eq!(tool_failed, 1, "first dispatch commits one tool.failed");
    let second = service
        .dispatch_tools(&admitted.run_id, std::slice::from_ref(&call))
        .expect("replay should succeed");
    assert_eq!(second.len(), 1);
    assert_eq!(
        second[0].error.as_ref().map(|error| error.code.as_str()),
        first[0].error.as_ref().map(|error| error.code.as_str())
    );
    let events = service.run_events(&admitted.run_id);
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "tool.failed")
            .count(),
        1,
        "duplicate dispatch must not append another failed event"
    );
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn persist_failure_rolls_back_tool_step_without_live_publish() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    let call = ToolCall {
        id: "call-fail".to_string(),
        name: "not_a_real_tool".to_string(),
        arguments: json!({}),
    };
    service
        .commit_provider_step(
            &admitted.run_id,
            1,
            &[LlmContentBlock {
                block_type: "tool_call".to_string(),
                tool_call_id: Some(call.id.clone()),
                name: Some(call.name.clone()),
                arguments_json: Some("{}".to_string()),
                ..LlmContentBlock::default()
            }],
            None,
            Some("tool_calls"),
            None,
            None,
            None,
        )
        .expect("assistant tool-call parent must be durable first");
    state
        .persistence()
        .expect("sqlite persistence")
        .inject_persist_failure();
    let results = service
        .dispatch_tools(&admitted.run_id, std::slice::from_ref(&call))
        .expect("dispatch should return persist failure");
    assert_eq!(
        results[0].error.as_ref().map(|error| error.code.as_str()),
        Some("event_persist_failed")
    );
    let events = service.run_events(&admitted.run_id);
    assert!(
        events
            .iter()
            .all(|event| event["event"] != "tool.requested"),
        "failed persist must roll back in-memory tool events: {events:?}"
    );
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn provider_step_commits_canonical_tool_call_message_atomically() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    let usage = rustscript_agent::Usage {
        input_tokens: 3,
        output_tokens: 5,
        total_tokens: 8,
    };
    let message_id = service
        .commit_provider_step(
            &admitted.run_id,
            1,
            &[LlmContentBlock {
                block_type: "tool_call".to_string(),
                tool_call_id: Some("c-1".to_string()),
                name: Some("read_file".to_string()),
                arguments_json: Some("{\"path\":\"a.rs\"}".to_string()),
                ..LlmContentBlock::default()
            }],
            Some(&usage),
            Some("tool_calls"),
            Some("openai"),
            Some("gpt-test"),
            Some("parent-msg"),
        )
        .expect("provider step should commit");
    assert!(!message_id.is_empty());
    let events = service.run_events(&admitted.run_id);
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "model.completed"),
        "provider step publishes only after commit"
    );
    let replayed = service
        .commit_provider_step(
            &admitted.run_id,
            1,
            &[LlmContentBlock {
                block_type: "tool_call".to_string(),
                tool_call_id: Some("c-1".to_string()),
                name: Some("read_file".to_string()),
                arguments_json: Some("{\"path\":\"a.rs\"}".to_string()),
                ..LlmContentBlock::default()
            }],
            Some(&usage),
            Some("tool_calls"),
            Some("openai"),
            Some("gpt-test"),
            Some("parent-msg"),
        )
        .expect("duplicate provider step is idempotent");
    assert_eq!(replayed, message_id);
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "model.completed")
            .count(),
        service
            .run_events(&admitted.run_id)
            .iter()
            .filter(|event| event["event"] == "model.completed")
            .count()
    );
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn missing_tool_result_parent_fails_typed_before_durable_result() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    let call = ToolCall {
        id: "call-orphan".to_string(),
        name: "not_a_real_tool".to_string(),
        arguments: json!({}),
    };
    let results = service
        .dispatch_tools(&admitted.run_id, std::slice::from_ref(&call))
        .expect("dispatch should return typed missing parent");
    assert_eq!(
        results[0].error.as_ref().map(|error| error.code.as_str()),
        Some("missing_tool_parent")
    );
    let events = service.run_events(&admitted.run_id);
    assert!(
        events.iter().all(|event| event["event"] != "tool.started"
            && event["event"] != "tool.failed"
            && event["event"] != "tool.completed"
            && event["event"] != "tool.requested"),
        "missing parent must not start a tool or persist a result: {events:?}"
    );
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn tool_result_stores_actual_assistant_parent_and_name() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    let call = ToolCall {
        id: "call-parent".to_string(),
        name: "not_a_real_tool".to_string(),
        arguments: json!({"secret": "nope"}),
    };
    let parent_id = service
        .commit_provider_step(
            &admitted.run_id,
            1,
            &[LlmContentBlock {
                block_type: "tool_call".to_string(),
                tool_call_id: Some(call.id.clone()),
                name: Some(call.name.clone()),
                arguments_json: Some(r#"{"secret":"nope"}"#.to_string()),
                ..LlmContentBlock::default()
            }],
            None,
            Some("tool_calls"),
            None,
            None,
            None,
        )
        .expect("assistant tool-call parent");
    let results = service
        .dispatch_tools(&admitted.run_id, std::slice::from_ref(&call))
        .expect("dispatch with parent");
    assert_eq!(
        results[0].error.as_ref().map(|error| error.code.as_str()),
        Some("unknown_tool")
    );
    assert_ne!(parent_id, "");
    let events = service.run_events(&admitted.run_id);
    assert!(
        events.iter().any(|event| event["event"] == "tool.failed"),
        "linked tool result must be durable: {events:?}"
    );
    let stored = service
        .session_messages(&admitted.session_id)
        .into_iter()
        .find(|message| message["role"] == "user" && message["tool_call_id"] == call.id)
        .expect("tool result message");
    assert_eq!(stored["parent_message_id"], json!(parent_id));
    assert_eq!(stored["name"], json!(call.name));
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn in_txn_failpoint_rolls_back_provider_step_on_reopen() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    state
        .persistence()
        .expect("sqlite persistence")
        .inject_fail_after_partial_write();
    service
        .commit_provider_step(
            &admitted.run_id,
            1,
            &[LlmContentBlock {
                block_type: "tool_call".to_string(),
                tool_call_id: Some("c-fail".to_string()),
                name: Some("read_file".to_string()),
                arguments_json: Some("{}".to_string()),
                ..LlmContentBlock::default()
            }],
            None,
            Some("tool_calls"),
            None,
            None,
            None,
        )
        .expect_err("in-txn failpoint must fail");
    assert!(
        service
            .run_events(&admitted.run_id)
            .iter()
            .all(|event| event["event"] != "model.completed"),
        "persist failure must leave live memory unchanged"
    );
    drop(state);
    let resumed = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("reopen");
    let events = resumed.service().run_events(&admitted.run_id);
    assert!(
        events
            .iter()
            .all(|event| event["event"] != "model.completed"),
        "rollback must leave no provider step: {events:?}"
    );
    drop(resumed);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn post_commit_failpoint_is_replayable_and_publishes_once_on_recovery() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    state
        .persistence()
        .expect("sqlite persistence")
        .inject_fail_after_commit_before_publish();
    let _ = service
        .commit_provider_step(
            &admitted.run_id,
            1,
            &[LlmContentBlock {
                block_type: "tool_call".to_string(),
                tool_call_id: Some("c-crash".to_string()),
                name: Some("read_file".to_string()),
                arguments_json: Some("{}".to_string()),
                ..LlmContentBlock::default()
            }],
            None,
            Some("tool_calls"),
            Some("openai"),
            Some("gpt-test"),
            Some("parent-msg"),
        )
        .expect_err("post-commit failpoint skips live publish");
    assert_eq!(
        service
            .run_events(&admitted.run_id)
            .iter()
            .filter(|event| event["event"] == "model.completed")
            .count(),
        0,
        "live publish must not happen before recovery"
    );
    drop(state);
    let resumed = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("reopen");
    let service = resumed.service();
    assert_eq!(
        service
            .run_events(&admitted.run_id)
            .iter()
            .filter(|event| event["event"] == "model.completed")
            .count(),
        1,
        "recovery must surface the durable event once"
    );
    service
        .commit_provider_step(
            &admitted.run_id,
            1,
            &[LlmContentBlock {
                block_type: "tool_call".to_string(),
                tool_call_id: Some("c-crash".to_string()),
                name: Some("read_file".to_string()),
                arguments_json: Some("{}".to_string()),
                ..LlmContentBlock::default()
            }],
            None,
            Some("tool_calls"),
            Some("openai"),
            Some("gpt-test"),
            Some("parent-msg"),
        )
        .expect("replay is idempotent");
    assert_eq!(
        service
            .run_events(&admitted.run_id)
            .iter()
            .filter(|event| event["event"] == "model.completed")
            .count(),
        1
    );
    drop(resumed);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn pending_provider_retries_only_when_safe_and_is_idempotent() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    service
        .commit_provider_request(&admitted.run_id, 1, true, &json!({"prompt": "hi"}))
        .expect("request boundary");
    drop(state);
    let resumed = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("reopen");
    let service = resumed.service();
    let provider = ScriptedProvider::new();
    provider.push_ok(json!({"content": [{"type": "text", "text": "ok"}]}));
    assert_eq!(
        service
            .recover_pending_provider(&admitted.run_id, 1, &provider)
            .expect("retry"),
        ProviderPendingDecision::Retry
    );
    assert_eq!(provider.call_count(), 1);
    assert_eq!(
        service
            .recover_pending_provider(&admitted.run_id, 1, &provider)
            .expect("replay"),
        ProviderPendingDecision::Replay
    );
    assert_eq!(provider.call_count(), 1);
    drop(resumed);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn pending_provider_with_effect_is_interrupted_without_retry() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    service
        .commit_provider_request(&admitted.run_id, 1, true, &json!({"prompt": "hi"}))
        .expect("request boundary");
    state
        .persistence()
        .expect("sqlite")
        .event_append(&json!({
            "run_id": admitted.run_id,
            "event_id": "effect-1",
            "event_type": "tool.started",
            "payload_json": "{\"tool_call_id\":\"c-1\"}",
            "now_ms": 20,
            "max_events": 128
        }))
        .expect("effect boundary");
    drop(state);
    let resumed = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("reopen");
    let service = resumed.service();
    let provider = ScriptedProvider::new();
    provider.push_ok(json!({"content": [{"type": "text", "text": "should not run"}]}));
    assert_eq!(
        service
            .recover_pending_provider(&admitted.run_id, 1, &provider)
            .expect("interrupt"),
        ProviderPendingDecision::Interrupted
    );
    assert_eq!(provider.call_count(), 0);
    assert_eq!(
        service
            .recover_pending_provider(&admitted.run_id, 1, &provider)
            .expect("interrupt idempotent"),
        ProviderPendingDecision::Interrupted
    );
    assert_eq!(provider.call_count(), 0);
    let interrupted = service
        .run_events(&admitted.run_id)
        .iter()
        .filter(|event| {
            event["event"] == "model.failed"
                && event["data"]["error_code"] == "interrupted_provider"
        })
        .count();
    assert_eq!(interrupted, 1);
    drop(resumed);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn persist_block_hides_store_mutation_until_durable_success() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    let guard = state.persistence().expect("sqlite").inject_block_persist();
    let run_id = admitted.run_id.clone();
    let worker_service = service.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = worker_service.commit_provider_step(
            &run_id,
            1,
            &[LlmContentBlock {
                block_type: "text".to_string(),
                text: Some("blocked".to_string()),
                ..LlmContentBlock::default()
            }],
            None,
            Some("stop"),
            None,
            None,
            None,
        );
        let _ = done_tx.send(result);
    });
    guard.wait_entered();
    assert!(
        service
            .run_events(&admitted.run_id)
            .iter()
            .all(|event| event["event"] != "model.completed"),
        "GET must not observe the step before durable success"
    );
    assert_eq!(
        service
            .session_messages(&admitted.session_id)
            .iter()
            .filter(|message| message["role"] == "assistant")
            .count(),
        0,
        "session messages must stay pre-commit during persist"
    );
    guard.release();
    done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("blocked persist must finish after release")
        .expect("provider step should commit after persist");
    worker.join().expect("persist worker");
    assert_eq!(
        service
            .run_events(&admitted.run_id)
            .iter()
            .filter(|event| event["event"] == "model.completed")
            .count(),
        1
    );
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn persist_failure_leaves_memory_unchanged_without_rollback() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    let before_events = service.run_events(&admitted.run_id).len();
    let before_messages = service.session_messages(&admitted.session_id).len();
    state
        .persistence()
        .expect("sqlite")
        .inject_persist_failure();
    service
        .commit_provider_step(
            &admitted.run_id,
            1,
            &[LlmContentBlock {
                block_type: "text".to_string(),
                text: Some("must not apply".to_string()),
                ..LlmContentBlock::default()
            }],
            None,
            Some("stop"),
            None,
            None,
            None,
        )
        .expect_err("injected persist failure must fail");
    assert_eq!(service.run_events(&admitted.run_id).len(), before_events);
    assert_eq!(
        service.session_messages(&admitted.session_id).len(),
        before_messages
    );
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn provider_and_tool_ordinals_are_deterministic_across_reopen() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    service
        .commit_provider_step(
            &admitted.run_id,
            1,
            &[LlmContentBlock {
                block_type: "tool_call".to_string(),
                tool_call_id: Some("c-ord".to_string()),
                name: Some("read_file".to_string()),
                arguments_json: Some("{\"path\":\"a.rs\"}".to_string()),
                ..LlmContentBlock::default()
            }],
            None,
            Some("tool_calls"),
            None,
            None,
            None,
        )
        .expect("provider step");
    service
        .commit_tool_step(
            &admitted.run_id,
            "tool.completed",
            json!({"tool_call_id": "c-ord"}),
            Some(&ToolResult::success("ok", json!({}))),
        )
        .expect("tool step");
    let live_by_id: Vec<(String, i64)> = service
        .session_messages(&admitted.session_id)
        .into_iter()
        .filter_map(|message| {
            Some((
                message["id"].as_str()?.to_string(),
                message["ordinal"].as_i64()?,
            ))
        })
        .collect();
    assert!(
        live_by_id.len() >= 2,
        "provider and tool messages must carry ordinals: {live_by_id:?}"
    );
    assert!(
        live_by_id.windows(2).all(|pair| pair[0].1 < pair[1].1),
        "live ordinals must be strictly increasing: {live_by_id:?}"
    );
    drop(state);
    let resumed = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("reopen");
    let resumed_by_id: Vec<(String, i64)> = resumed
        .service()
        .session_messages(&admitted.session_id)
        .into_iter()
        .filter_map(|message| {
            Some((
                message["id"].as_str()?.to_string(),
                message["ordinal"].as_i64()?,
            ))
        })
        .collect();
    assert!(
        resumed_by_id.windows(2).all(|pair| pair[0].1 < pair[1].1),
        "reopened ordinals must be strictly increasing: {resumed_by_id:?}"
    );
    for (id, ordinal) in &live_by_id {
        assert_eq!(
            resumed_by_id
                .iter()
                .find(|(resumed_id, _)| resumed_id == id)
                .map(|(_, resumed_ordinal)| *resumed_ordinal),
            Some(*ordinal),
            "ordinal for {id} must survive reopen"
        );
    }
    drop(resumed);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn corrupt_tool_event_without_canonical_result_fails_closed() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    service
        .persist_run_event(
            &admitted.run_id,
            "evt-corrupt",
            "tool.failed",
            json!({"tool_call_id": "c-corrupt", "error_code": "tool_failed"}),
        )
        .expect("orphan tool event");
    let results = service
        .dispatch_tools(
            &admitted.run_id,
            &[ToolCall {
                id: "c-corrupt".to_string(),
                name: "read_file".to_string(),
                arguments: json!({"path": "a.rs"}),
            }],
        )
        .expect("corrupt replay must dispatch");
    assert_eq!(
        results[0].error.as_ref().map(|error| error.code.as_str()),
        Some("corrupt_tool_result")
    );
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[tokio::test]
async fn terminal_run_refuses_pending_provider_without_retry() {
    let path = temporary_db_path();
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        test_source(),
        &path,
    )
    .expect("SQLite gateway should open");
    let service = state.service();
    let admitted = service
        .admit(admit_request(None))
        .await
        .expect("admit should succeed");
    service
        .commit_provider_request(&admitted.run_id, 1, true, &json!({"prompt": "hi"}))
        .expect("request boundary");
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;
    let provider = ScriptedProvider::new();
    provider.push_ok(json!({"content": [{"type": "text", "text": "should not run"}]}));
    assert_eq!(
        service
            .recover_pending_provider(&admitted.run_id, 1, &provider)
            .expect("terminal refusal"),
        ProviderPendingDecision::RefusedTerminal
    );
    assert_eq!(provider.call_count(), 0);
    assert_eq!(
        service
            .run_events(&admitted.run_id)
            .iter()
            .filter(|event| event["event"] == "model.completed")
            .count(),
        0
    );
    drop(state);
    std::fs::remove_file(path).expect("temporary SQLite state should be removed");
}

#[test]
fn oversized_tool_result_and_error_are_redacted_not_rejected() {
    let blob = "x".repeat(70_000);
    let encoded = encode_message_content(&[LlmContentBlock {
        block_type: "tool_result".to_string(),
        tool_call_id: Some("c-bound".to_string()),
        name: Some("read_file".to_string()),
        result: Some(json!({"blob": blob})),
        error: Some(json!({"code": "tool_failed", "message": "y".repeat(70_000)})),
        ..LlmContentBlock::default()
    }]);
    let block = encoded
        .as_array()
        .and_then(|blocks| blocks.first())
        .expect("encoded block");
    assert_eq!(block["result"]["redacted"], json!(true));
    assert_eq!(block["result"]["truncated"], json!(true));
    assert!(block["result"].get("blob").is_none());
    assert_eq!(block["error"]["redacted"], json!(true));
    assert_eq!(block["error"]["code"], json!("tool_failed"));
    assert!(block["error"].get("message").is_none());
    assert_eq!(block["truncated"], json!(true));
}
