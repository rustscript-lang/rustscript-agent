#![cfg(feature = "config-fixture")]

#[path = "support/provider_opaque_fixture.rs"]
#[allow(dead_code)]
mod provider_opaque_fixture;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use provider_opaque_fixture::FixtureHome;
use rustscript_agent::auth::oauth::ScriptedHttpsTransport;
use rustscript_agent::config::ProviderProfile;
use rustscript_agent::{
    AdmitRunRequest, AgentConfig, AgentGatewayConfig, AgentGatewayState, AgentHostBridges,
    AgentRunner, RunCancellation,
};
use serde_json::{Value as JsonValue, json};

const PROVIDER: &str = "openai";
const BASE_URL: &str = "https://fixture-durable.example.test/v1";
const CREDENTIAL: &str = "durable-fixture-credential";
const ACCESS: &str = "SYNTHETIC_DURABLE_ACCESS";
const REFRESH: &str = "SYNTHETIC_REFRESH_TOKEN";
const EXPECTED_URL: &str = "https://fixture-durable.example.test/v1/chat/completions";
const USER_TEXT: &str = "reply with a short service fixture answer";
const EXPECTED_USER_TEXT: &str = "{\"message\":\"reply with a short service fixture answer\"}";
const ANSWER: &str = "durable service answer";

fn fixture_home() -> FixtureHome {
    FixtureHome::for_profile("durable", PROVIDER, BASE_URL, CREDENTIAL, ACCESS)
}

fn fixture_db_path() -> PathBuf {
    let root = PathBuf::from(
        std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture temp"),
    );
    root.join(format!("provider-durable-{}.db", uuid::Uuid::new_v4()))
}

fn service_config() -> AgentGatewayConfig {
    AgentGatewayConfig {
        provider: Some(PROVIDER.to_string()),
        model: "durable-request-model".to_string(),
        run_timeout: Duration::from_secs(30),
        ..AgentGatewayConfig::default()
    }
}

fn admit_request() -> AdmitRunRequest {
    AdmitRunRequest {
        input: json!({"message": USER_TEXT}),
        model: Some("durable-request-model".to_string()),
        provider: Some(PROVIDER.to_string()),
        platform: "provider_durable_replay_loop_tests".to_string(),
        ..AdmitRunRequest::default()
    }
}

fn public_profile(credential_id: &str) -> ProviderProfile {
    ProviderProfile::new(
        PROVIDER,
        json!({
            "profile": PROVIDER,
            "protocol": "openai-chat-completions",
            "base_url": BASE_URL,
            "credential_id": credential_id,
        }),
    )
    .expect("bounded public credential reference should validate")
}

fn install_native_provider(
    service: &rustscript_agent::AgentService,
    home: &FixtureHome,
    transport: Arc<ScriptedHttpsTransport>,
) {
    service.set_auth_host_factory(home.auth_factory(transport));
    service.upsert_provider_profile(public_profile(CREDENTIAL));
}

fn open_sqlite_service(db_path: &std::path::Path) -> AgentGatewayState {
    AgentGatewayState::with_agent_file_and_sqlite(
        service_config(),
        rustscript_agent::bundled_agent_main_path(),
        db_path,
    )
    .expect("bundled production agent should compile against SQLite fixture")
}

fn actual_default_runner(
    home: &FixtureHome,
    transport: Arc<ScriptedHttpsTransport>,
) -> AgentRunner {
    let bridges = AgentHostBridges {
        auth_host_factory: Some(home.auth_factory(transport)),
        ..AgentHostBridges::default()
    };
    AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/main.rss"),
        AgentConfig::default(),
    )
    .expect("production agent loop should compile")
    .with_host(bridges)
    .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)))
}

fn queue_text_response(transport: &ScriptedHttpsTransport) {
    transport.push_json(
        200,
        json!({
            "id": "chatcmpl-durable-fixture",
            "choices": [{
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": ANSWER}
            }],
            "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}
        }),
    );
}

fn event_names(events: &[JsonValue]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|event| event.get("event").and_then(JsonValue::as_str))
        .collect()
}

fn named_event_count(events: &[JsonValue], name: &str) -> usize {
    events
        .iter()
        .filter(|event| event.get("event").and_then(JsonValue::as_str) == Some(name))
        .count()
}

fn assistant_messages(
    service: &rustscript_agent::AgentService,
    session_id: &str,
) -> Vec<JsonValue> {
    service
        .session_messages(session_id)
        .into_iter()
        .filter(|message| message["role"] == "assistant")
        .collect()
}

fn event_ids(events: &[JsonValue]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| event.get("event_id").and_then(JsonValue::as_str))
        .map(str::to_string)
        .collect()
}

fn message_ids(messages: &[JsonValue]) -> Vec<String> {
    messages
        .iter()
        .filter_map(|message| message.get("id").and_then(JsonValue::as_str))
        .map(str::to_string)
        .collect()
}

fn message_identity_and_content(messages: &[JsonValue]) -> Vec<JsonValue> {
    messages
        .iter()
        .map(|message| {
            json!({
                "id": message.get("id"),
                "role": message.get("role"),
                "run_id": message.get("run_id"),
                "session_id": message.get("session_id"),
                "created_at": message.get("created_at"),
                "content": message.get("content"),
                "parent_message_id": message.get("parent_message_id"),
                "finish_reason": message.get("finish_reason"),
                "metadata": message.get("metadata"),
                "token_estimate": message.get("token_estimate"),
            })
        })
        .collect()
}

fn assert_no_fixture_secrets(bytes: &[u8], label: &str) {
    for secret in [ACCESS.as_bytes(), REFRESH.as_bytes()] {
        assert!(
            !bytes.windows(secret.len()).any(|window| window == secret),
            "private fixture secret found in {label}"
        );
    }
}

fn assert_no_fixture_secret_text(text: &str, label: &str) {
    assert!(
        !text.contains(ACCESS),
        "private fixture secret found in {label}"
    );
    assert!(
        !text.contains(REFRESH),
        "private fixture secret found in {label}"
    );
}

fn assert_durable_files_secret_free(db_path: &std::path::Path) {
    for suffix in ["", "-wal", "-journal"] {
        let path = PathBuf::from(format!("{}{suffix}", db_path.display()));
        if let Ok(bytes) = fs::read(&path) {
            assert_no_fixture_secrets(&bytes, "SQLite fixture bytes");
        }
    }
}

fn assert_service_surfaces_secret_free(
    service: &rustscript_agent::AgentService,
    run_id: &str,
    session_id: &str,
    db_path: &std::path::Path,
) {
    let events = service.run_events(run_id);
    let messages = service.session_messages(session_id);
    let context = service
        .run_context(run_id)
        .expect("public retained run context");
    let resumed = service
        .resume_context(run_id)
        .expect("public persisted run context");
    assert_no_fixture_secret_text(
        &serde_json::to_string(&events).expect("events JSON"),
        "events",
    );
    assert_no_fixture_secret_text(
        &serde_json::to_string(&messages).expect("messages JSON"),
        "messages",
    );
    assert_no_fixture_secret_text(
        &serde_json::to_string(&context).expect("serialize public run context"),
        "public run context",
    );
    assert_no_fixture_secret_text(
        &serde_json::to_string(&resumed).expect("serialize resumed run context"),
        "resumed run context",
    );
    assert_durable_files_secret_free(db_path);
}

fn remove_db_artifacts(db_path: &std::path::Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let path = PathBuf::from(format!("{}{suffix}", db_path.display()));
        let _ = fs::remove_file(path);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_service_worker_sends_one_native_authenticated_default_provider_request() {
    let home = fixture_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    queue_text_response(&transport);
    let db_path = fixture_db_path();
    let state = open_sqlite_service(&db_path);
    let service = state.service();
    install_native_provider(&service, &home, Arc::clone(&transport));
    let admitted = service
        .admit(admit_request())
        .await
        .expect("service admission should succeed");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let events = service.run_events(&admitted.run_id);
    let names = event_names(&events);
    assert_eq!(
        named_event_count(&events, "run.completed"),
        1,
        "events={names:?}"
    );
    assert_eq!(
        named_event_count(&events, "model.requested"),
        1,
        "events={names:?}"
    );
    assert_eq!(
        named_event_count(&events, "model.completed"),
        1,
        "events={names:?}"
    );
    let assistants = assistant_messages(&service, &admitted.session_id);
    assert_eq!(
        assistants.len(),
        1,
        "completed run should persist one assistant answer"
    );
    assert!(assistants[0].to_string().contains(ANSWER));

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "one native provider send");
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].url, EXPECTED_URL);
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some("Bearer SYNTHETIC_DURABLE_ACCESS")
    );
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("public OpenAI request JSON");
    assert_no_fixture_secret_text(&sent[0].body, "provider request body");
    assert_eq!(wire["model"], json!("durable-request-model"));
    let wire_messages = wire["messages"]
        .as_array()
        .expect("parsed OpenAI public messages");
    assert_eq!(wire_messages.len(), 2);
    assert_eq!(wire_messages[0]["role"], "system");
    assert!(
        !wire_messages[0]["content"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );
    assert_eq!(
        wire_messages[1],
        json!({
            "role": "user",
            "content": [{"type": "text", "text": EXPECTED_USER_TEXT}]
        })
    );

    let context = service
        .run_context(&admitted.run_id)
        .expect("public run context should retain the named credential reference");
    assert_eq!(context.provider_options["credential_id"], CREDENTIAL);
    assert_service_surfaces_secret_free(&service, &admitted.run_id, &admitted.session_id, &db_path);

    let metrics = service.metrics().snapshot();
    assert_eq!(metrics.model_calls, 1);
    assert_eq!(metrics.turns, 1);

    drop(service);
    drop(state);
    drop(home);
    remove_db_artifacts(&db_path);
}

#[tokio::test(flavor = "multi_thread")]
async fn completed_provider_step_replays_in_service_without_a_duplicate_native_send() {
    let home = fixture_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    queue_text_response(&transport);
    let db_path = fixture_db_path();
    let state = open_sqlite_service(&db_path);
    let service = state.service();
    install_native_provider(&service, &home, Arc::clone(&transport));
    let admitted = service.admit(admit_request()).await.expect("admission");
    service.inject_crash_after_provider_commit();

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let events_before = service.run_events(&admitted.run_id);
    let names_before = event_names(&events_before);
    assert!(
        !names_before
            .iter()
            .any(|name| name.starts_with("run.completed")
                || *name == "run.failed"
                || *name == "run.cancelled")
    );
    assert_eq!(named_event_count(&events_before, "model.requested"), 1);
    assert_eq!(named_event_count(&events_before, "model.completed"), 1);
    let assistants_before = assistant_messages(&service, &admitted.session_id);
    assert_eq!(assistants_before.len(), 1);
    assert_eq!(
        transport.take_sent().len(),
        1,
        "initial native provider send"
    );

    // This is an in-service durable replay: retain service + DB, evict only
    // the run handle, then re-drive the same admitted run.
    service.evict_run_handle(&admitted.run_id);
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let events_after = service.run_events(&admitted.run_id);
    let names_after = event_names(&events_after);
    assert_eq!(
        named_event_count(&events_after, "run.completed"),
        1,
        "events={names_after:?}"
    );
    assert_eq!(named_event_count(&events_after, "model.requested"), 1);
    assert_eq!(named_event_count(&events_after, "model.completed"), 1);
    assert_eq!(
        assistant_messages(&service, &admitted.session_id),
        assistants_before
    );
    assert!(
        assistant_messages(&service, &admitted.session_id)[0]
            .to_string()
            .contains(ANSWER)
    );
    assert!(
        transport.take_sent().is_empty(),
        "completed step replay must not send again"
    );
    let metrics = service.metrics().snapshot();
    assert_eq!(metrics.model_calls, 1);
    assert_eq!(metrics.turns, 1);
    assert_service_surfaces_secret_free(&service, &admitted.run_id, &admitted.session_id, &db_path);

    drop(service);
    drop(state);
    drop(home);
    remove_db_artifacts(&db_path);
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_provider_request_redrive_sends_once_without_a_second_logical_request() {
    let home = fixture_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    queue_text_response(&transport);
    let db_path = fixture_db_path();
    let state = open_sqlite_service(&db_path);
    let service = state.service();
    install_native_provider(&service, &home, Arc::clone(&transport));
    let admitted = service.admit(admit_request()).await.expect("admission");
    service.inject_crash_after_provider_request();

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let events_before = service.run_events(&admitted.run_id);
    let names_before = event_names(&events_before);
    assert_eq!(named_event_count(&events_before, "model.requested"), 1);
    assert_eq!(named_event_count(&events_before, "model.completed"), 0);
    assert!(
        !names_before
            .iter()
            .any(|name| { matches!(*name, "run.completed" | "run.failed" | "run.cancelled") })
    );
    assert!(assistant_messages(&service, &admitted.session_id).is_empty());
    assert!(
        transport.take_sent().is_empty(),
        "request-boundary crash precedes native send"
    );

    // This is pending-request recovery inside the still-open service and DB,
    // not process-restart recovery.
    service.evict_run_handle(&admitted.run_id);
    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let events_after = service.run_events(&admitted.run_id);
    assert_eq!(named_event_count(&events_after, "run.completed"), 1);
    assert_eq!(named_event_count(&events_after, "model.requested"), 1);
    assert_eq!(named_event_count(&events_after, "model.completed"), 1);
    assert_eq!(assistant_messages(&service, &admitted.session_id).len(), 1);
    assert!(
        assistant_messages(&service, &admitted.session_id)[0]
            .to_string()
            .contains(ANSWER)
    );
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "one native send after pending recovery");
    assert_eq!(sent[0].url, EXPECTED_URL);
    let metrics = service.metrics().snapshot();
    assert_eq!(metrics.model_calls, 1);
    assert_eq!(metrics.turns, 1);
    assert_service_surfaces_secret_free(&service, &admitted.run_id, &admitted.session_id, &db_path);

    drop(service);
    drop(state);
    drop(home);
    remove_db_artifacts(&db_path);
}

#[tokio::test(flavor = "multi_thread")]
async fn completed_terminal_run_reopens_on_fresh_service_without_new_native_send() {
    let home_before = fixture_home();
    let transport_before = Arc::new(ScriptedHttpsTransport::new());
    queue_text_response(&transport_before);
    let db_path = fixture_db_path();
    let state_before = open_sqlite_service(&db_path);
    let service_before = state_before.service();
    install_native_provider(&service_before, &home_before, Arc::clone(&transport_before));
    let admitted = service_before
        .admit(admit_request())
        .await
        .expect("initial admission");

    service_before
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let original_events = service_before.run_events(&admitted.run_id);
    let original_messages = service_before.session_messages(&admitted.session_id);
    let original_event_ids = event_ids(&original_events);
    let original_message_ids = message_ids(&original_messages);
    assert!(!original_event_ids.is_empty());
    assert!(!original_message_ids.is_empty());
    assert_eq!(named_event_count(&original_events, "run.completed"), 1);
    assert_eq!(named_event_count(&original_events, "model.requested"), 1);
    assert_eq!(named_event_count(&original_events, "model.completed"), 1);
    assert_eq!(
        assistant_messages(&service_before, &admitted.session_id).len(),
        1
    );
    assert_eq!(transport_before.take_sent().len(), 1);
    assert_service_surfaces_secret_free(
        &service_before,
        &admitted.run_id,
        &admitted.session_id,
        &db_path,
    );

    // Drop every old service/state reference; only the assigned durable DB
    // survives this boundary. The new service gets a fresh factory and transport.
    drop(service_before);
    drop(state_before);
    drop(home_before);
    drop(transport_before);

    let home_after = fixture_home();
    let transport_after = Arc::new(ScriptedHttpsTransport::new());
    let state_after = open_sqlite_service(&db_path);
    let service_after = state_after.service();
    install_native_provider(&service_after, &home_after, Arc::clone(&transport_after));
    let resumed = service_after
        .resume_context(&admitted.run_id)
        .expect("completed run context should reopen from the same SQLite fixture");
    assert_eq!(resumed.provider_options["credential_id"], CREDENTIAL);

    service_after
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let reopened_events = service_after.run_events(&admitted.run_id);
    let reopened_messages = service_after.session_messages(&admitted.session_id);
    assert_eq!(event_ids(&reopened_events), original_event_ids);
    assert_eq!(message_ids(&reopened_messages), original_message_ids);
    assert_eq!(
        reopened_events, original_events,
        "reopen preserves exact event identities and contents"
    );
    assert_eq!(
        message_identity_and_content(&reopened_messages),
        message_identity_and_content(&original_messages),
        "reopen preserves exact durable message identities and contents"
    );
    assert_eq!(
        reopened_messages
            .iter()
            .filter_map(|message| message["ordinal"].as_u64())
            .collect::<Vec<_>>(),
        vec![1, 2],
        "reopened messages retain their durable order"
    );
    assert_eq!(named_event_count(&reopened_events, "run.completed"), 1);
    assert_eq!(named_event_count(&reopened_events, "model.requested"), 1);
    assert_eq!(named_event_count(&reopened_events, "model.completed"), 1);
    assert_eq!(
        assistant_messages(&service_after, &admitted.session_id).len(),
        1
    );
    assert!(transport_after.take_sent().is_empty());
    let metrics = service_after.metrics().snapshot();
    assert_eq!(metrics.model_calls, 0);
    assert_eq!(metrics.turns, 0);
    assert_service_surfaces_secret_free(
        &service_after,
        &admitted.run_id,
        &admitted.session_id,
        &db_path,
    );

    drop(service_after);
    drop(state_after);
    drop(home_after);
    drop(transport_after);
    remove_db_artifacts(&db_path);
}

#[tokio::test(flavor = "multi_thread")]
async fn default_provider_without_native_factory_fails_closed_before_send() {
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let db_path = fixture_db_path();
    let state = open_sqlite_service(&db_path);
    let service = state.service();
    service.upsert_provider_profile(public_profile(CREDENTIAL));
    let admitted = service.admit(admit_request()).await.expect("admission");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let events = service.run_events(&admitted.run_id);
    assert_eq!(named_event_count(&events, "run.failed"), 1);
    assert_eq!(named_event_count(&events, "model.requested"), 1);
    assert_eq!(named_event_count(&events, "model.failed"), 1);
    assert!(transport.take_sent().is_empty());
    assert_service_surfaces_secret_free(&service, &admitted.run_id, &admitted.session_id, &db_path);

    drop(service);
    drop(state);
    remove_db_artifacts(&db_path);
}

#[tokio::test(flavor = "multi_thread")]
async fn default_provider_with_missing_named_reference_fails_closed_before_send() {
    let home = fixture_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let db_path = fixture_db_path();
    let state = open_sqlite_service(&db_path);
    let service = state.service();
    service.set_auth_host_factory(home.auth_factory(Arc::clone(&transport)));
    service.upsert_provider_profile(public_profile("absent-durable-credential"));
    let admitted = service.admit(admit_request()).await.expect("admission");

    service
        .clone()
        .run_worker(admitted.run_id.clone(), "ignored".to_string())
        .await;

    let events = service.run_events(&admitted.run_id);
    assert_eq!(named_event_count(&events, "run.failed"), 1);
    assert_eq!(named_event_count(&events, "model.requested"), 1);
    assert_eq!(named_event_count(&events, "model.failed"), 1);
    assert!(transport.take_sent().is_empty());
    assert_service_surfaces_secret_free(&service, &admitted.run_id, &admitted.session_id, &db_path);

    drop(service);
    drop(state);
    drop(home);
    remove_db_artifacts(&db_path);
}

#[test]
fn credential_id_profile_option_is_bounded_literal_and_keeps_secret_denylist() {
    use rustscript_agent::config::ProviderProfileError;

    let profile = ProviderProfile::new(PROVIDER, json!({"credential_id": CREDENTIAL}))
        .expect("public named credential reference should be admitted");
    assert_eq!(profile.options()["credential_id"], CREDENTIAL);

    let maximum = "c".repeat(4096);
    let bounded = ProviderProfile::new(PROVIDER, json!({"credential_id": maximum.clone()}))
        .expect("maximum byte-bounded credential reference should be accepted literally");
    assert_eq!(bounded.options()["credential_id"], maximum);
    assert!(matches!(
        ProviderProfile::new(PROVIDER, json!({"credential_id": "c".repeat(4097)})),
        Err(ProviderProfileError::OptionStringTooLong)
    ));
    for invalid in ["", " ", "credential\nid"] {
        assert!(matches!(
            ProviderProfile::new(PROVIDER, json!({"credential_id": invalid})),
            Err(ProviderProfileError::InvalidOptionValue(key)) if key == "credential_id"
        ));
    }
    assert!(matches!(
        ProviderProfile::new(PROVIDER, json!({"api_key": "fixture-only"})),
        Err(ProviderProfileError::CredentialBearingOption(key)) if key == "api_key"
    ));
}

#[test]
fn explicit_empty_top_level_credential_id_blocks_provider_option_fallback() {
    let home = fixture_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = actual_default_runner(&home, Arc::clone(&transport));
    let context = json!({
        "credential_id": "",
        "provider": PROVIDER,
        "model": "durable-request-model",
        "input": {"message": USER_TEXT},
        "config": {"max_retries": 2},
        "limits": {"max_turns": 8, "max_tool_calls": 32},
        "provider_options": {
            "profile": PROVIDER,
            "protocol": "openai-chat-completions",
            "base_url": BASE_URL,
            "credential_id": CREDENTIAL
        }
    });

    let decision = provider_opaque_fixture::vm_value_to_json(
        &runner
            .run_with_context(provider_opaque_fixture::json_to_vm_value(&context))
            .expect("missing top-level credential returns a canonical failed decision"),
    );
    assert_eq!(decision["kind"], "run.failed");
    assert_eq!(decision["error"]["code"], "missing_credential");
    assert!(transport.take_sent().is_empty());
    drop(home);
}
