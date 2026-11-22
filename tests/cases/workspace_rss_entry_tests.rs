use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rustscript_agent::{AgentConfig, AgentRunner};
use rustscript_vm::Value;
use serde_json::{Map as JsonMap, Value as JsonValue, json};

fn private_test_root() -> PathBuf {
    let base = PathBuf::from(
        std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMPDIR")
            .expect("RUSTSCRIPT_AGENT_TEST_TMPDIR must point into assigned TEMP"),
    );
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after Unix epoch")
        .as_nanos();
    base.join(format!(
        "workspace-rss-admission-{}-{nonce}",
        std::process::id()
    ))
}

fn storage_runner(root: &Path) -> AgentRunner {
    let storage = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/storage/main.rss");
    AgentRunner::from_file(storage, AgentConfig::default().with_sqlite_root(root))
        .expect("production RSS storage entrypoint compiles")
}

fn storage_command(
    runner: &AgentRunner,
    db_name: &str,
    request_id: &str,
    op: &str,
    payload: JsonValue,
) -> JsonValue {
    storage_command_result(runner, db_name, request_id, op, payload)
        .unwrap_or_else(|error| panic!("{error}"))
}

fn storage_command_result(
    runner: &AgentRunner,
    db_name: &str,
    request_id: &str,
    op: &str,
    payload: JsonValue,
) -> Result<JsonValue, String> {
    let command = Value::map(vec![
        (Value::string("op"), Value::string(op)),
        (Value::string("request_id"), Value::string(request_id)),
        (Value::string("db_path"), Value::string(db_name)),
        (Value::string("db_mode"), Value::string("read_write_create")),
        (Value::string("busy_timeout_ms"), Value::Int(1_000)),
        (Value::string("max_rows"), Value::Int(128)),
        (Value::string("max_bytes"), Value::Int(65_536)),
        (Value::string("max_events"), Value::Int(128)),
        (Value::string("max_messages"), Value::Int(128)),
        (Value::string("now_ms"), Value::Int(1)),
        (
            Value::string("payload_json"),
            Value::string(payload.to_string()),
        ),
    ]);
    let result = runner
        .run_with_context(command)
        .map_err(|error| format!("RSS storage operation {op} failed: {error:?}"))?;
    let Value::Map(result) = result else {
        return Err(format!(
            "RSS storage operation {op} returned a non-map result"
        ));
    };
    Ok(value_to_json(&Value::Map(result)))
}

fn value_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Int(value) => json!(value),
        Value::Float(value) => serde_json::Number::from_f64(*value)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Value::Bool(value) => json!(value),
        Value::String(value) => JsonValue::String(value.to_string()),
        Value::Bytes(value) => JsonValue::String(String::from_utf8_lossy(value).into_owned()),
        Value::Array(values) => JsonValue::Array(
            values
                .iter()
                .map(|value| {
                    let encoded = value_to_json(value);
                    rustscript_agent::sqlite_storage_rows::sqlite_storage_row(&encoded)
                        .map(JsonValue::Array)
                        .unwrap_or(encoded)
                })
                .collect(),
        ),
        Value::Map(entries) => {
            let object: JsonMap<String, JsonValue> = entries
                .iter()
                .map(|(key, value)| {
                    let key = match key {
                        Value::String(key) => key.to_string(),
                        other => value_to_json(other).to_string(),
                    };
                    (key, value_to_json(value))
                })
                .collect();
            let encoded = JsonValue::Object(object);
            rustscript_agent::sqlite_storage_rows::sqlite_storage_cell(&encoded).unwrap_or(encoded)
        }
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn load_snapshot(runner: &AgentRunner, db_name: &str, request_id: &str) -> JsonValue {
    let result = storage_command(
        runner,
        db_name,
        request_id,
        "load.all",
        json!({"load_cap": 4096}),
    );
    assert_eq!(result["ok"], true, "RSS storage load failed: {result}");
    result["data"].clone()
}

fn table_counts(snapshot: &JsonValue) -> JsonValue {
    json!({
        "sessions": snapshot["sessions"].as_array().map_or(0, Vec::len),
        "messages": snapshot["messages"].as_array().map_or(0, Vec::len),
        "runs": snapshot["runs"].as_array().map_or(0, Vec::len),
        "events": snapshot["events"].as_array().map_or(0, Vec::len),
        "idempotency": snapshot["idempotency"].as_array().map_or(0, Vec::len),
    })
}

struct FrozenWorkspaceIdentity<'a> {
    selector: &'a str,
    canonical_path: &'a str,
    selected_name: &'a str,
}

fn workspace_admission_payload(
    session_id: &str,
    run_id: &str,
    message_id: &str,
    idempotency_key: &str,
    request_hash: &str,
    request_selector: Option<&str>,
    workspace: FrozenWorkspaceIdentity<'_>,
) -> JsonValue {
    let FrozenWorkspaceIdentity {
        selector: frozen_selector,
        canonical_path,
        selected_name,
    } = workspace;
    let workspace = json!({
        "selector": frozen_selector,
        "canonical_path": canonical_path,
        "selected_name": selected_name,
        "generation": 1
    });
    let identity = json!({
        "request_selector_present": request_selector.is_some(),
        "request_selector": request_selector.unwrap_or_default(),
        "selector": frozen_selector,
        "canonical_path": canonical_path,
        "selected_name": selected_name,
        "generation": 1
    });
    json!({
        "session_id": session_id,
        "session_new": 1,
        "profile": "default",
        "platform": "test",
        "account_id": session_id,
        "model": "test-model",
        "provider": "test-provider",
        "system_prompt": "",
        "session_metadata_json": json!({"workspace": workspace}).to_string(),
        "run_id": run_id,
        "parent_run_id": "",
        "input_json": "{\"run_context\":{\"input\":\"workspace admission\"}}",
        "message_id": message_id,
        "message_run_id": run_id,
        "script_hash": "test-script",
        "idempotency_scope": "api:chat",
        "idempotency_key": idempotency_key,
        "request_hash": request_hash,
        "workspace_identity_json": identity.to_string(),
        "event_id": format!("{run_id}-event"),
        "now_ms": 10,
        "expires_at_ms": 0
    })
}

fn assert_admission_tables_unchanged(before: &JsonValue, after: &JsonValue) {
    assert_eq!(table_counts(after), table_counts(before));
    for table in ["sessions", "messages", "runs", "events", "idempotency"] {
        assert_eq!(after[table], before[table], "unexpected {table} mutation");
    }
}

#[test]
fn workspace_selector_mismatch_rolls_back_every_rss_admission_write() {
    let root = private_test_root();
    fs::create_dir_all(&root).expect("create private RSS fixture root");
    let runner = storage_runner(&root);
    let database = "workspace-admission.sqlite3";

    let migration = storage_command(&runner, database, "migrate", "migrate", json!({}));
    assert_eq!(
        migration["ok"], true,
        "RSS storage migration failed: {migration}"
    );

    let session = storage_command(
        &runner,
        database,
        "create-session",
        "session.create",
        json!({
            "id": "session-1",
            "profile": "default",
            "platform": "test",
            "account_id": "account-1",
            "chat_id": "chat-1",
            "thread_id": "",
            "user_id": "user-1",
            "generation": 1,
            "status": "active",
            "system_prompt": "",
            "model": "test-model",
            "provider": "test-provider",
            "toolset_hash": "test-tools",
            "metadata_json": "{\"workspace\":{\"selector\":\"name:project\",\"canonical_path\":\"/private/project\",\"selected_name\":\"project\",\"generation\":1}}",
            "title": "",
            "end_reason": "",
            "now_ms": 1
        }),
    );
    assert_eq!(
        session["ok"], true,
        "RSS session creation failed: {session}"
    );

    let parent = storage_command(
        &runner,
        database,
        "create-parent-run",
        "run.create",
        json!({
            "id": "parent-run",
            "session_id": "session-1",
            "parent_run_id": "",
            "input_json": "{}",
            "provider": "test-provider",
            "model": "test-model",
            "script_hash": "test-script",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "now_ms": 2
        }),
    );
    assert_eq!(
        parent["ok"], true,
        "RSS parent run creation failed: {parent}"
    );

    let before = load_snapshot(&runner, database, "before-load");
    let links_before = storage_command(
        &runner,
        database,
        "children-before",
        "run.list_children",
        json!({"run_id": "parent-run"}),
    );

    let rejected = storage_command_result(
        &runner,
        database,
        "mismatched-admission",
        "admission.create",
        json!({
            "session_id": "session-1",
            "session_new": 0,
            "profile": "default",
            "platform": "test",
            "account_id": "account-1",
            "model": "test-model",
            "provider": "test-provider",
            "system_prompt": "",
            "session_metadata_json": "{\"workspace\":{\"selector\":\"name:alias\",\"canonical_path\":\"/private/project\",\"selected_name\":\"alias\",\"generation\":1}}",
            "run_id": "orphan-run",
            "parent_run_id": "parent-run",
            "input_json": "{\"run_context\":{\"input\":\"test\"}}",
            "message_id": "orphan-message",
            "message_run_id": "orphan-run",
            "script_hash": "test-script",
            "idempotency_scope": "api:chat",
            "idempotency_key": "orphan-key",
            "request_hash": "fnv64:0123456789abcdef",
            "workspace_identity_json": "",
            "event_id": "orphan-event",
            "now_ms": 3,
            "expires_at_ms": 0
        }),
    );
    let after = load_snapshot(&runner, database, "after-load");
    let links_after = storage_command(
        &runner,
        database,
        "children-after",
        "run.list_children",
        json!({"run_id": "parent-run"}),
    );
    assert_eq!(table_counts(&after), table_counts(&before));
    assert_eq!(after["sessions"], before["sessions"]);
    assert_eq!(after["messages"], before["messages"]);
    assert_eq!(after["runs"], before["runs"]);
    assert_eq!(after["events"], before["events"]);
    assert_eq!(after["idempotency"], before["idempotency"]);
    assert_eq!(links_after["data"], links_before["data"]);

    let rejected = rejected.unwrap_or_else(|error| panic!("selector mismatch failed: {error}"));
    assert_eq!(
        rejected["ok"], false,
        "selector mismatch must reject: {rejected}"
    );
    assert_eq!(rejected["code"], "workspace_conflict");

    fs::remove_dir_all(root).expect("remove private RSS fixture root");
}

#[test]
fn durable_workspace_replay_uses_original_selector_not_frozen_session_binding() {
    let root = private_test_root();
    fs::create_dir_all(&root).expect("create private durable replay fixture root");
    let runner = storage_runner(&root);
    let database = "workspace-replay.sqlite3";

    let migration = storage_command(&runner, database, "migrate", "migrate", json!({}));
    assert_eq!(
        migration["ok"], true,
        "RSS storage migration failed: {migration}"
    );

    let original = workspace_admission_payload(
        "explicit-session",
        "explicit-run",
        "explicit-message",
        "explicit-key",
        "fnv64:0123456789abcdef",
        Some("name:project"),
        FrozenWorkspaceIdentity {
            selector: "name:project",
            canonical_path: "/private/project",
            selected_name: "project",
        },
    );
    let admitted = storage_command(
        &runner,
        database,
        "admit-explicit",
        "admission.create",
        original.clone(),
    );
    assert_eq!(
        admitted["ok"], true,
        "initial RSS admission failed: {admitted}"
    );
    let before_alias = load_snapshot(&runner, database, "before-alias");

    let mut alias_retry = workspace_admission_payload(
        "explicit-session",
        "alias-run",
        "alias-message",
        "explicit-key",
        "fnv64:0123456789abcdef",
        Some("name:alias"),
        FrozenWorkspaceIdentity {
            selector: "name:project",
            canonical_path: "/private/project",
            selected_name: "project",
        },
    );
    alias_retry["session_new"] = json!(0);
    alias_retry["session_metadata_json"] = original["session_metadata_json"].clone();
    let alias_result = storage_command_result(
        &runner,
        database,
        "retry-alias",
        "admission.create",
        alias_retry,
    );
    let after_alias = load_snapshot(&runner, database, "after-alias");
    assert_admission_tables_unchanged(&before_alias, &after_alias);
    let alias_result = alias_result.unwrap_or_else(|error| panic!("alias replay failed: {error}"));
    assert_eq!(
        alias_result["ok"], false,
        "changed selector must conflict: {alias_result}"
    );
    assert_eq!(alias_result["code"], "idempotency_key_conflict");

    let default_original = workspace_admission_payload(
        "default-session",
        "default-run",
        "default-message",
        "default-key",
        "fnv64:0000000000000010",
        None,
        FrozenWorkspaceIdentity {
            selector: "name:project",
            canonical_path: "/private/project",
            selected_name: "project",
        },
    );
    let default_admitted = storage_command(
        &runner,
        database,
        "admit-default",
        "admission.create",
        default_original.clone(),
    );
    assert_eq!(
        default_admitted["ok"], true,
        "initial default-workspace admission failed: {default_admitted}"
    );
    let before_default_replay = load_snapshot(&runner, database, "before-default-replay");

    let mut default_retry = workspace_admission_payload(
        "default-session",
        "replacement-run",
        "replacement-message",
        "default-key",
        "fnv64:0000000000000010",
        None,
        FrozenWorkspaceIdentity {
            selector: "name:replacement",
            canonical_path: "/private/replacement",
            selected_name: "replacement",
        },
    );
    default_retry["session_new"] = json!(0);
    default_retry["session_metadata_json"] = default_original["session_metadata_json"].clone();
    let default_result = storage_command_result(
        &runner,
        database,
        "retry-default",
        "admission.create",
        default_retry,
    );
    let after_default_replay = load_snapshot(&runner, database, "after-default-replay");
    assert_admission_tables_unchanged(&before_default_replay, &after_default_replay);
    let default_result =
        default_result.unwrap_or_else(|error| panic!("default replay failed: {error}"));
    assert_eq!(
        default_result["ok"], true,
        "matching default replay failed: {default_result}"
    );
    assert_eq!(default_result["data"]["replayed"], true);
    assert_eq!(default_result["data"]["run"]["rows"][0][0], "default-run");

    fs::remove_dir_all(root).expect("remove private durable replay fixture root");
}
