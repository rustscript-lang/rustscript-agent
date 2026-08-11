use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rustscript_agent::{AgentConfig, AgentRunner};
use rustscript_vm::Value;
use serde_json::{Map as JsonMap, Value as JsonValue, json};

const STORAGE_FILES: &[&str] = &[
    "main.rss",
    "schema.rss",
    "sessions.rss",
    "messages.rss",
    "runs.rss",
    "events.rss",
    "approvals.rss",
    "compactions.rss",
    "gateway.rss",
];

fn storage_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/storage")
}

fn temporary_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the Unix epoch")
        .as_nanos();
    let root = PathBuf::from("/mnt/TEMP/rustscript/storage-tests")
        .join(format!("{label}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root).expect("temporary storage root should be created");
    root
}

fn storage_command(
    db_name: &str,
    request_id: &str,
    op: &str,
    payload: JsonValue,
    now_ms: i64,
) -> Value {
    Value::map(vec![
        (Value::string("op"), Value::string(op)),
        (Value::string("request_id"), Value::string(request_id)),
        (Value::string("db_path"), Value::string(db_name)),
        (Value::string("db_mode"), Value::string("read_write_create")),
        (Value::string("busy_timeout_ms"), Value::Int(1_000)),
        (Value::string("max_rows"), Value::Int(128)),
        (Value::string("max_bytes"), Value::Int(65_536)),
        (Value::string("max_events"), Value::Int(128)),
        (Value::string("max_messages"), Value::Int(128)),
        (Value::string("now_ms"), Value::Int(now_ms)),
        (
            Value::string("payload_json"),
            Value::string(payload.to_string()),
        ),
    ])
}

fn storage_runner(root: &std::path::Path) -> AgentRunner {
    AgentRunner::from_file(
        storage_root().join("main.rss"),
        AgentConfig::default().with_sqlite_root(root),
    )
    .expect("production storage entrypoint should compile")
}

fn run_storage(
    runner: &AgentRunner,
    db_name: &str,
    request_id: &str,
    op: &str,
    payload: JsonValue,
    now_ms: i64,
) -> JsonValue {
    let result = runner
        .run_with_context(storage_command(db_name, request_id, op, payload, now_ms))
        .unwrap_or_else(|error| panic!("storage op {op} failed: {error:?}"));
    let Value::Map(result) = result else {
        panic!("storage entrypoint should return a result map");
    };
    vm_value_to_json(&Value::Map(result))
}

/// Converts one VM value into JSON (test-side mirror of the gateway renderer).
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
                .map(|(key, value)| (vm_map_key_to_string(key), vm_value_to_json(value)))
                .collect(),
        ),
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn vm_map_key_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.to_string(),
        other => vm_value_to_json(other).to_string(),
    }
}

fn result_data(result: &JsonValue) -> JsonValue {
    result.get("data").cloned().unwrap_or(JsonValue::Null)
}

fn first_query_row(result: &JsonValue) -> JsonMap<String, JsonValue> {
    let data = result_data(result);
    let columns = data
        .get("columns")
        .and_then(JsonValue::as_array)
        .expect("SQLite query data should contain columns");
    let row = data
        .get("rows")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(JsonValue::as_array)
        .expect("SQLite query data should contain one row");
    columns
        .iter()
        .zip(row.iter())
        .map(|(column, value)| {
            (
                column
                    .as_str()
                    .expect("SQLite column names should be strings")
                    .to_string(),
                value.clone(),
            )
        })
        .collect()
}

fn query_rows(result: &JsonValue) -> Vec<JsonMap<String, JsonValue>> {
    let data = result_data(result);
    let columns = data
        .get("columns")
        .and_then(JsonValue::as_array)
        .expect("SQLite query data should contain columns");
    data.get("rows")
        .and_then(JsonValue::as_array)
        .expect("SQLite query data should contain rows")
        .iter()
        .map(|row| {
            columns
                .iter()
                .zip(row.as_array().expect("SQLite row should be an array"))
                .map(|(column, value)| {
                    (
                        column
                            .as_str()
                            .expect("SQLite column names should be strings")
                            .to_string(),
                        value.clone(),
                    )
                })
                .collect()
        })
        .collect()
}

fn session_payload(session_id: &str, now_ms: i64) -> JsonValue {
    json!({
        "id": session_id,
        "profile": "default",
        "platform": "test",
        "account_id": "account-1",
        "chat_id": "chat-1",
        "thread_id": "",
        "user_id": "user-1",
        "generation": 1,
        "system_prompt": "",
        "model": "test-model",
        "provider": "test-provider",
        "toolset_hash": "test-tools",
        "metadata_json": "{}",
        "now_ms": now_ms,
    })
}

fn run_payload(run_id: &str, session_id: &str, now_ms: i64) -> JsonValue {
    json!({
        "id": run_id,
        "session_id": session_id,
        "parent_run_id": "",
        "input_json": "{\"message\":\"hello\"}",
        "provider": "test-provider",
        "model": "test-model",
        "script_hash": "test-script",
        "idempotency_scope": "api:chat",
        "idempotency_key": run_id,
        "now_ms": now_ms,
    })
}

fn transition_payload(run_id: &str, from_status: &str, to_status: &str, now_ms: i64) -> JsonValue {
    json!({
        "run_id": run_id,
        "from_status": from_status,
        "to_status": to_status,
        "error_code": "",
        "error_message": "",
        "recovery_reason": "",
        "now_ms": now_ms,
    })
}

#[test]
fn native_agent_sources_do_not_define_private_host_functions() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for relative in [
        "src/lib.rs",
        "src/gateway.rs",
        "src/gateway_store.rs",
        "src/bin/rustscript-agent.rs",
        "src/bin/rustscript-agent-gateway.rs",
    ] {
        let path = root.join(relative);
        let source = fs::read_to_string(&path).expect("agent source should be readable");
        assert!(
            !source.contains("#[pd_host_function]"),
            "{} must not define private host functions",
            path.display()
        );
    }
}

#[test]
fn storage_rss_contract_files_are_present_and_use_generic_capabilities() {
    let root = storage_root();
    for file in STORAGE_FILES {
        let path = root.join(file);
        assert!(
            path.is_file(),
            "missing RSS storage module {}",
            path.display()
        );
        let source = fs::read_to_string(&path).expect("storage module should be readable");
        assert!(
            source.contains("sqlite::") || *file == "schema.rss",
            "{} must use the generic sqlite capability or be schema-only",
            path.display()
        );
        assert!(
            !source.contains("agent::")
                && !source.contains("telegram::")
                && !source.contains("provider::")
                && !source.contains("#[pd_host_function]")
                && !source.contains("rusqlite"),
            "{} must not define agent-private host or SQL implementations",
            path.display()
        );
    }

    let main = fs::read_to_string(root.join("main.rss")).expect("main storage module");
    for contract in [
        "sqlite::open",
        "sqlite::query",
        "sqlite::execute",
        "sqlite::transaction",
        "sqlite::close",
        "pub fn run(command: StorageCommand)",
        "json::decode",
    ] {
        assert!(main.contains(contract), "main.rss missing {contract}");
    }
    assert!(
        main.contains("busy_timeout_ms: busy_timeout_ms")
            && main.contains("max_result_bytes: max_bytes"),
        "SQLite open limits must include the busy timeout and result-byte limit"
    );

    let schema = fs::read_to_string(root.join("schema.rss")).expect("schema storage module");
    for table in [
        "schema_migrations",
        "sessions",
        "messages",
        "runs",
        "run_events",
        "approvals",
        "compactions",
        "provider_usage",
        "child_run_links",
        "delivery_cursors",
        "idempotency_records",
        "recovery_records",
    ] {
        assert!(schema.contains(table), "schema.rss missing table {table}");
    }
}

/// Blocked by a core compiler limitation (BLOCKED_VM_LIMITATION): the full
/// storage module set (main.rss + schema/sessions/messages/runs/events/
/// approvals/compactions) exceeds the core's program-wide local-slot encoding
/// ("local slot 65535 exceeds the supported bytecode encoding" from
/// `src/compiler/lifetime/liveness.rs` slot coloring + codegen u8 local
/// operands). Splitting the dispatcher does not help; the limit is
/// program-wide. Requires a core change: widen the local-slot operand encoding
/// or make the slot allocator/remap handle programs with more than ~256
/// program-wide locals. The tests below stay as the executable reproducer.
#[ignore = "core compiler local-slot limit for the full storage program; see test module docs"]
#[test]
fn production_storage_commands_return_sqlite_results_and_preserve_idempotency() {
    let root = temporary_root("commands");
    let runner = storage_runner(&root);
    let db_name = "commands.db";

    let migration = run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    assert_eq!(migration["ok"], json!(true));
    assert_eq!(result_data(&migration)["schema_version"], json!(2));

    let session_create = run_storage(
        &runner,
        db_name,
        "session-create-1",
        "session.create",
        session_payload("session-1", 2),
        2,
    );
    assert_eq!(session_create["ok"], json!(true));
    let session_row = first_query_row(&session_create);
    assert_eq!(session_row["id"], json!("session-1"));
    assert!(result_data(&session_create).get("rows").is_some());

    let idempotency_begin = run_storage(
        &runner,
        db_name,
        "idempotency-begin-1",
        "idempotency.begin",
        json!({
            "scope": "api:chat",
            "key": "request-1",
            "request_hash": "hash-1",
            "resource_type": "run",
            "resource_id": "run-1",
            "claim_token": "claim-1",
            "now_ms": 3,
            "expires_at_ms": 1000,
        }),
        3,
    );
    assert_eq!(
        first_query_row(&idempotency_begin)["state"],
        json!("claimed")
    );
    assert_eq!(first_query_row(&idempotency_begin)["acquired"], json!(1));
    assert_eq!(
        first_query_row(&idempotency_begin)["claim_token"],
        json!("claim-1")
    );

    let idempotency_complete = run_storage(
        &runner,
        db_name,
        "idempotency-complete-1",
        "idempotency.complete",
        json!({
            "scope": "api:chat",
            "key": "request-1",
            "request_hash": "hash-1",
            "claim_token": "claim-1",
            "state": "completed",
            "response_json": "{\"run_id\":\"run-1\"}",
            "now_ms": 4,
        }),
        4,
    );
    assert_eq!(
        result_data(&idempotency_complete)["rows_affected"],
        json!(1)
    );

    let idempotency_replay = run_storage(
        &runner,
        db_name,
        "idempotency-begin-2",
        "idempotency.begin",
        json!({
            "scope": "api:chat",
            "key": "request-1",
            "request_hash": "hash-1",
            "resource_type": "run",
            "resource_id": "run-1",
            "claim_token": "claim-2",
            "now_ms": 5,
            "expires_at_ms": 1000,
        }),
        5,
    );
    assert_eq!(
        first_query_row(&idempotency_replay)["state"],
        json!("completed")
    );
    assert_eq!(first_query_row(&idempotency_replay)["acquired"], json!(0));
    assert_eq!(
        first_query_row(&idempotency_replay)["claim_token"],
        json!("")
    );

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// Blocked by the same core compiler local-slot limit as
/// `production_storage_commands_return_sqlite_results_and_preserve_idempotency`;
/// kept as part of the executable reproducer (see the docs on that test).
#[ignore = "core compiler local-slot limit for the full storage program; see test module docs"]
#[test]
fn restart_recovery_marks_active_runs_and_replays_terminal_events() {
    let root = temporary_root("recovery");
    let runner = storage_runner(&root);
    let db_name = "recovery.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    run_storage(
        &runner,
        db_name,
        "session-create-1",
        "session.create",
        session_payload("session-1", 2),
        2,
    );

    run_storage(
        &runner,
        db_name,
        "run-create-1",
        "run.create",
        run_payload("run-1", "session-1", 3),
        3,
    );
    run_storage(
        &runner,
        db_name,
        "run-transition-1",
        "run.transition",
        transition_payload("run-1", "queued", "running", 4),
        4,
    );
    let event_append = run_storage(
        &runner,
        db_name,
        "event-append-1",
        "event.append",
        json!({
            "run_id": "run-1",
            "event_id": "event-started-1",
            "event_type": "run.started",
            "payload_json": "{\"status\":\"running\"}",
            "now_ms": 5,
            "max_events": 128,
        }),
        5,
    );
    assert!(result_data(&event_append).is_array());

    let recovery = run_storage(
        &runner,
        db_name,
        "recovery-1",
        "recovery.recover_active",
        json!({
            "reason": "gateway_restart",
            "details_json": "{\"source\":\"restart-test\"}",
            "now_ms": 6,
            "max_rows": 128,
            "max_bytes": 65_536,
            "max_events": 128,
        }),
        6,
    );
    assert_eq!(recovery["ok"], json!(true));
    assert!(result_data(&recovery).is_array());

    let run = run_storage(
        &runner,
        db_name,
        "run-get-1",
        "run.get",
        json!({"run_id": "run-1"}),
        7,
    );
    let run_row = first_query_row(&run);
    assert_eq!(run_row["status"], json!("failed"));
    assert_eq!(run_row["error_code"], json!("gateway_restart"));
    assert_eq!(run_row["recovery_reason"], json!("gateway_restart"));
    assert_eq!(run_row["finished_at_ms"], json!(6));

    let replay = run_storage(
        &runner,
        db_name,
        "replay-1",
        "event.replay",
        json!({
            "run_id": "run-1",
            "after_seq": 0,
            "max_events": 128,
            "max_bytes": 65_536,
        }),
        8,
    );
    let replay_rows = query_rows(&replay);
    assert_eq!(replay_rows.len(), 3);
    assert_eq!(replay_rows[0]["event_type"], json!("run.status_changed"));
    assert_eq!(replay_rows[0]["seq"], json!(1));
    assert_eq!(replay_rows[1]["event_type"], json!("run.started"));
    assert_eq!(replay_rows[1]["seq"], json!(2));
    assert_eq!(replay_rows[2]["event_type"], json!("run.failed"));
    assert_eq!(replay_rows[2]["seq"], json!(3));
    let terminal_payload: JsonValue = serde_json::from_str(
        replay_rows[2]["payload_json"]
            .as_str()
            .expect("terminal event payload should be JSON text"),
    )
    .expect("terminal event payload should be valid JSON");
    assert_eq!(terminal_payload["status"], json!("failed"));
    assert_eq!(terminal_payload["error_code"], json!("gateway_restart"));
    assert_eq!(
        terminal_payload["recovery_reason"],
        json!("gateway_restart")
    );

    let second_recovery = run_storage(
        &runner,
        db_name,
        "recovery-2",
        "recovery.recover_active",
        json!({
            "reason": "gateway_restart",
            "details_json": "{\"source\":\"second-restart\"}",
            "now_ms": 9,
            "max_rows": 128,
            "max_bytes": 65_536,
            "max_events": 128,
        }),
        9,
    );
    assert_eq!(second_recovery["ok"], json!(true));

    let replay_after_retry = run_storage(
        &runner,
        db_name,
        "replay-2",
        "event.replay",
        json!({
            "run_id": "run-1",
            "after_seq": 0,
            "max_events": 128,
            "max_bytes": 65_536,
        }),
        10,
    );
    assert_eq!(query_rows(&replay_after_retry).len(), 3);

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

#[test]
fn agent_runner_compiles_nested_rss_namespace_imports() {
    let root = temporary_root("nested-module");
    fs::write(
        root.join("sibling.rss"),
        r#"
        pub fn value() -> int { 17 }
    "#,
    )
    .expect("sibling source should be written");
    fs::write(
        root.join("nested.rss"),
        r#"
        use self::sibling as sibling;
        pub fn entry() -> int { sibling::value() }
    "#,
    )
    .expect("nested source should be written");
    let main_path = root.join("main.rss");
    fs::write(
        &main_path,
        r#"
        use self::nested as nested;
        pub fn run(input: map) -> int { nested::entry() }
    "#,
    )
    .expect("main source should be written");

    let runner = AgentRunner::from_file(&main_path, AgentConfig::default().with_sqlite_root(&root))
        .expect("agent runner should compile nested RSS modules");
    assert_eq!(
        runner
            .run_with_context(Value::map(vec![]))
            .expect("nested RSS program should run"),
        Value::Int(17)
    );

    fs::remove_dir_all(root).expect("temporary nested module root should be removed");
}
