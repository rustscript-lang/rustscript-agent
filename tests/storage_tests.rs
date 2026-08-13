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
    storage_command_with_limits(db_name, request_id, op, payload, now_ms, 128)
}

/// Same command envelope with an explicit `max_messages` page bound.
fn storage_command_with_limits(
    db_name: &str,
    request_id: &str,
    op: &str,
    payload: JsonValue,
    now_ms: i64,
    max_messages: i64,
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
        (Value::string("max_messages"), Value::Int(max_messages)),
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

/// Runs one storage command and returns the raw result (error assertions use
/// this instead of the panicking `run_storage` helper).
fn run_storage_result(
    runner: &AgentRunner,
    db_name: &str,
    request_id: &str,
    op: &str,
    payload: JsonValue,
    now_ms: i64,
) -> Result<JsonValue, rustscript_agent::RunError> {
    let result =
        runner.run_with_context(storage_command(db_name, request_id, op, payload, now_ms))?;
    let Value::Map(result) = result else {
        return Err(rustscript_agent::RunError::NoEntry);
    };
    Ok(vm_value_to_json(&Value::Map(result)))
}

/// Same as [`raw_sql_runner`] but ends with one query whose result map is
/// returned as the program result.
fn query_sql_runner(
    root: &std::path::Path,
    label: &str,
    statements: &[&str],
    final_sql: &str,
) -> AgentRunner {
    let body = statements
        .iter()
        .map(|sql| format!("    sqlite::execute(db, \"{sql}\", []);"))
        .collect::<Vec<_>>()
        .join("\n");
    let source = format!(
        r#"
use sqlite;
pub fn run(input: map) -> map {{
    let db: int = sqlite::open({{
        path: input["db_name"],
        mode: "read_write_create",
        limits: {{
            busy_timeout_ms: 1000,
            max_connections: 1,
            max_rows: 64,
            max_result_bytes: 65536,
            max_statements: 64,
            max_transaction_ms: 5000
        }}
    }});
{body}
    let result: map = sqlite::query(db, "{final_sql}", [], {{ max_rows: 64, max_result_bytes: 65536 }});
    sqlite::close(db);
    result
}}
"#
    );
    let path = root.join(format!("{label}.rss"));
    fs::write(&path, source).expect("query SQL program should be written");
    AgentRunner::from_file(&path, AgentConfig::default().with_sqlite_root(root))
        .expect("query SQL program should compile")
}

/// Runs one storage command with an explicit `max_messages` page bound.
fn run_storage_page(
    runner: &AgentRunner,
    db_name: &str,
    request_id: &str,
    op: &str,
    payload: JsonValue,
    now_ms: i64,
    max_messages: i64,
) -> JsonValue {
    let result = runner
        .run_with_context(storage_command_with_limits(
            db_name,
            request_id,
            op,
            payload,
            now_ms,
            max_messages,
        ))
        .unwrap_or_else(|error| panic!("storage op {op} failed: {error:?}"));
    let Value::Map(result) = result else {
        panic!("storage entrypoint should return a result map");
    };
    vm_value_to_json(&Value::Map(result))
}

fn message_payload(message_id: &str, session_id: &str, _ordinal: i64, now_ms: i64) -> JsonValue {
    json!({
        "id": message_id,
        "session_id": session_id,
        "role": "user",
        "content_json": "{\"text\":\"hello\"}",
        "name": "",
        "tool_call_id": "",
        "parent_message_id": "",
        "token_estimate": 1,
        "metadata_json": "{}",
        "now_ms": now_ms,
    })
}

fn event_payload(
    run_id: &str,
    event_id: &str,
    event_type: &str,
    now_ms: i64,
    max_events: i64,
) -> JsonValue {
    json!({
        "run_id": run_id,
        "event_id": event_id,
        "event_type": event_type,
        "payload_json": format!("{{\"type\":\"{event_type}\"}}"),
        "now_ms": now_ms,
        "max_events": max_events,
    })
}

/// Writes a tiny RSS program that opens `db_name` under `root` and executes
/// the given SQL statements, then returns an [`AgentRunner`] for it. Used to
/// craft pre-existing databases (released schema versions, poisoned tables).
fn raw_sql_runner(root: &std::path::Path, label: &str, statements: &[&str]) -> AgentRunner {
    let body = statements
        .iter()
        .map(|sql| format!("    sqlite::execute(db, \"{sql}\", []);"))
        .collect::<Vec<_>>()
        .join("\n");
    let source = format!(
        r#"
use sqlite;
pub fn run(input: map) -> bool {{
    let db: int = sqlite::open({{
        path: input["db_name"],
        mode: "read_write_create",
        limits: {{
            busy_timeout_ms: 1000,
            max_connections: 1,
            max_rows: 64,
            max_result_bytes: 65536,
            max_statements: 64,
            max_transaction_ms: 5000
        }}
    }});
{body}
    sqlite::close(db);
    true
}}
"#
    );
    let path = root.join(format!("{label}.rss"));
    fs::write(&path, source).expect("raw SQL program should be written");
    AgentRunner::from_file(&path, AgentConfig::default().with_sqlite_root(root))
        .expect("raw SQL program should compile")
}

fn run_raw_sql(runner: &AgentRunner, db_name: &str) {
    runner
        .run_with_context(Value::map(vec![(
            Value::string("db_name"),
            Value::string(db_name),
        )]))
        .expect("raw SQL statements should execute");
}

/// Builds a real released-v1 database: it copies the production schema
/// module next to a small program that executes migration 1's statements and
/// records version 1, exactly as a v1 release would have.
fn released_v1_runner(root: &std::path::Path) -> AgentRunner {
    fs::copy(storage_root().join("schema.rss"), root.join("schema.rss"))
        .expect("production schema module should be copied");
    let source = r#"
use sqlite;
use self::schema as schema;
pub fn run(input: map) -> bool {
    let db: int = sqlite::open({
        path: input["db_name"],
        mode: "read_write_create",
        limits: {
            busy_timeout_ms: 1000,
            max_connections: 1,
            max_rows: 64,
            max_result_bytes: 65536,
            max_statements: 64,
            max_transaction_ms: 5000
        }
    });
    sqlite::execute(db, schema::schema_migrations_table_sql(), []);
    let mut statements = [];
    let mut statement_index = 0;
    while statement_index < 11 {
        statements[statements.length] = { sql: schema::schema_migration_statement(0, statement_index), params: [] };
        statement_index += 1;
    }
    statements[statements.length] = {
        sql: schema::schema_migration_record_sql(),
        params: [1, schema::schema_migration_name(0), schema::schema_migration_checksum(0), 1]
    };
    sqlite::transaction(db, statements);
    sqlite::close(db);
    true
}
"#;
    let path = root.join("craft-v1.rss");
    fs::write(&path, source).expect("v1 crafter should be written");
    AgentRunner::from_file(&path, AgentConfig::default().with_sqlite_root(root))
        .expect("v1 crafter should compile")
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
        "run_retention",
    ] {
        assert!(schema.contains(table), "schema.rss missing table {table}");
    }
}

/// The full production storage program compiles and serves typed commands
/// backed by the generic SQLite capability: migration, session create,
/// idempotency claim/complete/replay, and the atomic result envelope shapes.
/// (The former BLOCKED_VM_LIMITATION doc — the core local-slot encoding limit
/// — was resolved in the core Layer 14 contract; see the git history of the
/// core for the local-slot widening.)
#[test]
fn production_storage_commands_return_sqlite_results_and_preserve_idempotency() {
    let root = temporary_root("commands");
    let runner = storage_runner(&root);
    let db_name = "commands.db";

    let migration = run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    assert_eq!(migration["ok"], json!(true));
    assert_eq!(result_data(&migration)["schema_version"], json!(3));

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

/// Restart recovery is durable and exactly once: an interrupted run receives
/// one terminal transition and one terminal recovery event, prior events stay
/// replayable, and a second recovery is a no-op. (The former
/// BLOCKED_VM_LIMITATION doc — the core local-slot encoding limit — was
/// resolved in the core Layer 14 contract.)
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
    assert!(
        result_data(&event_append)["results"].is_array(),
        "event.append must carry the atomic transaction results array"
    );

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
    assert!(
        result_data(&recovery)["results"].is_array(),
        "recovery must carry the atomic transaction results array"
    );

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

/// A2 scale criterion: more than 1,024 total records persist through typed
/// per-record commands with no snapshot ceiling (the removed gateway path
/// refused 1,019+ records in one atomic replace).
#[test]
fn storage_scale_exceeds_1024_records_without_snapshot_ceiling() {
    let root = temporary_root("scale");
    let runner = storage_runner(&root);
    let db_name = "scale.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    run_storage(
        &runner,
        db_name,
        "session-create-1",
        "session.create",
        session_payload("session-1", 2),
        2,
    );

    const MESSAGE_COUNT: i64 = 1060;
    let mut now_ms = 3;
    for ordinal in 1..=MESSAGE_COUNT {
        run_storage(
            &runner,
            db_name,
            &format!("message-append-{ordinal}"),
            "message.append",
            message_payload(&format!("message-{ordinal}"), "session-1", ordinal, now_ms),
            now_ms,
        );
        now_ms += 1;
    }

    // The session's last_message_seq proves all 1,060 records were appended
    // beyond the former 1,019-record snapshot ceiling.
    let session = run_storage(
        &runner,
        db_name,
        "session-get-1",
        "session.get",
        json!({"session_id": "session-1"}),
        now_ms,
    );
    assert_eq!(
        first_query_row(&session)["last_message_seq"],
        json!(MESSAGE_COUNT)
    );

    // Pages stay bounded while the total row count is unbounded; the next
    // page resumes after the last returned ordinal.
    let page = run_storage_page(
        &runner,
        db_name,
        "message-list-1",
        "message.list",
        json!({
            "session_id": "session-1",
            "after_ordinal": 0,
        }),
        now_ms,
        10,
    );
    let page_rows = query_rows(&page);
    assert_eq!(page_rows.len(), 10);
    assert_eq!(page_rows[0]["ordinal"], json!(1));
    assert_eq!(page_rows[9]["ordinal"], json!(10));
    let next_page = run_storage_page(
        &runner,
        db_name,
        "message-list-2",
        "message.list",
        json!({
            "session_id": "session-1",
            "after_ordinal": 10,
        }),
        now_ms,
        10,
    );
    let next_page_rows = query_rows(&next_page);
    assert_eq!(next_page_rows.len(), 10);
    assert_eq!(next_page_rows[0]["ordinal"], json!(11));

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// A2 event-sequence criteria: per-run monotonic sequence allocation, a
/// persisted retention floor/high-water, `cursor_too_old` below the floor,
/// and replay reporting precise oldest/high-water cursors.
#[test]
fn event_retention_floor_high_water_and_cursor_too_old() {
    let root = temporary_root("retention");
    let runner = storage_runner(&root);
    let db_name = "retention.db";
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

    // The transition appended seq 1; appending 250 more events with a
    // retention of 128 keeps the tail: first retained seq = 251 - 128 + 1.
    let mut now_ms = 5;
    for seq in 2..=251 {
        run_storage(
            &runner,
            db_name,
            &format!("event-append-{seq}"),
            "event.append",
            event_payload("run-1", &format!("event-{seq}"), "model.delta", now_ms, 128),
            now_ms,
        );
        now_ms += 1;
    }

    let too_old = run_storage(
        &runner,
        db_name,
        "replay-too-old",
        "event.replay",
        json!({
            "run_id": "run-1",
            "after_seq": 0,
            "max_events": 128,
            "max_bytes": 65_536,
        }),
        now_ms,
    );
    assert_eq!(too_old["ok"], json!(false));
    assert_eq!(too_old["code"], json!("cursor_too_old"));
    assert_eq!(too_old["oldest_available_seq"], json!(124));
    assert_eq!(too_old["high_water_seq"], json!(251));

    let below_floor = run_storage(
        &runner,
        db_name,
        "replay-below-floor",
        "event.replay",
        json!({
            "run_id": "run-1",
            "after_seq": 123,
            "max_events": 128,
            "max_bytes": 65_536,
        }),
        now_ms,
    );
    assert_eq!(below_floor["ok"], json!(false));
    assert_eq!(below_floor["code"], json!("cursor_too_old"));

    let full_replay = run_storage(
        &runner,
        db_name,
        "replay-full",
        "event.replay",
        json!({
            "run_id": "run-1",
            "after_seq": 124,
            "max_events": 128,
            "max_bytes": 65_536,
        }),
        now_ms,
    );
    assert_eq!(full_replay["ok"], json!(true));
    assert_eq!(full_replay["oldest_available_seq"], json!(124));
    assert_eq!(full_replay["high_water_seq"], json!(251));
    let replay_rows = query_rows(&full_replay);
    assert_eq!(replay_rows.len(), 128);
    assert_eq!(replay_rows[0]["seq"], json!(124));
    assert_eq!(replay_rows[127]["seq"], json!(251));
    assert_eq!(replay_rows[0]["event_type"], json!("model.delta"));

    // Bounded pages: a page that fits entirely reports no truncation, and a
    // page larger than the retained tail reports truncation with a cursor.
    let small = run_storage(
        &runner,
        db_name,
        "replay-small",
        "event.replay",
        json!({
            "run_id": "run-1",
            "after_seq": 250,
            "max_events": 5,
            "max_bytes": 65_536,
        }),
        now_ms,
    );
    assert_eq!(small["ok"], json!(true));
    assert_eq!(query_rows(&small).len(), 2);
    assert_eq!(small["truncated"], json!(false));
    assert_eq!(small["next_cursor"], json!(0));

    let bounded = run_storage(
        &runner,
        db_name,
        "replay-bounded",
        "event.replay",
        json!({
            "run_id": "run-1",
            "after_seq": 124,
            "max_events": 100,
            "max_bytes": 65_536,
        }),
        now_ms,
    );
    assert_eq!(bounded["ok"], json!(true));
    assert_eq!(query_rows(&bounded).len(), 100);
    assert_eq!(bounded["truncated"], json!(true));
    assert!(
        bounded["next_cursor"]
            .as_i64()
            .is_some_and(|cursor| cursor > 0)
    );

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// A2 failure criterion: duplicate event identity is rejected atomically and
/// leaves no partial state (the append transaction rolls back entirely).
#[test]
fn duplicate_event_sequence_is_rejected_and_leaves_no_partial_state() {
    let root = temporary_root("duplicate-event");
    let runner = storage_runner(&root);
    let db_name = "duplicate.db";
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
    run_storage(
        &runner,
        db_name,
        "event-append-1",
        "event.append",
        event_payload("run-1", "event-1", "model.delta", 5, 128),
        5,
    );

    // Same event_id again: UNIQUE(event_id) violation aborts the transaction.
    let duplicate = run_storage_result(
        &runner,
        db_name,
        "event-append-dup",
        "event.append",
        event_payload("run-1", "event-1", "model.delta", 6, 128),
        6,
    );
    assert!(
        duplicate.is_err(),
        "duplicate event_id must be rejected, got {duplicate:?}"
    );

    // No partial state: exactly two events (transition + first append), and
    // the retention high-water did not advance.
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
        7,
    );
    let replay_rows = query_rows(&replay);
    assert_eq!(replay_rows.len(), 2);
    assert_eq!(replay_rows[1]["seq"], json!(2));
    assert_eq!(replay["high_water_seq"], json!(2));

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// A2 concurrency criterion: two connections claiming the same idempotency
/// key with the same request hash acquire exactly once.
#[test]
fn concurrent_idempotency_claims_acquire_exactly_once() {
    let root = temporary_root("concurrent-idempotency");
    let db_name = "concurrent.db";
    run_storage(
        &storage_runner(&root),
        db_name,
        "migrate-1",
        "migrate",
        json!({}),
        1,
    );

    let runner_a = storage_runner(&root);
    let runner_b = storage_runner(&root);
    let mut acquired = 0;
    std::thread::scope(|scope| {
        let handle_a = scope.spawn(|| {
            run_storage(
                &runner_a,
                db_name,
                "idempotency-a",
                "idempotency.begin",
                json!({
                    "scope": "api:chat",
                    "key": "request-1",
                    "request_hash": "hash-1",
                    "resource_type": "run",
                    "resource_id": "run-a",
                    "claim_token": "claim-a",
                    "now_ms": 2,
                    "expires_at_ms": 1000,
                }),
                2,
            )
        });
        let handle_b = scope.spawn(|| {
            run_storage(
                &runner_b,
                db_name,
                "idempotency-b",
                "idempotency.begin",
                json!({
                    "scope": "api:chat",
                    "key": "request-1",
                    "request_hash": "hash-1",
                    "resource_type": "run",
                    "resource_id": "run-b",
                    "claim_token": "claim-b",
                    "now_ms": 3,
                    "expires_at_ms": 1000,
                }),
                3,
            )
        });
        for handle in [handle_a, handle_b] {
            let result = handle.join().expect("idempotency thread should finish");
            let row = first_query_row(&result);
            assert_eq!(row["state"], json!("claimed"));
            acquired += row["acquired"].as_i64().expect("acquired flag") as i64;
        }
    });
    assert_eq!(acquired, 1, "exactly one concurrent claim must acquire");

    // The loser's claim token must not be stored.
    let replay = run_storage(
        &runner_a,
        db_name,
        "idempotency-replay",
        "idempotency.begin",
        json!({
            "scope": "api:chat",
            "key": "request-1",
            "request_hash": "hash-1",
            "resource_type": "run",
            "resource_id": "run-a",
            "claim_token": "claim-c",
            "now_ms": 4,
            "expires_at_ms": 1000,
        }),
        4,
    );
    assert_eq!(first_query_row(&replay)["acquired"], json!(0));

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// A2 parent/child criteria: link creation validates both runs, queries
/// preserve ordinal/relation/state, and child cancellation state is readable
/// through the run record.
#[test]
fn parent_child_links_support_query_and_cancellation_state() {
    let root = temporary_root("parent-child");
    let runner = storage_runner(&root);
    let db_name = "links.db";
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
        "run-create-parent",
        "run.create",
        run_payload("parent-1", "session-1", 3),
        3,
    );
    run_storage(
        &runner,
        db_name,
        "run-create-child",
        "run.create",
        json!({
            "id": "child-1",
            "session_id": "session-1",
            "parent_run_id": "parent-1",
            "input_json": "{\"message\":\"child\"}",
            "provider": "test-provider",
            "model": "test-model",
            "script_hash": "test-script",
            "idempotency_scope": "api:chat",
            "idempotency_key": "child-1",
            "now_ms": 4,
        }),
        4,
    );
    let link = run_storage(
        &runner,
        db_name,
        "link-child-1",
        "run.link_child",
        json!({
            "parent_run_id": "parent-1",
            "child_run_id": "child-1",
            "ordinal": 0,
            "relation": "subagent",
            "state": "active",
            "now_ms": 5,
        }),
        5,
    );
    assert_eq!(link["ok"], json!(true));

    // Linking to a nonexistent run is a typed failure (no orphan links).
    let missing = run_storage(
        &runner,
        db_name,
        "link-child-missing",
        "run.link_child",
        json!({
            "parent_run_id": "parent-1",
            "child_run_id": "ghost-1",
            "ordinal": 1,
            "relation": "subagent",
            "state": "pending",
            "now_ms": 6,
        }),
        6,
    );
    assert_eq!(missing["ok"], json!(false));
    assert_eq!(missing["code"], json!("run_not_found"));

    // The child runs and is cancelled; the parent/child link stays queryable.
    run_storage(
        &runner,
        db_name,
        "run-transition-child-running",
        "run.transition",
        transition_payload("child-1", "queued", "running", 7),
        7,
    );
    run_storage(
        &runner,
        db_name,
        "run-transition-child-cancelled",
        "run.transition",
        transition_payload("child-1", "running", "cancelled", 8),
        8,
    );
    let children = run_storage(
        &runner,
        db_name,
        "list-children-1",
        "run.list_children",
        json!({"run_id": "parent-1"}),
        9,
    );
    let child_rows = query_rows(&children);
    assert_eq!(child_rows.len(), 1);
    assert_eq!(child_rows[0]["child_run_id"], json!("child-1"));
    assert_eq!(child_rows[0]["ordinal"], json!(0));
    assert_eq!(child_rows[0]["relation"], json!("subagent"));
    assert_eq!(child_rows[0]["state"], json!("active"));

    let child = run_storage(
        &runner,
        db_name,
        "run-get-child",
        "run.get",
        json!({"run_id": "child-1"}),
        10,
    );
    let child_row = first_query_row(&child);
    assert_eq!(child_row["parent_run_id"], json!("parent-1"));
    assert_eq!(child_row["status"], json!("cancelled"));

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// A2 boundary criteria: bounded pages, bounded command payloads, bounded
/// stored payloads, and typed errors for unknown operations.
#[test]
fn bounded_pages_payloads_and_unknown_commands() {
    let root = temporary_root("bounds");
    let runner = storage_runner(&root);
    let db_name = "bounds.db";
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
    for seq in 2..=12 {
        run_storage(
            &runner,
            db_name,
            &format!("event-append-{seq}"),
            "event.append",
            event_payload(
                "run-1",
                &format!("event-{seq}"),
                "model.delta",
                seq + 3,
                128,
            ),
            seq + 3,
        );
    }

    // Unknown operations are typed errors, not crashes.
    let unknown = run_storage(
        &runner,
        db_name,
        "unknown-op",
        "no.such.operation",
        json!({}),
        100,
    );
    assert_eq!(unknown["ok"], json!(false));
    assert_eq!(unknown["code"], json!("unknown_operation"));

    // An oversized command payload is rejected before any SQL runs.
    let huge_payload = "x".repeat(5 * 1024 * 1024);
    let oversized_command = run_storage_result(
        &runner,
        db_name,
        "oversized-command",
        "session.get",
        json!({"session_id": huge_payload}),
        101,
    );
    let oversized = oversized_command.expect("oversized command must return a typed result");
    assert_eq!(oversized["ok"], json!(false));
    assert_eq!(oversized["code"], json!("payload_too_large"));

    // An oversized stored payload violates the schema CHECK and fails.
    let oversized_event = run_storage_result(
        &runner,
        db_name,
        "oversized-event",
        "event.append",
        json!({
            "run_id": "run-1",
            "event_id": "event-huge",
            "event_type": "model.delta",
            "payload_json": format!("{{\"blob\":\"{}\"}}", "y".repeat(1024 * 1024)),
            "now_ms": 200,
            "max_events": 128,
        }),
        200,
    );
    assert!(
        oversized_event.is_err(),
        "oversized stored payload must be rejected, got {oversized_event:?}"
    );

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// A2 migration criteria: fresh databases migrate to the current schema,
/// repeated migration is idempotent, upgrade from a released v1 database
/// applies only the missing migrations, and an interrupted migration rolls
/// back with no partial schema state.
#[test]
fn migrations_are_transactional_idempotent_and_upgrade_from_released_versions() {
    let root = temporary_root("migrations");
    let db_name = "migrations.db";
    let runner = storage_runner(&root);

    let first = run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    assert_eq!(result_data(&first)["schema_version"], json!(3));
    let second = run_storage(&runner, db_name, "migrate-2", "migrate", json!({}), 2);
    assert_eq!(result_data(&second)["schema_version"], json!(3));

    // A released v1 database upgrades to v3 without re-running v1. The
    // crafter builds a real v1 schema by executing the production schema
    // module's migration-1 statements, then recording version 1.
    let v1_db = "upgrade.db";
    let v1_crafter = released_v1_runner(&root);
    run_raw_sql(&v1_crafter, v1_db);
    let upgraded = run_storage(&runner, v1_db, "migrate-upgrade", "migrate", json!({}), 3);
    assert_eq!(result_data(&upgraded)["schema_version"], json!(3));
    let run_created = run_storage(
        &runner,
        v1_db,
        "upgrade-session",
        "session.create",
        session_payload("session-upgraded", 4),
        4,
    );
    assert_eq!(
        run_created["ok"],
        json!(true),
        "upgraded schema must serve commands"
    );

    // An interrupted migration rolls back atomically: a poisoned
    // schema_migrations table (extra NOT NULL column) makes the v1 record
    // insert fail, and the whole migration transaction is undone.
    let poisoned_db = "poisoned.db";
    let poisoner = raw_sql_runner(
        &root,
        "craft-poison",
        &[
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at_ms INTEGER NOT NULL, extra TEXT NOT NULL)",
        ],
    );
    run_raw_sql(&poisoner, poisoned_db);
    let poisoned = run_storage_result(
        &runner,
        poisoned_db,
        "migrate-poisoned",
        "migrate",
        json!({}),
        5,
    );
    assert!(
        poisoned.is_err(),
        "migration into a poisoned schema must fail, got {poisoned:?}"
    );

    // The failed migration left no partial state: no migration record and no
    // v1 tables were created by the rolled-back transaction.
    let inspector = query_sql_runner(
        &root,
        "inspect-poison",
        &[
            "CREATE TABLE IF NOT EXISTS probe (n INTEGER)",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM schema_migrations",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'sessions'",
        ],
        "SELECT n FROM probe ORDER BY n",
    );
    let inspected = inspector
        .run_with_context(Value::map(vec![(
            Value::string("db_name"),
            Value::string(poisoned_db),
        )]))
        .expect("poison inspection should run");
    let Value::Map(inspected) = inspected else {
        panic!("inspection should return a map");
    };
    let rows = vm_value_to_json(&Value::Map(inspected))["rows"]
        .as_array()
        .expect("inspection rows")
        .clone();
    assert_eq!(rows[0][0], json!(0), "no migration record after rollback");
    assert_eq!(rows[1][0], json!(0), "no v1 tables after rollback");

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}
