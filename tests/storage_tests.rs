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
    "jobs.rss",
    "admission.rss",
    "load.rss",
    "existence.rss",
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
    // Honors RUSTSCRIPT_AGENT_TEST_TMP (CI sets it to a runner-local
    // directory); the default keeps local development state under
    // /mnt/TEMP/rustscript (workspace rule).
    let root = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/mnt/TEMP/rustscript/storage-tests"))
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
        "title": "",
        "end_reason": "",
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
        "run_id": "",
        "finish_reason": "",
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
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    collect_rs_files(&root, &mut sources);
    assert!(
        !sources.is_empty(),
        "src/ must contain Rust sources to audit"
    );
    for path in sources {
        let source = fs::read_to_string(&path).expect("agent source should be readable");
        assert!(
            !source.contains("#[pd_host_function]"),
            "{} must not define private host functions",
            path.display()
        );
    }
}

fn collect_rs_files(directory: &std::path::Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("source directory should be readable") {
        let path = entry.expect("directory entry should be readable").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
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
        "jobs",
    ] {
        assert!(schema.contains(table), "schema.rss missing table {table}");
    }
    for op in [
        "admission.create",
        "run.terminal",
        "session.delete",
        "load.all",
        "job.create",
        "job.update",
        "job.delete",
    ] {
        assert!(
            main.contains(op),
            "main.rss must dispatch the production typed op {op}"
        );
    }
    assert!(
        !main.contains("gateway.rss"),
        "production main.rss must never import the legacy gateway.rss adapter"
    );
    assert!(
        fs::read_to_string(root.join("gateway.rss"))
            .expect("gateway adapter")
            .contains("LEGACY ADAPTER"),
        "gateway.rss must be marked as a legacy adapter, not a production path"
    );
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
    assert_eq!(result_data(&migration)["schema_version"], json!(5));

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
    assert_eq!(below_floor["ok"], json!(true));
    let below_floor_rows = query_rows(&below_floor);
    assert_eq!(below_floor_rows[0]["seq"], json!(124));

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

/// A2 exact-once criterion: re-appending the SAME event_id with the SAME
/// run and content is an idempotent replay (no second row, no UNIQUE
/// conflict); re-appending the SAME event_id with DIFFERENT content is a
/// typed conflict — never a silent swallow, never a fabricated second event.
#[test]
fn duplicate_event_sequence_replays_exactly_once_or_conflicts_typed() {
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

    // Retry the exact same event_id with the exact same content: this is the
    // ambiguous-commit retry (SQLite committed, the response was lost) and
    // must be a successful idempotent replay, NOT a UNIQUE(event_id) failure.
    let replay = run_storage(
        &runner,
        db_name,
        "event-append-replay",
        "event.append",
        event_payload("run-1", "event-1", "model.delta", 6, 128),
        6,
    );
    assert_eq!(
        replay["ok"],
        json!(true),
        "the same event_id + content must replay idempotently, got {replay:?}"
    );
    let replay_data = result_data(&replay);
    assert_eq!(
        replay_data["results"][0]["replayed"],
        json!(true),
        "the replay result must advertise the pre-existing durable event"
    );
    assert_eq!(
        replay_data["results"][0]["existing_seq"],
        json!(2),
        "the replay surfaces the original seq (the transition event holds seq 1), never a new allocation"
    );

    // Now clash on the SAME event_id with DIFFERENT content: that is a typed
    // conflict, not a silent overwrite and not a second event.
    let conflict = run_storage_result(
        &runner,
        db_name,
        "event-append-conflict",
        "event.append",
        event_payload("run-1", "event-1", "model.mock", 7, 128),
        7,
    );
    let conflict = conflict.expect("a typed conflict is still a returned result");
    assert_eq!(
        conflict["ok"],
        json!(false),
        "same event_id + different content must be a typed conflict: {conflict:?}"
    );
    assert_eq!(conflict["code"], json!("event_id_conflict"));

    // The durable trail is exact-once: still (transition + one append), seq 1
    // "model.delta" untouched, retention high-water unchanged.
    let replay_again = run_storage(
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
    let replay_rows = query_rows(&replay_again);
    assert_eq!(replay_rows.len(), 2);
    assert_eq!(replay_rows[0]["event_type"], json!("run.status_changed"));
    assert_eq!(replay_rows[1]["seq"], json!(2));
    assert_eq!(replay_rows[1]["event_id"], json!("event-1"));
    assert_eq!(replay_rows[1]["event_type"], json!("model.delta"));
    assert_eq!(replay_again["high_water_seq"], json!(2));

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// A2 exact-once ownership: the SAME event_id used against a DIFFERENT run is
/// a typed ownership conflict, never a silent cross-run replay.
#[test]
fn duplicate_event_id_across_runs_is_typed_ownership_conflict() {
    let root = temporary_root("duplicate-event-owner");
    let runner = storage_runner(&root);
    let db_name = "duplicate-owner.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    run_storage(
        &runner,
        db_name,
        "session-create-1",
        "session.create",
        session_payload("session-1", 2),
        2,
    );
    for (run_id, now) in [("run-a", 3), ("run-b", 4)] {
        run_storage(
            &runner,
            db_name,
            &format!("run-create-{run_id}"),
            "run.create",
            run_payload(run_id, "session-1", now),
            now,
        );
    }
    run_storage(
        &runner,
        db_name,
        "event-append-a",
        "event.append",
        event_payload("run-a", "shared-id", "model.delta", 5, 128),
        5,
    );

    // Same event_id but a different run with identical-looking content: the
    // event_id is owned by run-a, so run-b's append must be a typed conflict.
    let conflict = run_storage_result(
        &runner,
        db_name,
        "event-append-b",
        "event.append",
        event_payload("run-b", "shared-id", "model.delta", 6, 128),
        6,
    )
    .expect("a typed conflict must be a returned result");
    assert_eq!(conflict["ok"], json!(false));
    assert_eq!(conflict["code"], json!("event_id_conflict"));

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
    assert_eq!(result_data(&first)["schema_version"], json!(5));
    let second = run_storage(&runner, db_name, "migrate-2", "migrate", json!({}), 2);
    assert_eq!(result_data(&second)["schema_version"], json!(5));

    // A released v1 database upgrades to v3 without re-running v1. The
    // crafter builds a real v1 schema by executing the production schema
    // module's migration-1 statements, then recording version 1.
    let v1_db = "upgrade.db";
    let v1_crafter = released_v1_runner(&root);
    run_raw_sql(&v1_crafter, v1_db);
    // A real v1-era RUN row (the v1 runs table has no origin_actor column):
    // after the v5 upgrade the ALTER adds the column with the empty default,
    // so old rows survive and read an EMPTY origin actor (typed-rejected by
    // the telegram owner gate — never fabricated or fatal).
    let old_row_crafter = raw_sql_runner(
        &root,
        "craft-old-run",
        &[
            "INSERT INTO sessions (id, profile, platform, account_id, chat_id, thread_id, user_id, generation, status, system_prompt, model, provider, toolset_hash, metadata_json, last_message_seq, created_at_ms, updated_at_ms) VALUES ('old-session', 'telegram', 'telegram', 'fixture_bot', '555', '', '555', 1, 'active', '', 'm', 'p', '', '{}', 0, 1, 1)",
            "INSERT INTO runs (id, session_id, parent_run_id, status, input_json, provider, model, script_hash, idempotency_scope, idempotency_key, turn_count, input_tokens, output_tokens, error_code, error_message, recovery_reason, created_at_ms, started_at_ms, finished_at_ms, updated_at_ms) VALUES ('old-run', 'old-session', '', 'running', '{}', 'p', 'm', '', '', '', 0, 0, 0, '', '', '', 1, 1, 0, 1)",
        ],
    );
    run_raw_sql(&old_row_crafter, v1_db);
    let upgraded = run_storage(&runner, v1_db, "migrate-upgrade", "migrate", json!({}), 3);
    assert_eq!(result_data(&upgraded)["schema_version"], json!(5));
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
    // The v5 ALTER preserved the pre-v5 row and its origin column is empty.
    let old_run = run_storage(
        &runner,
        v1_db,
        "upgrade-old-run",
        "run.get",
        json!({"run_id": "old-run"}),
        5,
    );
    let old_row = first_query_row(&old_run);
    assert_eq!(old_row["id"], json!("old-run"));
    assert_eq!(
        old_row["origin_actor"],
        json!(""),
        "a pre-v5 run row must keep an empty origin actor after the upgrade"
    );
    // run.get serves the v5 row shape (21 columns: 20 v1 + origin_actor).
    assert_eq!(
        query_rows(&old_run)[0].len(),
        21,
        "the upgraded run row must expose the v5 column shape"
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

/// P2-4: the core SQLite host does not enforce foreign keys (documented core
/// blocker), so the RSS layer must explicitly reject every orphan write:
/// run.create (unknown session / parent), message.append (unknown session),
/// event.append (unknown run), approval.request (unknown run/session),
/// compaction.start (unknown session/run), and run.link_child (unknown pair)
/// all fail with typed errors and leave no rows behind.
#[test]
fn orphan_references_are_rejected_with_typed_errors() {
    let root = temporary_root("orphans");
    let runner = storage_runner(&root);
    let db_name = "orphans.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);

    let run_missing_session = run_storage(
        &runner,
        db_name,
        "run-create-orphan",
        "run.create",
        run_payload("run-orphan", "session-ghost", 2),
        2,
    );
    assert_eq!(run_missing_session["ok"], json!(false));
    assert_eq!(run_missing_session["code"], json!("session_not_found"));

    run_storage(
        &runner,
        db_name,
        "session-create-1",
        "session.create",
        session_payload("session-1", 3),
        3,
    );
    let run_missing_parent = run_storage(
        &runner,
        db_name,
        "run-create-parent-orphan",
        "run.create",
        json!({
            "id": "run-parent-orphan",
            "session_id": "session-1",
            "parent_run_id": "parent-ghost",
            "input_json": "{}",
            "provider": "p",
            "model": "m",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "now_ms": 4,
        }),
        4,
    );
    assert_eq!(run_missing_parent["ok"], json!(false));
    assert_eq!(run_missing_parent["code"], json!("parent_not_found"));

    run_storage(
        &runner,
        db_name,
        "run-create-1",
        "run.create",
        run_payload("run-1", "session-1", 5),
        5,
    );
    let message_orphan = run_storage(
        &runner,
        db_name,
        "message-append-orphan",
        "message.append",
        message_payload("message-orphan", "session-ghost", 1, 6),
        6,
    );
    assert_eq!(message_orphan["ok"], json!(false));
    assert_eq!(message_orphan["code"], json!("session_not_found"));

    let event_orphan = run_storage(
        &runner,
        db_name,
        "event-append-orphan",
        "event.append",
        event_payload("run-ghost", "event-orphan", "model.delta", 7, 128),
        7,
    );
    assert_eq!(event_orphan["ok"], json!(false));
    assert_eq!(event_orphan["code"], json!("run_not_found"));

    let approval_orphan = run_storage(
        &runner,
        db_name,
        "approval-orphan",
        "approval.request",
        json!({
            "id": "approval-orphan",
            "run_id": "run-ghost",
            "session_id": "session-1",
            "tool_call_id": "tool-1",
            "tool_name": "shell",
            "arguments_json": "{}",
            "risk_class": "execute",
            "decision_scope": "",
            "one_time": 0,
            "requested_at_ms": 8,
            "expires_at_ms": 0,
        }),
        8,
    );
    assert_eq!(approval_orphan["ok"], json!(false));
    assert_eq!(approval_orphan["code"], json!("run_not_found"));

    let compaction_orphan = run_storage(
        &runner,
        db_name,
        "compaction-orphan",
        "compaction.start",
        json!({
            "id": "compaction-orphan",
            "session_id": "session-ghost",
            "run_id": "run-1",
            "generation": 1,
            "source_start_ordinal": 1,
            "source_end_ordinal": 1,
            "retained_tail_ordinal": 1,
            "summary_json": "{}",
            "token_estimate": 0,
            "model": "m",
            "now_ms": 9,
        }),
        9,
    );
    assert_eq!(compaction_orphan["ok"], json!(false));
    assert_eq!(compaction_orphan["code"], json!("run_not_found"));

    // No orphan rows exist anywhere after the rejections.
    let inspector = query_sql_runner(
        &root,
        "inspect-orphans",
        &[
            "CREATE TABLE IF NOT EXISTS probe (n INTEGER)",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM runs",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM messages",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM run_events",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM approvals",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM compactions",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM child_run_links",
        ],
        "SELECT n FROM probe ORDER BY n",
    );
    let inspected = inspector
        .run_with_context(Value::map(vec![(
            Value::string("db_name"),
            Value::string(db_name),
        )]))
        .expect("orphan inspection should run");
    let Value::Map(inspected) = inspected else {
        panic!("inspection should return a map");
    };
    let rows = vm_value_to_json(&Value::Map(inspected))["rows"]
        .as_array()
        .expect("inspection rows")
        .clone();
    // Probe rows are sorted ascending; runs is the only non-zero count.
    assert_eq!(rows[0][0], json!(0), "no orphan messages");
    assert_eq!(rows[1][0], json!(0), "no orphan events");
    assert_eq!(rows[2][0], json!(0), "no orphan approvals");
    assert_eq!(rows[3][0], json!(0), "no orphan compactions");
    assert_eq!(rows[4][0], json!(0), "no orphan child links");
    assert_eq!(rows[5][0], json!(1), "only run-1 exists");

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// P3: the compaction guarded insert's `ON CONFLICT ... DO UPDATE` must
/// also require the existing row to carry the SAME id
/// (`compactions.id = excluded.id`). The typed different-id precheck closes
/// the in-process race; this SQL-level guard closes the cross-process
/// window where two processes both passed the precheck before either row
/// existed — the update must never silently replace a failed row's audit
/// identity. Both clauses below are the production
/// `compaction_start_insert` statement (rss/storage/compactions.rss) with
/// literal parameters, differing only in the id guard, so the semantics are
/// exercised against real SQLite exactly as shipped.
#[test]
fn compaction_conflict_update_requires_the_same_id() {
    let root = temporary_root("compaction-race-guard");
    let runner = storage_runner(&root);
    let db_name = "race-guard.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    run_storage(
        &runner,
        db_name,
        "session-1",
        "session.create",
        session_payload("session-1", 2),
        2,
    );
    run_storage(
        &runner,
        db_name,
        "run-1",
        "run.create",
        run_payload("run-1", "session-1", 3),
        3,
    );
    run_storage(
        &runner,
        db_name,
        "run-running",
        "run.transition",
        transition_payload("run-1", "queued", "running", 4),
        4,
    );
    run_storage(
        &runner,
        db_name,
        "run-compacting",
        "run.transition",
        transition_payload("run-1", "running", "compacting", 5),
        5,
    );
    for ordinal in 1..=3 {
        run_storage(
            &runner,
            db_name,
            &format!("message-append-{ordinal}"),
            "message.append",
            message_payload(
                &format!("message-{ordinal}"),
                "session-1",
                ordinal,
                5 + ordinal,
            ),
            5 + ordinal,
        );
    }
    // The typed path creates the pending row (id compaction-1) and fails it.
    let started = run_storage(
        &runner,
        db_name,
        "start",
        "compaction.start",
        json!({
            "id": "compaction-1",
            "session_id": "session-1",
            "run_id": "run-1",
            "generation": 2,
            "source_start_ordinal": 1,
            "source_end_ordinal": 3,
            "retained_tail_ordinal": 3,
            "summary_json": "{}",
            "token_estimate": 0,
            "model": "m",
            "now_ms": 1000,
        }),
        1000,
    );
    assert_eq!(started["ok"], json!(true));
    run_storage(
        &runner,
        db_name,
        "fail",
        "compaction.fail",
        json!({
            "id": "compaction-1",
            "error_message": "boom",
            "completed_at_ms": 1000,
        }),
        1000,
    );

    // A second process's guarded insert for the SAME session+generation but
    // a DIFFERENT id. Both clause variants below mirror the production
    // statement; the first one intentionally drops the id guard to prove the
    // setup detects a clobber (sensitivity), the second carries the shipped
    // guard and must leave the failed row untouched.
    let insert_head = concat!(
        "INSERT INTO compactions (id, session_id, run_id, generation, source_start_ordinal, source_end_ordinal, retained_tail_ordinal, summary_json, token_estimate, model, state, created_at_ms) ",
        "SELECT 'compaction-2', 'session-1', 'run-1', 2, 1, 3, 3, '{}', 0, 'm', 'pending', 1000 ",
        "FROM sessions JOIN runs ON runs.session_id = sessions.id ",
        "WHERE sessions.id = 'session-1' AND sessions.generation + 1 = 2 AND runs.id = 'run-1' AND runs.session_id = 'session-1' AND runs.status = 'compacting' ",
        "AND 1 >= 0 AND 3 >= 1 AND 3 >= 1 AND 3 <= 3 ",
        "AND EXISTS (SELECT 1 FROM messages WHERE messages.session_id = sessions.id AND messages.ordinal = 1) ",
        "AND EXISTS (SELECT 1 FROM messages WHERE messages.session_id = sessions.id AND messages.ordinal = 3) ",
        "AND NOT EXISTS (SELECT 1 FROM compactions existing WHERE existing.id = 'compaction-2' AND existing.session_id <> 'session-1') ",
        "ON CONFLICT (session_id, generation) DO UPDATE SET id = excluded.id, run_id = excluded.run_id, source_start_ordinal = excluded.source_start_ordinal, source_end_ordinal = excluded.source_end_ordinal, retained_tail_ordinal = excluded.retained_tail_ordinal, summary_json = excluded.summary_json, token_estimate = excluded.token_estimate, model = excluded.model, state = 'pending', error_message = '', created_at_ms = excluded.created_at_ms, completed_at_ms = 0 ",
        "WHERE compactions.state = 'failed'"
    );
    let unguarded = query_sql_runner(
        &root,
        "race-unguarded",
        &[insert_head],
        "SELECT id, state FROM compactions WHERE session_id = 'session-1' AND generation = 2",
    );
    let inspected = unguarded
        .run_with_context(Value::map(vec![(
            Value::string("db_name"),
            Value::string(db_name),
        )]))
        .expect("unguarded insert should run");
    let Value::Map(inspected) = inspected else {
        panic!("inspection should return a map");
    };
    let rows = vm_value_to_json(&Value::Map(inspected))["rows"]
        .as_array()
        .expect("inspection rows")
        .clone();
    assert_eq!(
        rows[0][0],
        json!("compaction-2"),
        "without the id guard the different-id insert would clobber the failed row"
    );
    assert_eq!(rows[0][1], json!("pending"));

    // Restore the failed row's identity so the guarded clause can be
    // exercised in isolation.
    let restore = query_sql_runner(
        &root,
        "race-restore",
        &[
            "UPDATE compactions SET id = 'compaction-1', state = 'failed', error_message = 'boom', completed_at_ms = 1000 WHERE session_id = 'session-1' AND generation = 2",
        ],
        "SELECT id, state FROM compactions WHERE session_id = 'session-1' AND generation = 2",
    );
    let inspected = restore
        .run_with_context(Value::map(vec![(
            Value::string("db_name"),
            Value::string(db_name),
        )]))
        .expect("restore should run");
    let Value::Map(inspected) = inspected else {
        panic!("inspection should return a map");
    };
    let rows = vm_value_to_json(&Value::Map(inspected))["rows"]
        .as_array()
        .expect("inspection rows")
        .clone();
    assert_eq!(rows[0][0], json!("compaction-1"));
    assert_eq!(rows[0][1], json!("failed"));

    // The shipped clause: the conflict fires on the unique key, but the DO
    // UPDATE must not clobber the failed row because excluded.id differs.
    let guarded_sql = format!("{insert_head} AND compactions.id = excluded.id");
    let guarded = query_sql_runner(
        &root,
        "race-guarded",
        &[guarded_sql.as_str()],
        "SELECT id, state, error_message FROM compactions WHERE session_id = 'session-1' AND generation = 2",
    );
    let inspected = guarded
        .run_with_context(Value::map(vec![(
            Value::string("db_name"),
            Value::string(db_name),
        )]))
        .expect("guarded insert should run");
    let Value::Map(inspected) = inspected else {
        panic!("inspection should return a map");
    };
    let rows = vm_value_to_json(&Value::Map(inspected))["rows"]
        .as_array()
        .expect("inspection rows")
        .clone();
    assert_eq!(rows.len(), 1, "exactly one compaction row must remain");
    assert_eq!(
        rows[0][0],
        json!("compaction-1"),
        "the different-id insert must not clobber the failed row's audit identity"
    );
    assert_eq!(rows[0][1], json!("failed"), "the row must stay failed");
    assert_eq!(
        rows[0][2],
        json!("boom"),
        "the failure message must survive"
    );

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// P3: a run.transition that matches no row is a typed `transition_conflict`,
/// never a silent success.
#[test]
fn transition_conflict_is_typed_when_no_row_matches() {
    let root = temporary_root("transition-conflict");
    let runner = storage_runner(&root);
    let db_name = "transition.db";
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
    // Wrong from_status: the guarded UPDATE matches nothing.
    let conflict = run_storage(
        &runner,
        db_name,
        "run-transition-conflict",
        "run.transition",
        transition_payload("run-1", "completed", "running", 4),
        4,
    );
    assert_eq!(conflict["ok"], json!(false));
    assert_eq!(conflict["code"], json!("transition_conflict"));
    // The run is untouched and no status_changed event was appended.
    let run = run_storage(
        &runner,
        db_name,
        "run-get-1",
        "run.get",
        json!({"run_id": "run-1"}),
        5,
    );
    assert_eq!(first_query_row(&run)["status"], json!("queued"));

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// P3: run.link_child is idempotent — re-linking an existing pair is a
/// success and never creates a duplicate row.
#[test]
fn link_child_is_idempotent() {
    let root = temporary_root("link-idempotent");
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
            "input_json": "{}",
            "provider": "p",
            "model": "m",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "now_ms": 4,
        }),
        4,
    );
    let link_payload = json!({
        "parent_run_id": "parent-1",
        "child_run_id": "child-1",
        "ordinal": 0,
        "relation": "subagent",
        "state": "active",
        "now_ms": 5,
    });
    let first = run_storage(
        &runner,
        db_name,
        "link-1",
        "run.link_child",
        link_payload.clone(),
        5,
    );
    assert_eq!(first["ok"], json!(true));
    let second = run_storage(
        &runner,
        db_name,
        "link-2",
        "run.link_child",
        link_payload,
        6,
    );
    assert_eq!(second["ok"], json!(true), "re-linking must be idempotent");
    let children = run_storage(
        &runner,
        db_name,
        "list-children-1",
        "run.list_children",
        json!({"run_id": "parent-1"}),
        7,
    );
    assert_eq!(
        query_rows(&children).len(),
        1,
        "exactly one link row survives"
    );

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// A6 subagent supervision storage contract: the `run.link_child` command
/// the subagent policy emits (`relation: "subagent"`, `state: "active"`)
/// durably records each child under its parent, `run.list_children` returns
/// the fanout in ordinal order, and the parent/child identity survives child
/// terminal transitions (so parent-cancellation propagation can enumerate
/// pending/active children). This is the A2 storage half of the A6 policy
/// that is buildable without the missing generic task/child capability.
#[test]
fn subagent_supervision_links_and_fanout_are_durable() {
    let root = temporary_root("a6-subagent-links");
    let runner = storage_runner(&root);
    let db_name = "a6-subagent.db";
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
    // Admit three children under the parent, mirroring the subagent policy's
    // admit path: run.create carries parent_run_id, then run.link_child
    // records the durable link exactly as the policy's link command describes.
    for i in 0..3 {
        let child_id = format!("child-{i}");
        run_storage(
            &runner,
            db_name,
            &format!("run-create-{i}"),
            "run.create",
            json!({
                "id": child_id,
                "session_id": "session-1",
                "parent_run_id": "parent-1",
                "input_json": "{}",
                "provider": "p",
                "model": "m",
                "script_hash": "s",
                "idempotency_scope": "api:chat",
                "idempotency_key": "",
                "now_ms": 4 + i,
            }),
            4 + i,
        );
        let link = run_storage(
            &runner,
            db_name,
            &format!("link-{i}"),
            "run.link_child",
            json!({
                "parent_run_id": "parent-1",
                "child_run_id": child_id,
                "ordinal": i,
                "relation": "subagent",
                "state": "active",
                "now_ms": 10 + i,
            }),
            10 + i,
        );
        assert_eq!(link["ok"], json!(true), "child {i} link must be durable");
    }
    // Fanout: list_children returns the three subagent links in ordinal order.
    let children = run_storage(
        &runner,
        db_name,
        "list-children",
        "run.list_children",
        json!({"run_id": "parent-1"}),
        13,
    );
    let rows = query_rows(&children);
    assert_eq!(rows.len(), 3, "parent fanout must be exactly three");
    assert_eq!(rows[0]["child_run_id"], json!("child-0"));
    assert_eq!(rows[0]["ordinal"], json!(0));
    assert_eq!(rows[0]["relation"], json!("subagent"));
    assert_eq!(rows[1]["child_run_id"], json!("child-1"));
    assert_eq!(rows[2]["child_run_id"], json!("child-2"));
    assert_eq!(rows[2]["ordinal"], json!(2));
    // Every child row carries the durable parent_run_id.
    let child = run_storage(
        &runner,
        db_name,
        "run-get-child",
        "run.get",
        json!({"run_id": "child-0"}),
        14,
    );
    let child_row = first_query_row(&child);
    assert_eq!(child_row["parent_run_id"], json!("parent-1"));
    // A child reaching terminal keeps its link (parent-cancellation
    // enumeration can still see the full fanout; the policy filters by state).
    run_storage(
        &runner,
        db_name,
        "run-transition-child-completed",
        "run.transition",
        transition_payload("child-0", "queued", "completed", 15),
        15,
    );
    let after = run_storage(
        &runner,
        db_name,
        "list-children-after-terminal",
        "run.list_children",
        json!({"run_id": "parent-1"}),
        16,
    );
    assert_eq!(
        query_rows(&after).len(),
        3,
        "terminal children keep their durable link"
    );

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}
#[test]
fn event_prune_updates_retention_floor_and_high_water() {
    let root = temporary_root("prune-retention");
    let runner = storage_runner(&root);
    let db_name = "prune.db";
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
    let mut now_ms = 5;
    for seq in 2..=40 {
        run_storage(
            &runner,
            db_name,
            &format!("event-append-{seq}"),
            "event.append",
            event_payload("run-1", &format!("event-{seq}"), "model.delta", now_ms, 256),
            now_ms,
        );
        now_ms += 1;
    }
    let pruned = run_storage(
        &runner,
        db_name,
        "prune-1",
        "event.prune",
        json!({"run_id": "run-1", "max_events": 10, "now_ms": now_ms}),
        now_ms,
    );
    assert_eq!(pruned["ok"], json!(true));
    // 40 events + 1 transition event; retain the last 10 -> floor 31,
    // high-water 40.
    let replay = run_storage(
        &runner,
        db_name,
        "replay-after-prune",
        "event.replay",
        json!({
            "run_id": "run-1",
            "after_seq": 0,
            "max_events": 128,
            "max_bytes": 65_536,
        }),
        now_ms + 1,
    );
    assert_eq!(replay["ok"], json!(false));
    assert_eq!(replay["code"], json!("cursor_too_old"));
    assert_eq!(replay["oldest_available_seq"], json!(31));
    assert_eq!(replay["high_water_seq"], json!(40));

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// P1-2 (RSS layer): admission.create is one atomic transaction — a failed
/// admission (unknown session) commits nothing, and a successful admission
/// commits the session, user message, run, run.started event, retention
/// floor, child link, and idempotency record together.
#[test]
fn admission_create_is_atomic_and_writes_the_full_normalized_set() {
    let root = temporary_root("admission");
    let runner = storage_runner(&root);
    let db_name = "admission.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);

    let rejected = run_storage(
        &runner,
        db_name,
        "admission-rejected",
        "admission.create",
        json!({
            "session_id": "session-ghost",
            "session_new": 0,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "session-ghost",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "run_id": "run-rejected",
            "parent_run_id": "",
            "input_json": "{\"text\":\"hello\"}",
            "message_id": "message-rejected",
            "message_run_id": "run-rejected",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "request_hash": "",
            "origin_actor": "",
            "event_id": "event-rejected",
            "now_ms": 2,
            "expires_at_ms": 0,
            "conversation_json": "",
        }),
        2,
    );
    assert_eq!(rejected["ok"], json!(false));
    assert_eq!(rejected["code"], json!("session_not_found"));

    let admitted = run_storage(
        &runner,
        db_name,
        "admission-ok",
        "admission.create",
        json!({
            "session_id": "session-1",
            "session_new": 1,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "session-1",
            "model": "test-model",
            "provider": "test-provider",
            "system_prompt": "be helpful",
            "run_id": "run-1",
            "parent_run_id": "",
            "input_json": "{\"text\":\"hello\"}",
            "message_id": "message-1",
            "message_run_id": "run-1",
            "script_hash": "script-hash",
            "idempotency_scope": "api:chat",
            "idempotency_key": "request-1",
            "request_hash": "hash-1",
            "origin_actor": "",
            "event_id": "event-started-1",
            "now_ms": 3,
            "expires_at_ms": 0,
            "conversation_json": "",
        }),
        3,
    );
    assert_eq!(admitted["ok"], json!(true));
    let data = result_data(&admitted);
    let run_row = data["run"]["rows"][0].as_array().expect("run row");
    assert_eq!(run_row[0], json!("run-1"));
    assert_eq!(run_row[1], json!("session-1"));
    assert_eq!(run_row[3], json!("running"));
    let session_row = data["session"]["rows"][0].as_array().expect("session row");
    assert_eq!(session_row[0], json!("session-1"));
    assert_eq!(session_row[9], json!("be helpful"));
    let message_row = data["message"]["rows"][0].as_array().expect("message row");
    assert_eq!(message_row[1], json!("session-1"));
    assert_eq!(message_row[2], json!(1), "first message ordinal is 1");
    assert_eq!(message_row[3], json!("user"));
    let idempotency_row = data["idempotency"]["rows"][0]
        .as_array()
        .expect("idempotency row");
    assert_eq!(idempotency_row[2], json!("hash-1"));
    assert_eq!(idempotency_row[4], json!("run-1"));
    assert_eq!(idempotency_row[5], json!("completed"));

    // The run.started event is seq 1 and the retention floor is 1/1.
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
        4,
    );
    let replay_rows = query_rows(&replay);
    assert_eq!(replay_rows.len(), 1);
    assert_eq!(replay_rows[0]["event_type"], json!("run.started"));
    assert_eq!(replay_rows[0]["seq"], json!(1));
    assert_eq!(replay["oldest_available_seq"], json!(1));
    assert_eq!(replay["high_water_seq"], json!(1));

    // The rejected admission left nothing behind: only the successful run,
    // one message, and one event exist.
    let inspector = query_sql_runner(
        &root,
        "inspect-admission",
        &[
            "CREATE TABLE IF NOT EXISTS probe (n INTEGER)",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM sessions",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM runs",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM messages",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM run_events",
        ],
        "SELECT n FROM probe ORDER BY n",
    );
    let inspected = inspector
        .run_with_context(Value::map(vec![(
            Value::string("db_name"),
            Value::string(db_name),
        )]))
        .expect("admission inspection should run");
    let Value::Map(inspected) = inspected else {
        panic!("inspection should return a map");
    };
    let rows = vm_value_to_json(&Value::Map(inspected))["rows"]
        .as_array()
        .expect("inspection rows")
        .clone();
    assert_eq!(rows[0][0], json!(1), "one session");
    assert_eq!(rows[1][0], json!(1), "one run");
    assert_eq!(rows[2][0], json!(1), "one message");
    assert_eq!(rows[3][0], json!(1), "one event");

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// P1-3 (RSS layer): run.terminal commits the status change, the terminal
/// events, the retention update, and the optional assistant message in one
/// transaction; sequences are allocated as max+1 and returned for
/// reconciliation.
#[test]
fn run_terminal_commits_atomically_and_returns_assigned_sequences() {
    let root = temporary_root("terminal");
    let runner = storage_runner(&root);
    let db_name = "terminal.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    run_storage(
        &runner,
        db_name,
        "admission-1",
        "admission.create",
        json!({
            "session_id": "session-1",
            "session_new": 1,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "session-1",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "run_id": "run-1",
            "parent_run_id": "",
            "input_json": "{\"text\":\"hi\"}",
            "message_id": "message-1",
            "message_run_id": "run-1",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "request_hash": "",
            "origin_actor": "",
            "event_id": "event-started-1",
            "now_ms": 2,
            "expires_at_ms": 0,
            "conversation_json": "",
        }),
        2,
    );
    // Two script events: seq 2 and 3.
    for (seq, event_id) in [(2i64, "event-2"), (3, "event-3")] {
        run_storage(
            &runner,
            db_name,
            &format!("event-append-{seq}"),
            "event.append",
            event_payload("run-1", event_id, "model.delta", seq + 1, 128),
            seq + 1,
        );
    }

    let terminal = run_storage(
        &runner,
        db_name,
        "terminal-1",
        "run.terminal",
        json!({
            "run_id": "run-1",
            "to_status": "completed",
            "error_code": "",
            "error_message": "",
            "event_1_id": "event-delta",
            "event_1_type": "message.delta",
            "event_1_payload": "{\"delta\":\"done\"}",
            "event_2_id": "event-completed",
            "event_2_type": "run.completed",
            "event_2_payload": "{\"status\":\"completed\"}",
            "event_count": 2,
            "message_id": "message-assistant",
            "message_session_id": "session-1",
            "message_role": "assistant",
            "message_content_json": "{\"text\":\"done\"}",
            "message_run_id": "run-1",
            "message_finish_reason": "stop",
            "now_ms": 6,
        }),
        6,
    );
    assert_eq!(terminal["ok"], json!(true));
    let data = result_data(&terminal);
    let run_row = data["run"]["rows"][0].as_array().expect("run row");
    assert_eq!(run_row[3], json!("completed"));
    assert_eq!(run_row[18], json!(6), "finished_at_ms is set");
    // Events 1..5 with assigned sequences; the terminal events are 4 and 5.
    let event_rows = data["events"]["rows"].as_array().expect("event rows");
    assert_eq!(event_rows.len(), 5);
    let last = event_rows[4].as_array().expect("last event row");
    assert_eq!(last[2], json!("event-completed"));
    assert_eq!(last[0], json!(5), "terminal event sequence is max+1");
    let second_last = event_rows[3].as_array().expect("second last event row");
    assert_eq!(second_last[2], json!("event-delta"));
    assert_eq!(second_last[0], json!(4));

    // The terminal response must expose the durable assistant row used by
    // the caller to reconcile the pre-generated message id.
    let terminal_message_rows = data["message"]["rows"]
        .as_array()
        .expect("terminal message rows");
    assert_eq!(terminal_message_rows.len(), 1);
    assert_eq!(terminal_message_rows[0][0], json!("message-assistant"));

    // The assistant message is part of the same commit.
    let message = run_storage(
        &runner,
        db_name,
        "message-get-assistant",
        "message.get",
        json!({
            "message_id": "message-assistant",
            "session_id": "session-1",
            "run_id": "run-1"
        }),
        7,
    );
    let message_row = first_query_row(&message);
    assert_eq!(message_row["ordinal"], json!(2));
    assert_eq!(message_row["role"], json!("assistant"));
    assert_eq!(message_row["run_id"], json!("run-1"));
    assert_eq!(message_row["finish_reason"], json!("stop"));

    // A second terminal commit on the same run is a typed conflict (the
    // status is no longer 'running'), so exactly one terminal exists.
    let second_terminal = run_storage(
        &runner,
        db_name,
        "terminal-2",
        "run.terminal",
        json!({
            "run_id": "run-1",
            "to_status": "cancelled",
            "error_code": "",
            "error_message": "",
            "event_1_id": "event-dup",
            "event_1_type": "run.cancelled",
            "event_1_payload": "{}",
            "event_2_id": "",
            "event_2_type": "",
            "event_2_payload": "",
            "event_count": 1,
            "message_id": "",
            "message_session_id": "",
            "message_role": "",
            "message_content_json": "",
            "message_run_id": "",
            "message_finish_reason": "",
            "now_ms": 8,
        }),
        8,
    );
    assert_eq!(second_terminal["ok"], json!(false));
    assert_eq!(second_terminal["code"], json!("transition_conflict"));

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// P1: a durable message lookup is authorized by the owning run and session,
/// not by a globally unique message id alone.
#[test]
fn message_get_requires_run_and_session_ownership() {
    let root = temporary_root("message-owner");
    let runner = storage_runner(&root);
    let db_name = "message-owner.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    run_storage(
        &runner,
        db_name,
        "admission-1",
        "admission.create",
        json!({
            "session_id": "session-owner",
            "session_new": 1,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "session-owner",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "run_id": "run-owner",
            "parent_run_id": "",
            "input_json": "{\"text\":\"hi\"}",
            "message_id": "message-input",
            "message_run_id": "run-owner",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "request_hash": "",
            "origin_actor": "",
            "event_id": "event-started-1",
            "now_ms": 2,
            "expires_at_ms": 0,
            "conversation_json": "",
        }),
        2,
    );
    run_storage(
        &runner,
        db_name,
        "terminal-1",
        "run.terminal",
        json!({
            "run_id": "run-owner",
            "to_status": "completed",
            "error_code": "",
            "error_message": "",
            "event_1_id": "event-delta",
            "event_1_type": "message.delta",
            "event_1_payload": "{\"delta\":\"done\"}",
            "event_2_id": "event-completed",
            "event_2_type": "run.completed",
            "event_2_payload": "{\"status\":\"completed\"}",
            "event_count": 2,
            "message_id": "message-assistant",
            "message_session_id": "session-owner",
            "message_role": "assistant",
            "message_content_json": "{\"text\":\"done\"}",
            "message_run_id": "run-owner",
            "message_finish_reason": "stop",
            "now_ms": 3,
        }),
        3,
    );
    run_storage(
        &runner,
        db_name,
        "session-foreign",
        "session.create",
        session_payload("session-foreign", 4),
        4,
    );

    let unauthorized = run_storage(
        &runner,
        db_name,
        "message-owner-check",
        "message.get",
        json!({
            "message_id": "message-assistant",
            "session_id": "session-foreign",
            "run_id": "run-foreign"
        }),
        5,
    );
    assert_eq!(
        query_rows(&unauthorized).len(),
        0,
        "a message id must not authorize cross-session or cross-run reads"
    );

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// P1: a terminal parent remains durable while an active child still points
/// at it, so restart/load cannot leave a dangling parent reference.
#[test]
fn prune_terminal_excludes_parents_with_active_children() {
    let root = temporary_root("prune-child-owner");
    let runner = storage_runner(&root);
    let db_name = "prune-child-owner.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    run_storage(
        &runner,
        db_name,
        "session-1",
        "session.create",
        session_payload("session-1", 2),
        2,
    );
    run_storage(
        &runner,
        db_name,
        "parent-create",
        "run.create",
        run_payload("parent-run", "session-1", 3),
        3,
    );
    run_storage(
        &runner,
        db_name,
        "parent-start",
        "run.transition",
        transition_payload("parent-run", "queued", "running", 4),
        4,
    );
    run_storage(
        &runner,
        db_name,
        "parent-complete",
        "run.transition",
        transition_payload("parent-run", "running", "completed", 5),
        5,
    );
    run_storage(
        &runner,
        db_name,
        "child-create",
        "run.create",
        json!({
            "id": "child-run",
            "session_id": "session-1",
            "parent_run_id": "parent-run",
            "input_json": "{\"message\":\"child\"}",
            "provider": "test-provider",
            "model": "test-model",
            "script_hash": "test-script",
            "idempotency_scope": "api:chat",
            "idempotency_key": "child-run",
            "now_ms": 6
        }),
        6,
    );
    run_storage(
        &runner,
        db_name,
        "child-start",
        "run.transition",
        transition_payload("child-run", "queued", "running", 7),
        7,
    );

    let pruned = run_storage(
        &runner,
        db_name,
        "prune-1",
        "runs.prune_terminal",
        json!({"older_than_ms": 100, "now_ms": 200, "max_rows": 32}),
        200,
    );
    assert_eq!(query_rows(&pruned).len(), 0);
    let parent = run_storage(
        &runner,
        db_name,
        "parent-get",
        "run.get",
        json!({"run_id": "parent-run"}),
        201,
    );
    assert_eq!(
        query_rows(&parent).len(),
        1,
        "active child keeps parent durable"
    );

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// P1-1 (RSS layer): load.all drains every page — more rows than a single
/// 512-row page and more bytes than a single page's byte budget are both
/// loaded completely, with no silent truncation.
#[test]
fn load_all_paginates_beyond_single_page_and_byte_limits() {
    let root = temporary_root("load-all");
    let runner = storage_runner(&root);
    let db_name = "load-all.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);

    // 600 sessions (more than one 512-row page) and one run with 600
    // messages + 600 events (more than one page each).
    let mut now_ms = 2;
    for index in 0..600 {
        run_storage(
            &runner,
            db_name,
            &format!("session-create-{index}"),
            "session.create",
            json!({
                "id": format!("session-{index:03}"),
                "profile": "default",
                "platform": "test",
                "account_id": format!("account-{index:03}"),
                "chat_id": format!("chat-{index:03}"),
                "thread_id": "",
                "user_id": "user-1",
                "generation": 1,
                "system_prompt": "",
                "model": "test-model",
                "provider": "test-provider",
                "toolset_hash": "test-tools",
                "metadata_json": "{}",
                "title": "",
                "end_reason": "",
                "now_ms": now_ms,
            }),
            now_ms,
        );
        now_ms += 1;
    }
    run_storage(
        &runner,
        db_name,
        "admission-1",
        "admission.create",
        json!({
            "session_id": "session-000",
            "session_new": 0,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "session-000",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "run_id": "run-1",
            "parent_run_id": "",
            "input_json": "{\"text\":\"hi\"}",
            "message_id": "message-admission",
            "message_run_id": "run-1",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "request_hash": "",
            "origin_actor": "",
            "event_id": "event-started-1",
            "now_ms": now_ms,
            "expires_at_ms": 0,
            "conversation_json": "",
        }),
        now_ms,
    );
    now_ms += 1;
    for ordinal in 1..=600 {
        run_storage(
            &runner,
            db_name,
            &format!("message-append-{ordinal}"),
            "message.append",
            message_payload(
                &format!("message-{ordinal:03}"),
                "session-000",
                ordinal,
                now_ms,
            ),
            now_ms,
        );
        now_ms += 1;
    }
    for seq in 2..=600 {
        run_storage(
            &runner,
            db_name,
            &format!("event-append-{seq}"),
            "event.append",
            event_payload(
                "run-1",
                &format!("event-{seq:03}"),
                "model.delta",
                now_ms,
                2048,
            ),
            now_ms,
        );
        now_ms += 1;
    }

    let loaded = run_storage(
        &runner,
        db_name,
        "load-all-1",
        "load.all",
        json!({
            "max_rows": 512,
            "max_bytes": 2 * 1024 * 1024,
            "load_cap": 1_000_000,
        }),
        now_ms,
    );
    assert_eq!(loaded["ok"], json!(true));
    let data = result_data(&loaded);
    let sessions = data["sessions"].as_array().expect("sessions rows");
    assert_eq!(sessions.len(), 600, "all sessions load across pages");
    let runs = data["runs"].as_array().expect("runs rows");
    assert_eq!(runs.len(), 1);
    let messages = data["messages"].as_array().expect("messages rows");
    assert_eq!(messages.len(), 601, "admission message + 600 appends");
    let events = data["events"].as_array().expect("events rows");
    assert_eq!(
        events.len(),
        600,
        "retained tail obeys the raised retention clamp (≥ 4096 stream chunks)"
    );
    // Row shapes: sessions carry the id first; events carry seq first.
    let session_first = sessions[0].as_array().expect("session row");
    assert_eq!(session_first[0], json!("session-000"));
    let event_first = events[0].as_array().expect("event row");
    assert_eq!(
        event_first[0],
        json!(1),
        "the full retained tail is served, starting at seq 1"
    );

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// P1-4 (RSS layer): session.delete cascades every dependent row in one
/// transaction, and jobs round-trip through the normalized table.
#[test]
fn session_delete_cascades_and_jobs_round_trip() {
    let root = temporary_root("delete-jobs");
    let runner = storage_runner(&root);
    let db_name = "delete-jobs.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);

    let job_create = run_storage(
        &runner,
        db_name,
        "job-create-1",
        "job.create",
        json!({
            "id": "job-1",
            "name": "nightly",
            "schedule_json": "{\"cron\":\"0 9 * * *\"}",
            "prompt": "run the agent",
            "deliver_json": "{\"channel\":\"telegram\"}",
            "skills_json": "[\"demo\"]",
            "repeat_count": 2,
            "enabled": 1,
            "now_ms": 2,
        }),
        2,
    );
    assert_eq!(job_create["ok"], json!(true));
    let job_row = first_query_row(&job_create);
    assert_eq!(job_row["id"], json!("job-1"));
    assert_eq!(job_row["name"], json!("nightly"));
    assert_eq!(job_row["enabled"], json!(1));

    let job_update = run_storage(
        &runner,
        db_name,
        "job-update-1",
        "job.update",
        json!({
            "id": "job-1",
            "name": "weekly",
            "schedule_json": "{}",
            "prompt": "updated",
            "deliver_json": "{}",
            "skills_json": "[]",
            "repeat_count": 0,
            "enabled": 0,
            "now_ms": 3,
        }),
        3,
    );
    assert_eq!(first_query_row(&job_update)["enabled"], json!(0));

    // Admission + terminal so the run has events and a child link candidate.
    run_storage(
        &runner,
        db_name,
        "admission-parent",
        "admission.create",
        json!({
            "session_id": "session-1",
            "session_new": 1,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "session-1",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "run_id": "parent-1",
            "parent_run_id": "",
            "input_json": "{\"text\":\"hi\"}",
            "message_id": "message-1",
            "message_run_id": "parent-1",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "key-1",
            "request_hash": "hash-1",
            "origin_actor": "",
            "event_id": "event-1",
            "now_ms": 4,
            "expires_at_ms": 0,
            "conversation_json": "",
        }),
        4,
    );
    run_storage(
        &runner,
        db_name,
        "admission-child",
        "admission.create",
        json!({
            "session_id": "session-1",
            "session_new": 0,
            "profile": "gateway",
            "platform": "api_server",
            "account_id": "session-1",
            "model": "m",
            "provider": "p",
            "system_prompt": "",
            "run_id": "child-1",
            "parent_run_id": "parent-1",
            "input_json": "{\"text\":\"child\"}",
            "message_id": "message-2",
            "message_run_id": "child-1",
            "script_hash": "s",
            "idempotency_scope": "api:chat",
            "idempotency_key": "",
            "request_hash": "",
            "origin_actor": "",
            "event_id": "event-2",
            "now_ms": 5,
            "expires_at_ms": 0,
            "conversation_json": "",
        }),
        5,
    );
    run_storage(
        &runner,
        db_name,
        "delivery-cursor-1",
        "delivery.advance",
        json!({
            "session_id": "session-1",
            "consumer": "sse",
            "event_seq": 1,
            "now_ms": 6,
        }),
        6,
    );

    let deleted = run_storage(
        &runner,
        db_name,
        "session-delete-1",
        "session.delete",
        json!({"session_id": "session-1"}),
        7,
    );
    assert_eq!(deleted["ok"], json!(true));

    let inspector = query_sql_runner(
        &root,
        "inspect-delete",
        &[
            "CREATE TABLE IF NOT EXISTS probe (n INTEGER)",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM sessions",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM runs",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM messages",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM run_events",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM child_run_links",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM delivery_cursors",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM idempotency_records",
            "INSERT INTO probe (n) SELECT COUNT(*) FROM jobs",
        ],
        "SELECT n FROM probe ORDER BY n",
    );
    let inspected = inspector
        .run_with_context(Value::map(vec![(
            Value::string("db_name"),
            Value::string(db_name),
        )]))
        .expect("delete inspection should run");
    let Value::Map(inspected) = inspected else {
        panic!("inspection should return a map");
    };
    let rows = vm_value_to_json(&Value::Map(inspected))["rows"]
        .as_array()
        .expect("inspection rows")
        .clone();
    // Probe rows are sorted ascending: seven zero counts (everything
    // session-scoped cascades, including run-scoped idempotency records)
    // then the jobs count, which is independent of sessions.
    assert_eq!(rows[0][0], json!(0), "session cascaded");
    assert_eq!(rows[1][0], json!(0), "runs cascaded");
    assert_eq!(rows[2][0], json!(0), "messages cascaded");
    assert_eq!(rows[3][0], json!(0), "events cascaded");
    assert_eq!(rows[4][0], json!(0), "child links cascaded");
    assert_eq!(rows[5][0], json!(0), "delivery cursors cascaded");
    assert_eq!(
        rows[6][0],
        json!(0),
        "idempotency records cascade with their runs"
    );
    assert_eq!(rows[7][0], json!(1), "jobs are independent of sessions");

    let job_list = run_storage(&runner, db_name, "job-list-1", "job.list", json!({}), 8);
    assert_eq!(query_rows(&job_list).len(), 1);
    let job_delete = run_storage(
        &runner,
        db_name,
        "job-delete-1",
        "job.delete",
        json!({"job_id": "job-1"}),
        9,
    );
    assert_eq!(job_delete["ok"], json!(true));

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// P2-1 (RSS layer): recovery reports how many runs it recovered so the
/// gateway can loop bounded batches until every active run is recovered
/// exactly once.
#[test]
fn recovery_reports_recovered_count_for_batched_loops() {
    let root = temporary_root("recovery-count");
    let runner = storage_runner(&root);
    let db_name = "recovery-count.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    run_storage(
        &runner,
        db_name,
        "session-create-1",
        "session.create",
        session_payload("session-1", 2),
        2,
    );
    for index in 0..3 {
        run_storage(
            &runner,
            db_name,
            &format!("run-create-{index}"),
            "run.create",
            run_payload(&format!("run-{index}"), "session-1", 3 + index),
            3 + index,
        );
    }
    let first = run_storage(
        &runner,
        db_name,
        "recovery-first",
        "recovery.recover_active",
        json!({
            "reason": "gateway_restart",
            "details_json": "{}",
            "now_ms": 10,
            "max_rows": 128,
            "max_bytes": 65_536,
            "max_events": 128,
        }),
        10,
    );
    assert_eq!(first["recovered"], json!(3));
    let second = run_storage(
        &runner,
        db_name,
        "recovery-second",
        "recovery.recover_active",
        json!({
            "reason": "gateway_restart",
            "details_json": "{}",
            "now_ms": 11,
            "max_rows": 128,
            "max_bytes": 65_536,
            "max_events": 128,
        }),
        11,
    );
    assert_eq!(second["recovered"], json!(0), "second recovery is a no-op");

    fs::remove_dir_all(root).expect("temporary storage root should be removed");
}

/// P3: `session.touch` must not no-op when the caller's payload carries a
/// generation that differs from the durable one (a compaction bumped it):
/// the touch is keyed by session id only, so a stale caller can never
/// silently lose an update.
#[test]
fn session_touch_is_not_a_noop_after_a_generation_bump() {
    let root = temporary_root("touch-generation");
    let runner = storage_runner(&root);
    let db_name = "touch-generation.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    run_storage(
        &runner,
        db_name,
        "session-create-1",
        "session.create",
        session_payload("session-1", 2),
        2,
    );
    // The durable session starts at generation 1; a caller with a stale
    // generation (for example after a compaction bumped it) touches again.
    let result = run_storage(
        &runner,
        db_name,
        "session-touch-1",
        "session.touch",
        json!({
            "session_id": "session-1",
            "status": "active",
            "generation": 7,
            "system_prompt": "updated",
            "model": "test-model",
            "provider": "test-provider",
            "toolset_hash": "test-tools",
            "metadata_json": "{}",
            "title": "touched",
            "end_reason": "",
            "now_ms": 100,
        }),
        100,
    );
    let row = first_query_row(&result);
    assert_eq!(
        row["updated_at_ms"],
        json!(100),
        "the touch must land regardless of the caller's generation"
    );
    assert_eq!(row["title"], json!("touched"));
    assert_eq!(row["system_prompt"], json!("updated"));
    fs::remove_dir_all(root).expect("temporary root should be removed");
}

/// P3: the hard 1M-row load cap is a parameterized command bound: a load
/// over the configured cap fails with the typed `load_too_large` error
/// instead of silently truncating, and a load under the cap succeeds.
#[test]
fn load_all_enforces_a_parameterized_load_cap() {
    let root = temporary_root("load-cap");
    let runner = storage_runner(&root);
    let db_name = "load-cap.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    let mut now_ms = 2;
    for index in 0..12 {
        run_storage(
            &runner,
            db_name,
            &format!("session-create-{index}"),
            "session.create",
            json!({
                "id": format!("cap-session-{index:02}"),
                "profile": "default",
                "platform": "test",
                "account_id": format!("account-{index:02}"),
                "chat_id": format!("chat-{index:02}"),
                "thread_id": "",
                "user_id": "user-1",
                "generation": 1,
                "system_prompt": "",
                "model": "test-model",
                "provider": "test-provider",
                "toolset_hash": "test-tools",
                "metadata_json": "{}",
                "title": "",
                "end_reason": "",
                "now_ms": now_ms,
            }),
            now_ms,
        );
        now_ms += 1;
    }
    let overloaded = run_storage(
        &runner,
        db_name,
        "load-cap-small",
        "load.all",
        json!({
            "max_rows": 512,
            "max_bytes": 2 * 1024 * 1024,
            "load_cap": 4,
        }),
        now_ms,
    );
    assert_eq!(
        overloaded["ok"],
        json!(false),
        "a load over the cap must be rejected, got: {overloaded}"
    );
    assert_eq!(
        overloaded["code"],
        json!("load_too_large"),
        "the rejection must be typed, got: {overloaded}"
    );
    let ok = run_storage(
        &runner,
        db_name,
        "load-cap-large",
        "load.all",
        json!({
            "max_rows": 512,
            "max_bytes": 2 * 1024 * 1024,
            "load_cap": 100,
        }),
        now_ms,
    );
    assert_eq!(ok["ok"], json!(true), "a load under the cap must succeed");
    fs::remove_dir_all(root).expect("temporary root should be removed");
}

/// P3: `job.delete` reports the real durable `rows_affected`: deleting an
/// existing job reports 1, deleting a missing job reports 0 (never a
/// hardcoded success).
#[test]
fn job_delete_reports_real_rows_affected() {
    let root = temporary_root("job-delete");
    let runner = storage_runner(&root);
    let db_name = "job-delete.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    run_storage(
        &runner,
        db_name,
        "job-create-1",
        "job.create",
        json!({
            "id": "job-1",
            "name": "nightly",
            "schedule_json": "{}",
            "prompt": "run",
            "deliver_json": "{}",
            "skills_json": "[]",
            "repeat_count": 0,
            "enabled": 1,
            "now_ms": 2,
        }),
        2,
    );
    let deleted = run_storage(
        &runner,
        db_name,
        "job-delete-1",
        "job.delete",
        json!({"job_id": "job-1"}),
        3,
    );
    assert_eq!(
        deleted["ok"],
        json!(true),
        "deleting an existing job must succeed"
    );
    assert_eq!(
        deleted["rows_affected"],
        json!(1),
        "the first delete must report one affected row, got: {deleted}"
    );
    let missing = run_storage(
        &runner,
        db_name,
        "job-delete-2",
        "job.delete",
        json!({"job_id": "job-1"}),
        4,
    );
    assert_eq!(
        missing["rows_affected"],
        json!(0),
        "deleting a missing job must report zero affected rows, got: {missing}"
    );
    fs::remove_dir_all(root).expect("temporary root should be removed");
}

#[test]
fn delivery_set_is_monotonic_and_unvalidated() {
    let root = temporary_root("delivery-set");
    let runner = storage_runner(&root);
    let db_name = "delivery-set.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    run_storage(
        &runner,
        db_name,
        "session-create-1",
        "session.create",
        session_payload("session-1", 2),
        2,
    );

    // `delivery.advance` validates the value against the session's event
    // high-water (no runs yet -> 0), so transport-level cursors like the
    // Telegram getUpdates offset cannot use it.
    let rejected = run_storage(
        &runner,
        db_name,
        "advance-rejected",
        "delivery.advance",
        json!({
            "session_id": "session-1",
            "consumer": "telegram:offset",
            "event_seq": 42,
            "now_ms": 3,
        }),
        3,
    );
    assert_eq!(
        rejected["ok"],
        json!(true),
        "advance no-ops above the high-water instead of erroring"
    );
    assert_eq!(
        rejected["rows_affected"],
        json!(0),
        "advance must not persist a value above the session high-water"
    );

    // `delivery.set` is the sibling command for unvalidated monotonic
    // cursors (poll offsets, session generations).
    run_storage(
        &runner,
        db_name,
        "set-1",
        "delivery.set",
        json!({
            "session_id": "session-1",
            "consumer": "telegram:offset",
            "event_seq": 42,
            "now_ms": 4,
        }),
        4,
    );
    run_storage(
        &runner,
        db_name,
        "set-2",
        "delivery.set",
        json!({
            "session_id": "session-1",
            "consumer": "telegram:offset",
            "event_seq": 7,
            "now_ms": 5,
        }),
        5,
    );
    run_storage(
        &runner,
        db_name,
        "set-3",
        "delivery.set",
        json!({
            "session_id": "session-1",
            "consumer": "telegram:offset",
            "event_seq": 5,
            "now_ms": 6,
        }),
        6,
    );
    let read = run_storage(
        &runner,
        db_name,
        "get-1",
        "delivery.get",
        json!({ "session_id": "session-1", "consumer": "telegram:offset" }),
        7,
    );
    assert_eq!(read["ok"], json!(true));
    let rows = read["data"]["rows"].as_array().expect("cursor rows");
    assert_eq!(rows.len(), 1, "one cursor row per (session, consumer)");
    assert_eq!(rows[0][1], json!("telegram:offset"));
    assert_eq!(
        rows[0][2],
        json!(42),
        "delivery.set must be monotonic: 7 then 5 must leave 42"
    );
    fs::remove_dir_all(root).expect("temporary root should be removed");
}

/// P3 (RSS layer): `runs.prune_terminal` is the janitor's bounded durable
/// retention sweep. It deletes ONLY terminal runs (completed/failed/
/// cancelled) whose `updated_at_ms` is older than the window, cascading
/// their events/retention/idempotency records. Active and `terminal_pending`
/// runs are never matched, so restart replay and the terminal retry loop
/// stay intact.
#[test]
fn runs_prune_terminal_reclaims_only_old_terminal_runs() {
    let root = temporary_root("prune-terminal");
    let runner = storage_runner(&root);
    let db_name = "prune-terminal.db";
    run_storage(&runner, db_name, "migrate-1", "migrate", json!({}), 1);
    let admission = |run_id: &str, now_ms: i64| {
        run_storage(
            &runner,
            db_name,
            &format!("admission-{run_id}"),
            "admission.create",
            json!({
                "session_id": "session-1",
                "session_new": 1,
                "profile": "gateway",
                "platform": "api_server",
                "account_id": "session-1",
                "model": "m",
                "provider": "p",
                "system_prompt": "",
                "run_id": run_id,
                "parent_run_id": "",
                "input_json": "{\"text\":\"hi\"}",
                "message_id": format!("message-{run_id}"),
                "message_run_id": run_id,
                "script_hash": "s",
                "idempotency_scope": "api:chat",
                "idempotency_key": "",
                "request_hash": "",
                "origin_actor": "",
                "event_id": format!("event-started-{run_id}"),
                "now_ms": now_ms,
                "expires_at_ms": 0,
                "conversation_json": "",
            }),
            now_ms,
        );
    };
    let terminal = |run_id: &str, to_status: &str, now_ms: i64| {
        run_storage(
            &runner,
            db_name,
            &format!("terminal-{run_id}"),
            "run.terminal",
            json!({
                "run_id": run_id,
                "to_status": to_status,
                "error_code": "",
                "error_message": "",
                "event_1_id": format!("event-terminal-{run_id}"),
                "event_1_type": "run.completed",
                "event_1_payload": "{\"status\":\"completed\"}",
                "event_2_id": "",
                "event_2_type": "",
                "event_2_payload": "",
                "event_count": 1,
                "message_id": "",
                "message_session_id": "",
                "message_role": "",
                "message_content_json": "",
                "message_run_id": "",
                "message_finish_reason": "",
                "now_ms": now_ms,
            }),
            now_ms,
        );
    };

    admission("old-terminal", 100);
    terminal("old-terminal", "completed", 200);
    admission("recent-terminal", 1000);
    terminal("recent-terminal", "completed", 1100);
    // Active run: NEVER matched by the sweep.
    admission("active", 2000);
    // waiting_approval run (a parked run the retry loop owns): NEVER
    // matched.
    admission("pending", 3000);
    run_storage(
        &runner,
        db_name,
        "pending-transition",
        "run.transition",
        transition_payload("pending", "running", "waiting_approval", 3100),
        3100,
    );

    // Window boundary: reclaims everything older than 1000 ms.
    let old_before = run_storage(
        &runner,
        db_name,
        "old-before",
        "run.get",
        json!({"run_id": "old-terminal"}),
        900,
    );
    assert_eq!(
        old_before["ok"],
        json!(true),
        "old terminal exists before prune: {old_before}"
    );
    assert_eq!(
        old_before["data"]["rows"][0][3],
        json!("completed"),
        "old terminal status: {old_before}"
    );
    let pruned = run_storage(
        &runner,
        db_name,
        "prune-1",
        "runs.prune_terminal",
        json!({
            "older_than_ms": 1000,
            "now_ms": 10_000,
            "max_rows": 64,
        }),
        10_000,
    );
    assert_eq!(pruned["ok"], json!(true), "prune must succeed: {pruned}");
    assert_eq!(
        pruned["data"]["rows"].as_array().map(Vec::len),
        Some(1),
        "exactly the old terminal run must be reclaimed, got: {pruned}"
    );
    let deleted = pruned["data"]["rows"]
        .as_array()
        .expect("deleted run ids")
        .iter()
        .filter_map(|row| {
            row.as_array()
                .and_then(|row| row.first().and_then(JsonValue::as_str))
        })
        .collect::<Vec<_>>();
    assert!(
        deleted.contains(&"old-terminal"),
        "the old terminal run must be reclaimed, got {deleted:?}"
    );
    assert!(
        !deleted.contains(&"recent-terminal"),
        "the recent terminal run must survive, got {deleted:?}"
    );
    assert!(
        !deleted.contains(&"active") && !deleted.contains(&"pending"),
        "active and terminal_pending runs must never be pruned, got {deleted:?}"
    );

    // Cascades: the old run's events/retention/idempotency are gone with it.
    let old_get = run_storage(
        &runner,
        db_name,
        "old-get",
        "run.get",
        json!({"run_id": "old-terminal"}),
        10_001,
    );
    assert_eq!(
        old_get["data"]["rows"].as_array().map(Vec::len),
        Some(0),
        "the old terminal run must be gone: {old_get}"
    );
    let recent_get = run_storage(
        &runner,
        db_name,
        "recent-get",
        "run.get",
        json!({"run_id": "recent-terminal"}),
        10_002,
    );
    assert_eq!(recent_get["ok"], json!(true));

    // A second sweep with an older boundary is a bounded no-op.
    let again = run_storage(
        &runner,
        db_name,
        "prune-2",
        "runs.prune_terminal",
        json!({
            "older_than_ms": 10_000,
            "now_ms": 10_000,
            "max_rows": 64,
        }),
        10_000,
    );
    assert_eq!(again["ok"], json!(true));
    let again_deleted = again["data"]["rows"].as_array().map(Vec::len).unwrap_or(0);
    assert_eq!(
        again_deleted, 1,
        "only the old terminal run was already reclaimed"
    );

    fs::remove_dir_all(root).expect("temporary root should be removed");
}
