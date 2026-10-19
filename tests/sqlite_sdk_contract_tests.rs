//! Formal Agent SQLite contract for the pinned SDK.
//!
//! These cases use the same `AgentConfig` construction as production
//! `GatewayPersistence`: gateway HTTP/SQLite policy and fuel, plus the
//! database root. They do not install a private runtime, open a Rust SQLite
//! connection, or read database bytes. Schema version 7 and checkpoint
//! restore are outside this contract.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rustscript_agent::{AgentConfig, AgentGatewayConfig, AgentRunner};
use rustscript_vm::Value;

const REVISION_TRIGGER: &str = "CREATE TRIGGER revision_insert AFTER INSERT ON messages BEGIN UPDATE revisions SET revision=revision+1; END";
const TRIGGER_TAIL: &str = "CREATE TRIGGER revision_insert AFTER INSERT ON messages BEGIN UPDATE revisions SET revision=revision+1; END; DROP TABLE messages";
const MULTIPLE_SELECTS: &str = "SELECT 1; SELECT 2";

fn private_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the Unix epoch")
        .as_nanos();
    let root =
        PathBuf::from(std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("required test root"))
            .join(format!("{label}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root).expect("private fixture root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private fixture mode");
    root
}

fn persistence_config(root: &Path) -> AgentConfig {
    let gateway = AgentGatewayConfig::default();
    assert!(
        !gateway.sqlite.allow_unsafe_sql,
        "production persistence policy must keep unsafe SQL disabled"
    );
    AgentConfig {
        http: gateway.http,
        sqlite: gateway.sqlite,
        fuel: gateway.fuel,
    }
    .with_sqlite_root(root)
}

fn run_int(root: &Path, database: &str, source: &str) -> Result<i64, String> {
    let runner = AgentRunner::from_source(source, persistence_config(root))
        .map_err(|error| format!("compile: {error}"))?;
    match runner.run_with_context(Value::string(database)) {
        Ok(Value::Int(value)) => Ok(value),
        Ok(other) => Err(format!("unexpected result {other:?}")),
        Err(error) => Err(error.to_string()),
    }
}

fn execute_trigger_source() -> String {
    format!(
        r#"use sqlite;
pub fn run(path: string) -> int {{
    let db = sqlite::open({{ path: path, mode: "read_write_create" }});
    sqlite::execute(&db, "CREATE TABLE messages (id INTEGER)", []);
    sqlite::execute(&db, "CREATE TABLE revisions (revision INTEGER)", []);
    sqlite::execute(&db, "INSERT INTO revisions VALUES (0)", []);
    sqlite::execute(&db, "{REVISION_TRIGGER}", []);
    sqlite::execute(&db, "INSERT INTO messages VALUES (1)", []);
    let result = sqlite::query(&db, "SELECT revision FROM revisions", [], {{}});
    let revision = result.rows.copy()[0].cells.copy()[0].int_value;
    sqlite::close(db);
    revision
}}
"#
    )
}

fn transaction_trigger_source() -> String {
    format!(
        r#"use sqlite;
pub fn run(path: string) -> int {{
    let db = sqlite::open({{ path: path, mode: "read_write_create" }});
    let results = sqlite::transaction(&db, [
        {{ sql: "CREATE TABLE messages (id INTEGER)", params: [], query: false, limits: {{}} }},
        {{ sql: "CREATE TABLE revisions (revision INTEGER)", params: [], query: false, limits: {{}} }},
        {{ sql: "INSERT INTO revisions VALUES (0)", params: [], query: false, limits: {{}} }},
        {{ sql: "{REVISION_TRIGGER}", params: [], query: false, limits: {{}} }},
        {{ sql: "INSERT INTO messages VALUES (1)", params: [], query: false, limits: {{}} }},
        {{ sql: "SELECT revision FROM revisions", params: [], query: true, limits: {{}} }}
    ]);
    let last: SqliteTransactionResult = results[5].copy();
    let queried: SqliteQueryResult = last.query;
    let observed = queried.rows.copy()[0].cells.copy()[0].int_value;
    let committed = sqlite::query(&db, "SELECT revision FROM revisions", [], {{}});
    let durable = committed.rows.copy()[0].cells.copy()[0].int_value;
    sqlite::close(db);
    if observed == durable => {{ observed }} else => {{ -1 }}
}}
"#
    )
}

fn schema_source() -> &'static str {
    r#"use sqlite;
pub fn run(path: string) -> int {
    let db = sqlite::open({ path: path, mode: "read_write_create" });
    sqlite::execute(&db, "CREATE TABLE messages (id INTEGER)", []);
    sqlite::execute(&db, "CREATE TABLE revisions (revision INTEGER)", []);
    sqlite::execute(&db, "INSERT INTO revisions VALUES (0)", []);
    sqlite::close(db);
    0
}
"#
}

fn execute_tail_source() -> String {
    format!(
        r#"use sqlite;
pub fn run(path: string) -> int {{
    let db = sqlite::open({{ path: path, mode: "read_write" }});
    sqlite::execute(&db, "{TRIGGER_TAIL}", []);
    sqlite::close(db);
    1
}}
"#
    )
}

fn transaction_tail_source() -> String {
    format!(
        r#"use sqlite;
pub fn run(path: string) -> int {{
    let db = sqlite::open({{ path: path, mode: "read_write" }});
    sqlite::transaction(&db, [
        {{ sql: "{TRIGGER_TAIL}", params: [], query: false, limits: {{}} }}
    ]);
    sqlite::close(db);
    1
}}
"#
    )
}

fn residue_source() -> &'static str {
    r#"use sqlite;
pub fn run(path: string) -> int {
    let db = sqlite::open({ path: path, mode: "read_write" });
    let triggers = sqlite::query(&db, "SELECT count(*) FROM sqlite_schema WHERE type='trigger'", [], {});
    let rows = sqlite::query(&db, "SELECT count(*) FROM messages", [], {});
    let revision = sqlite::query(&db, "SELECT revision FROM revisions", [], {});
    let trigger_count = triggers.rows.copy()[0].cells.copy()[0].int_value;
    let row_count = rows.rows.copy()[0].cells.copy()[0].int_value;
    let revision_value = revision.rows.copy()[0].cells.copy()[0].int_value;
    sqlite::close(db);
    trigger_count * 100 + row_count * 10 + revision_value
}
"#
}

fn query_selects_source() -> String {
    format!(
        r#"use sqlite;
pub fn run(path: string) -> int {{
    let db = sqlite::open({{ path: path, mode: "read_write_create" }});
    sqlite::query(&db, "{MULTIPLE_SELECTS}", [], {{}});
    sqlite::close(db);
    1
}}
"#
    )
}

fn transaction_selects_source() -> String {
    format!(
        r#"use sqlite;
pub fn run(path: string) -> int {{
    let db = sqlite::open({{ path: path, mode: "read_write_create" }});
    sqlite::transaction(&db, [
        {{ sql: "{MULTIPLE_SELECTS}", params: [], query: true, limits: {{}} }}
    ]);
    sqlite::close(db);
    1
}}
"#
    )
}

fn ordinary_select_source() -> &'static str {
    r#"use sqlite;
pub fn run(path: string) -> int {
    let db = sqlite::open({ path: path, mode: "read_write_create" });
    let result = sqlite::query(&db, "SELECT 1", [], {});
    let value = result.rows.copy()[0].cells.copy()[0].int_value;
    sqlite::close(db);
    value
}
"#
}

fn expect_multiple_statements(error: &str) {
    assert!(
        error.contains("multiple SQLite statements are not allowed"),
        "{error}"
    );
}

#[test]
fn formal_sdk_execute_trigger_updates_revision() {
    let root = private_root("sdk-execute-trigger");
    let revision = run_int(&root, "execute.sqlite", &execute_trigger_source())
        .expect("one legal trigger must execute, fire, and return the stored revision");
    assert_eq!(
        revision, 1,
        "insert must update the stored revision through the trigger"
    );
}

#[test]
fn formal_sdk_transaction_trigger_updates_revision() {
    let root = private_root("sdk-transaction-trigger");
    let revision = run_int(&root, "transaction.sqlite", &transaction_trigger_source())
        .expect("schema-dependent trigger transaction must commit and return the stored revision");
    assert_eq!(
        revision, 1,
        "transaction insert must update the stored revision, matching the committed query"
    );
}

fn reject_tail(label: &str, source: &str) {
    let root = private_root(label);
    let prepared = run_int(&root, "fixture.sqlite", schema_source()).expect("schema setup");
    assert_eq!(prepared, 0);
    let rejected =
        run_int(&root, "fixture.sqlite", source).expect_err("trigger tail must be rejected");
    expect_multiple_statements(&rejected);
    let residue = run_int(&root, "fixture.sqlite", residue_source()).expect("residue query");
    assert_eq!(
        residue, 0,
        "rejected tail must not create a trigger, drop the table, or change revision"
    );
}

#[test]
fn formal_sdk_execute_rejects_trigger_tail_without_partial_ddl() {
    reject_tail("sdk-execute-tail", &execute_tail_source());
}

#[test]
fn formal_sdk_transaction_rejects_trigger_tail_without_partial_ddl() {
    reject_tail("sdk-transaction-tail", &transaction_tail_source());
}

fn reject_selects(label: &str, source: &str) {
    let root = private_root(label);
    let rejected =
        run_int(&root, "selects.sqlite", source).expect_err("two selects must be rejected");
    expect_multiple_statements(&rejected);
    let ordinary =
        run_int(&root, "selects.sqlite", ordinary_select_source()).expect("ordinary select");
    assert_eq!(
        ordinary, 1,
        "rejecting two selects must leave a single select unchanged"
    );
}

#[test]
fn formal_sdk_query_rejects_multiple_selects_without_rows() {
    reject_selects("sdk-query-selects", &query_selects_source());
}

#[test]
fn formal_sdk_transaction_rejects_multiple_selects_without_rows() {
    reject_selects("sdk-transaction-selects", &transaction_selects_source());
}
