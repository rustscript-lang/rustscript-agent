use super::*;

#[test]
fn bounded_context_packed_transport_rejects_incomplete_markers_and_layout() {
    let root = temporary_root("bounded-context-packed-layout");
    let db = "layout.db";
    let normal = storage_runner(&root);
    seed_session_and_run(&normal, db, "session-1", "run-1", 10);
    seed_history(&root, db, 1);
    for (label, before, after) in [
        ("header", "NULL AS c18", "NULL AS wrong_header"),
        (
            "tag",
            "SELECT 2, context_page.*",
            "SELECT 9, context_page.*",
        ),
        (
            "padding",
            "context_page.*, NULL, NULL, NULL, NULL, NULL",
            "context_page.*, 'bad', NULL, NULL, NULL, NULL",
        ),
        (
            "incomplete",
            "SELECT * FROM context_packed ORDER BY",
            "SELECT * FROM context_packed WHERE context_tag <> 4 ORDER BY",
        ),
        ("count", "m AS c1", "(m+1) AS c1"),
        ("marker", "(m < ?) AS c3", "(m >= ?) AS c3"),
        (
            "width",
            "SELECT * FROM context_packed ORDER BY",
            "SELECT *, 1 AS extra FROM context_packed ORDER BY",
        ),
        (
            "type",
            "SELECT 2, context_page.*",
            "SELECT '2', context_page.*",
        ),
        (
            "cursor",
            "storage_context_unpack(packed, command)",
            "let packed: SqliteQueryResult = {columns: packed.columns, rows: packed.rows, truncated: packed.truncated, next_cursor: 1}; storage_context_unpack(packed, command)",
        ),
    ] {
        let malformed = context_fixture_runner(&root, |source| {
            assert_eq!(source.matches(before).count(), 1, "{label}");
            source.replacen(before, after, 1)
        });
        let result = context(&malformed, db, "session-1");
        assert_eq!(result["ok"], false, "{label}: {result}");
        assert_eq!(result["code"], "snapshot_invalid", "{label}: {result}");
    }
    assert_eq!(context(&normal, db, "session-1")["ok"], true);
    fs::remove_dir_all(root).unwrap();
}

fn shipping_command(db: &str, op: &str) -> Value {
    // Production command budgets, without changing the lower-bound fixtures.
    Value::map(vec![
        (Value::string("op"), Value::string(op)),
        (Value::string("request_id"), Value::string("packed-budget")),
        (Value::string("db_path"), Value::string(db)),
        (Value::string("db_mode"), Value::string("read_write_create")),
        (Value::string("busy_timeout_ms"), Value::Int(5_000)),
        (Value::string("max_rows"), Value::Int(512)),
        (Value::string("max_bytes"), Value::Int(2_097_152)),
        (Value::string("max_events"), Value::Int(128)),
        (Value::string("max_messages"), Value::Int(128)),
        (Value::string("now_ms"), Value::Int(20)),
        (
            Value::string("payload_json"),
            Value::string(if op == "message.list" {
                json!({"session_id":"session-1", "after_ordinal":0}).to_string()
            } else {
                json!({"session_id":"session-1"}).to_string()
            }),
        ),
    ])
}

fn shipping_query(runner: &AgentRunner, db: &str, op: &str) -> JsonValue {
    vm_value_to_json(&runner.run_with_context(shipping_command(db, op)).unwrap())
}

#[test]
fn bounded_context_packed_aggregate_keeps_shipping_two_mib_limit() {
    let root = temporary_root("bounded-context-packed-bytes");
    let db = "aggregate.db";
    let normal = storage_runner(&root);
    seed_session_and_run(&normal, db, "session-1", "run-1", 10);
    seed_history(&root, db, 100);
    run_raw_sql(
        &raw_sql_runner(
            &root,
            "aggregate-large",
            &[
                "UPDATE messages SET content_json=json_array(json_object('type','text','text',replace(hex(zeroblob(6000)),'0','a')))",
                "INSERT INTO compactions (id,session_id,run_id,generation,source_start_ordinal,source_end_ordinal,retained_tail_ordinal,summary_json,state,created_at_ms) VALUES ('summary','session-1','run-1',2,1,100,100,json_object('text',replace(hex(zeroblob(500000)),'0','a')),'committed',20)",
            ],
        ),
        db,
    );
    // Each former standalone query fits; only their combined native result is
    // over budget. The packed route explicitly fails, with no legacy retry.
    for op in ["message.list", "compaction.latest"] {
        let result = shipping_query(&normal, db, op);
        assert_eq!(result["ok"], true, "{op}");
        assert_eq!(result["data"]["truncated"], false, "{op}");
    }
    let result = shipping_query(&normal, db, "compaction.context");
    assert_eq!(result["ok"], false);
    assert_eq!(result["code"], "snapshot_too_large");
    run_raw_sql(
        &raw_sql_runner(
            &root,
            "aggregate-small",
            &["UPDATE compactions SET summary_json='{}'"],
        ),
        db,
    );
    let small = shipping_query(&normal, db, "compaction.context");
    assert_eq!(small["ok"], true, "{small}");
    assert_eq!(rows(&small["data"]["messages"]).len(), 100);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bounded_context_packed_aggregate_keeps_shipping_512_row_limit() {
    let root = temporary_root("bounded-context-packed-rows");
    let db = "rows.db";
    let normal = storage_runner(&root);
    seed_session_and_run(&normal, db, "session-1", "run-1", 10);
    run_raw_sql(
        &raw_sql_runner(
            &root,
            "aggregate-many-summaries",
            &[
                "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<510) INSERT INTO compactions (id,session_id,run_id,generation,source_start_ordinal,source_end_ordinal,retained_tail_ordinal,summary_json,state,created_at_ms) SELECT 'summary-'||x,'session-1','run-1',x,1,1,1,'{}','committed',x FROM n",
            ],
        ),
        db,
    );
    let standalone = shipping_query(&normal, db, "compaction.latest");
    assert_eq!(rows(&standalone["data"]).len(), 510);
    assert_eq!(standalone["data"]["truncated"], false);
    let result = shipping_query(&normal, db, "compaction.context");
    assert_eq!(result["ok"], false);
    assert_eq!(result["code"], "snapshot_too_large");
    run_raw_sql(
        &raw_sql_runner(
            &root,
            "aggregate-remove-one",
            &["DELETE FROM compactions WHERE generation=510"],
        ),
        db,
    );
    let exact = shipping_query(&normal, db, "compaction.context");
    assert_eq!(exact["ok"], true, "{exact}");
    let latest = rows(&exact["data"]["latest"]);
    assert_eq!(latest.len(), 509);
    assert_eq!(latest[0][3], 509);
    assert_eq!(latest[508][3], 1);
    fs::remove_dir_all(root).unwrap();
}
