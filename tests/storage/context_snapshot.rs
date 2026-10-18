use super::*;

#[path = "context_snapshot_lifecycle.rs"]
mod lifecycle;

fn rows(data: &JsonValue) -> Vec<Vec<JsonValue>> {
    rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(data).unwrap()
}

fn context(runner: &AgentRunner, db: &str, session: &str) -> JsonValue {
    run_storage(
        runner,
        db,
        "context",
        "compaction.context",
        json!({"session_id": session}),
        20,
    )
}

fn seed_history(root: &std::path::Path, db: &str, count: usize) {
    let sql = format!(
        "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x < {count}) INSERT INTO messages (id, session_id, ordinal, role, content_json, name, tool_call_id, parent_message_id, token_estimate, metadata_json, created_at_ms, run_id, finish_reason) SELECT 'message-'||x, 'session-1', x, CASE WHEN x%2=0 THEN 'assistant' ELSE 'user' END, json_object('text', 'fact-'||x), '', '', '', 1, '{{}}', x, '', '' FROM n WHERE x > COALESCE((SELECT MAX(ordinal) FROM messages WHERE session_id='session-1'),0)"
    );
    run_raw_sql(&raw_sql_runner(root, "seed-context-history", &[&sql]), db);
}

#[test]
fn bounded_context_matches_legacy_pages_at_128_129_256_257() {
    let root = temporary_root("bounded-context-pages");
    let db = "context.db";
    let runner = storage_runner(&root);
    seed_session_and_run(&runner, db, "session-1", "run-1", 10);
    for count in [0, 1, 127, 128, 129, 256, 257] {
        if count > 0 {
            seed_history(&root, db, count);
        }
        let snapshot = context(&runner, db, "session-1");
        assert_eq!(snapshot["ok"], true, "{snapshot}");
        let data = &snapshot["data"];
        assert_eq!(data["summary_loaded"], count < 128);
        let old_session = run_storage(
            &runner,
            db,
            "session",
            "session.get",
            json!({"session_id":"session-1"}),
            20,
        );
        assert_eq!(rows(&data["session"]), rows(&old_session["data"]));
        let old_page = run_storage(
            &runner,
            db,
            "page",
            "message.list",
            json!({"session_id":"session-1", "after_ordinal":0}),
            20,
        );
        assert_eq!(rows(&data["messages"]), rows(&old_page["data"]));
        assert_eq!(rows(&data["messages"]).len(), count.min(128));
        assert!(rows(&data["latest"]).is_empty());
        let mut collected = rows(&data["messages"]);
        while collected.len() < count {
            let cursor = collected.last().unwrap()[2].as_i64().unwrap();
            let next = run_storage(
                &runner,
                db,
                "continue",
                "message.list",
                json!({"session_id":"session-1", "after_ordinal":cursor}),
                20,
            );
            collected.extend(rows(&next["data"]));
        }
        assert_eq!(collected.len(), count);
        for (index, row) in collected.iter().enumerate() {
            assert_eq!(row[0], format!("message-{}", index + 1));
            assert_eq!(row[2], (index + 1) as i64);
            assert_eq!(
                serde_json::from_str::<JsonValue>(row[4].as_str().unwrap()).unwrap(),
                json!([{"type":"text", "text":format!("fact-{}",index+1)}])
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bounded_context_empty_missing_and_cross_session_filter() {
    let root = temporary_root("bounded-context-filter");
    let runner = storage_runner(&root);
    let db = "filter.db";
    seed_session_and_run(&runner, db, "session-1", "run-1", 10);
    let mut foreign = session_payload("foreign-session", 11);
    foreign["chat_id"] = json!("foreign-chat");
    run_storage(
        &runner,
        db,
        "foreign-session",
        "session.create",
        foreign,
        11,
    );
    run_storage(
        &runner,
        db,
        "foreign-message",
        "message.append",
        message_payload("foreign-message", "foreign-session", 1, 12),
        12,
    );
    let empty = context(&runner, db, "session-1");
    assert_eq!(empty["ok"], true);
    assert_eq!(empty["data"]["summary_loaded"], true);
    assert!(rows(&empty["data"]["messages"]).is_empty());
    assert!(rows(&empty["data"]["latest"]).is_empty());
    for missing in ["missing", "session-1' OR 1=1 --"] {
        let result = context(&runner, db, missing);
        assert_eq!(result["ok"], false);
        assert_eq!(result["code"], "session_not_found");
    }
    let own = context(&runner, db, "foreign-session");
    assert_eq!(rows(&own["data"]["messages"])[0][0], "foreign-message");
    assert!(rows(&context(&runner, db, "session-1")["data"]["messages"]).is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bounded_context_never_selects_large_premature_summary_at_full_page() {
    let root = temporary_root("bounded-context-summary-gate");
    let runner = storage_runner(&root);
    let db = "gate.db";
    seed_session_and_run(&runner, db, "session-1", "run-1", 10);
    seed_history(&root, db, 128);
    run_raw_sql(
        &raw_sql_runner(
            &root,
            "large-summary",
            &[
                "INSERT INTO compactions (id,session_id,run_id,generation,source_start_ordinal,source_end_ordinal,retained_tail_ordinal,summary_json,state,created_at_ms) VALUES ('summary','session-1','run-1',2,1,128,128,json_object('text',replace(hex(zeroblob(40000)),'0','a')),'committed',20)",
            ],
        ),
        db,
    );
    let full = context(&runner, db, "session-1");
    assert_eq!(full["ok"], true, "{full}");
    assert_eq!(full["data"]["summary_loaded"], false);
    assert!(rows(&full["data"]["latest"]).is_empty());
    run_raw_sql(
        &raw_sql_runner(
            &root,
            "shorten-history",
            &["DELETE FROM messages WHERE ordinal=128"],
        ),
        db,
    );
    let small = context(&runner, db, "session-1");
    assert_eq!(small["ok"], false, "{small}");
    assert_eq!(small["code"], "snapshot_too_large");
    let session = run_storage(
        &runner,
        db,
        "after-bound",
        "session.get",
        json!({"session_id":"session-1"}),
        20,
    );
    assert_eq!(session["ok"], true);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bounded_context_rejects_byte_truncation_then_releases_database() {
    let root = temporary_root("bounded-context-byte-bound");
    let runner = storage_runner(&root);
    let db = "bytes.db";
    seed_session_and_run(&runner, db, "session-1", "run-1", 10);
    seed_history(&root, db, 25);
    run_raw_sql(
        &raw_sql_runner(
            &root,
            "large-messages",
            &[
                "UPDATE messages SET content_json=json_array(json_object('type','text','text',replace(hex(zeroblob(3000)),'0','a')))",
            ],
        ),
        db,
    );
    let result = context(&runner, db, "session-1");
    assert_eq!(result["ok"], false, "{result}");
    assert_eq!(result["code"], "snapshot_too_large");
    run_raw_sql(
        &raw_sql_runner(
            &root,
            "small-again",
            &["UPDATE messages SET content_json='[]'"],
        ),
        db,
    );
    assert_eq!(context(&runner, db, "session-1")["ok"], true);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bounded_context_payload_is_typed_and_cannot_override_authority() {
    let root = temporary_root("bounded-context-typed-payload");
    let runner = storage_runner(&root);
    let db = "typed.db";
    seed_session_and_run(&runner, db, "session-1", "run-1", 10);
    for payload in [
        json!({}),
        json!({"session_id":7}),
        json!({"session_id":"session-1", "db_path":"foreign.db"}),
        json!({"session_id":"session-1", "op":"session.delete"}),
    ] {
        let result = run_storage_result(
            &runner,
            db,
            "invalid",
            "compaction.context",
            payload.clone(),
            20,
        );
        assert!(
            !result.as_ref().is_ok_and(|value| value["ok"] == true),
            "payload must fail closed: {payload}: {result:?}"
        );
    }
    assert_eq!(context(&runner, db, "session-1")["ok"], true);
    fs::remove_dir_all(root).unwrap();
}
