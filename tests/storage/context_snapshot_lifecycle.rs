use super::*;

#[test]
fn bounded_context_postmigration_read_needs_no_transaction_route() {
    let root = temporary_root("bounded-context-no-transaction");
    let db = "route.db";
    let normal = storage_runner(&root);
    seed_session_and_run(&normal, db, "session-1", "run-1", 10);
    seed_history(&root, db, 1);
    run_raw_sql(
        &raw_sql_runner(
            &root,
            "route-facts",
            &[
                "UPDATE sessions SET generation=7 WHERE id='session-1'",
                "INSERT INTO compactions (id,session_id,run_id,generation,source_start_ordinal,source_end_ordinal,retained_tail_ordinal,summary_json,state,created_at_ms) VALUES ('summary','session-1','run-1',7,1,1,1,json_object('text','current-summary'),'committed',20)",
            ],
        ),
        db,
    );
    let guarded = context_fixture_runner(&root, |mut source| {
        // Schema is already seeded. Only the postmigration context reader is
        // guarded: normal entry migration and all write commands stay real.
        let start = source.find("fn storage_compaction_context_read(").unwrap();
        let end = source[start..].find("fn storage_dispatch(").unwrap() + start;
        let guarded = source[start..end].replace(
            "sqlite::transaction(&db_id,",
            "test_forbidden_context_transaction(db_id,",
        );
        source.replace_range(start..end, &guarded);
        source.push_str(r#"
fn test_forbidden_context_transaction(db_id: resource<sqlite.connection>, statements: array<SqliteStatement>) -> array<SqliteTransactionResult> {
    let denied = sqlite::query(&db_id, "SELECT * FROM forbidden_context_transaction_route", [], sql_limits(1, 4096, 5000));
    sqlite::transaction(&db_id, statements)
}
"#);
        source
    });
    let snapshot = context(&guarded, db, "session-1");
    assert_eq!(snapshot["ok"], true, "{snapshot}");
    assert_eq!(rows(&snapshot["data"]["session"])[0][7], 7);
    assert_eq!(rows(&snapshot["data"]["messages"])[0][0], "message-1");
    assert_eq!(rows(&snapshot["data"]["latest"])[0][3], 7);
    assert_eq!(
        rows(&snapshot["data"]["latest"])[0][7],
        "{\"text\":\"current-summary\"}"
    );
    assert_eq!(snapshot["data"]["summary_loaded"], true);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bounded_context_statement_reads_coherent_generation_during_sdk_writes() {
    use std::sync::{Arc, Barrier};
    let root = temporary_root("bounded-context-coherence");
    let db = "coherent.db";
    let reader = storage_runner(&root);
    seed_session_and_run(&reader, db, "session-1", "run-1", 10);
    seed_history(&root, db, 1);
    run_raw_sql(
        &raw_sql_runner(
            &root,
            "coherent-initial",
            &[
                "UPDATE messages SET content_json=json_object('text','1')",
                "INSERT INTO compactions (id,session_id,run_id,generation,source_start_ordinal,source_end_ordinal,retained_tail_ordinal,summary_json,state,created_at_ms) VALUES ('summary','session-1','run-1',1,1,1,1,json_object('text','1'),'committed',20)",
            ],
        ),
        db,
    );
    let writer = AgentRunner::from_source(r#"
use sqlite;
fn number(n: int) -> SqliteValue { {kind:"int", int_value:n, float_value:null, text_value:null, blob_value:null} }
pub fn run(generation: int) -> int {
    let db = sqlite::open({path:"coherent.db", mode:"read_write"});
    let results = sqlite::transaction(&db, [
        {sql:"UPDATE sessions SET generation=? WHERE id='session-1'", params:[number(generation.copy())], query:false},
        {sql:"UPDATE messages SET content_json=json_object('text',CAST(? AS TEXT)) WHERE session_id='session-1'", params:[number(generation.copy())], query:false},
        {sql:"UPDATE compactions SET generation=?,summary_json=json_object('text',CAST(? AS TEXT)) WHERE id='summary'", params:[number(generation.copy()),number(generation.copy())], query:false}
    ]);
    sqlite::close(db);
    results.length
}
"#, AgentConfig::default().with_sqlite_root(&root)).unwrap();
    let start = Arc::new(Barrier::new(2));
    std::thread::scope(|scope| {
        let go = Arc::clone(&start);
        let worker = scope.spawn(move || {
            go.wait();
            for generation in 2..=9 {
                assert_eq!(
                    writer.run_with_context(Value::Int(generation)).unwrap(),
                    Value::Int(3)
                );
            }
        });
        start.wait();
        for _ in 0..16 {
            let snapshot = context(&reader, db, "session-1");
            assert_eq!(snapshot["ok"], true, "{snapshot}");
            let data = &snapshot["data"];
            let generation = rows(&data["session"])[0][7].as_i64().unwrap();
            let message = rows(&data["messages"]);
            let latest = rows(&data["latest"]);
            assert_eq!(latest[0][3], generation);
            let content: JsonValue = serde_json::from_str(message[0][4].as_str().unwrap()).unwrap();
            let summary: JsonValue = serde_json::from_str(latest[0][7].as_str().unwrap()).unwrap();
            assert_eq!(content[0]["text"], generation.to_string());
            assert_eq!(summary["text"], generation.to_string());
        }
        worker.join().unwrap();
    });
    assert_eq!(
        rows(&context(&reader, db, "session-1")["data"]["session"])[0][7],
        9
    );
    fs::remove_dir_all(root).unwrap();
}

#[path = "context_snapshot_packed.rs"]
mod packed;

fn context_fixture_runner(
    root: &std::path::Path,
    transform: impl FnOnce(String) -> String,
) -> AgentRunner {
    for file in STORAGE_FILES {
        fs::copy(storage_root().join(file), root.join(file)).unwrap();
    }
    let source = fs::read_to_string(root.join("main.rss")).unwrap();
    fs::write(root.join("main.rss"), transform(source)).unwrap();
    AgentRunner::from_file(
        root.join("main.rss"),
        AgentConfig::default().with_sqlite_root(root),
    )
    .unwrap()
}

#[test]
fn bounded_context_failed_single_query_releases_connection() {
    let root = temporary_root("bounded-context-query-error");
    let db = "query-error.db";
    let normal = storage_runner(&root);
    seed_session_and_run(&normal, db, "session-1", "run-1", 10);
    let broken = context_fixture_runner(&root, |source| {
        let anchor = "storage_context_sql(), [sql_text(input.session_id.copy())";
        assert_eq!(source.matches(anchor).count(), 1);
        source.replacen(
            anchor,
            "\"SELECT * FROM missing_context_table\", [sql_text(input.session_id.copy())",
            1,
        )
    });
    let result = run_storage_result(
        &broken,
        db,
        "fail-query",
        "compaction.context",
        json!({"session_id":"session-1"}),
        20,
    )
    .unwrap_err();
    assert!(
        result.to_string().contains("missing_context_table"),
        "{result}"
    );
    run_storage(
        &normal,
        db,
        "after-query-error",
        "message.append",
        message_payload("after-query-error", "session-1", 1, 21),
        21,
    );
    assert_eq!(
        rows(&context(&normal, db, "session-1")["data"]["messages"])[0][0],
        "after-query-error"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bounded_context_cancelled_after_open_migration_releases_owned_connection() {
    let root = temporary_root("bounded-context-cancel");
    let db = "cancel.db";
    let normal = storage_runner(&root);
    seed_session_and_run(&normal, db, "session-1", "run-1", 10);
    let instrumented = context_fixture_runner(&root, |source| {
        let anchor = "let result = storage_dispatch(db_id, command);";
        assert_eq!(source.matches(anchor).count(), 1);
        source.replacen("use sqlite;", "use sqlite;\nuse stream;", 1)
            .replacen(anchor, "stream::emit({op:\"context.after_open_migration\"});\nlet result = storage_dispatch(db_id, command);", 1)
    });
    struct CancelAfterOpen {
        cancellation: rustscript_agent::RunCancellation,
        entered: bool,
    }
    impl rustscript_agent::RunEventSink for CancelAfterOpen {
        fn deliver(&mut self, value: Value) -> Result<(), rustscript_agent::RunDeliveryError> {
            assert_eq!(
                emit_op(&value).as_deref(),
                Some("context.after_open_migration")
            );
            self.entered = true;
            self.cancellation
                .request(rustscript_agent::CancellationReason::Requested);
            Ok(())
        }
    }
    let cancellation = rustscript_agent::RunCancellation::new();
    let mut sink = CancelAfterOpen {
        cancellation: cancellation.clone(),
        entered: false,
    };
    let result = instrumented.run_with_context_and_events(
        storage_command(
            db,
            "cancel-context",
            "compaction.context",
            json!({"session_id":"session-1"}),
            20,
        ),
        &mut sink,
        &cancellation,
    );
    assert!(sink.entered);
    assert!(result.is_err(), "{result:?}");
    assert!(!cancellation.watcher_is_armed());
    run_storage(
        &normal,
        db,
        "after-cancel",
        "message.append",
        message_payload("after-cancel", "session-1", 1, 21),
        21,
    );
    assert_eq!(
        rows(&context(&normal, db, "session-1")["data"]["messages"])[0][0],
        "after-cancel"
    );
    fs::remove_dir_all(root).unwrap();
}
