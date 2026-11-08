//! Production managed effects: real RSS leaves and fresh gateway recovery.
use rustscript_agent::config::{ManagedRetentionLimits, ManagedWorkspaceConfig};
use rustscript_agent::effects::ResourceQuota;
use rustscript_agent::{AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, ScriptedProvider};
use serde_json::{Value, json};
use std::{fs, path::PathBuf, sync::Arc};
#[path = "effect_commit_recovery/authority_matrix.rs"]
mod authority_matrix;
#[cfg(feature = "workspace-io-fault")]
#[path = "effect_commit_recovery/budget_matrix.rs"]
mod budget_matrix;
#[cfg(feature = "workspace-io-fault")]
#[path = "effect_commit_recovery/io_matrix.rs"]
mod io_matrix;
#[path = "effect_commit_recovery/schema_matrix.rs"]
mod schema_matrix;
#[path = "effect_commit_recovery/startup_matrix.rs"]
mod startup_matrix;

fn assert_managed_canonical_readback(state: &AgentGatewayState, run: &str) {
    let persistence = state.persistence().unwrap();
    let service = state.service();
    let durable = persistence
        .event_replay(&json!({"run_id":run,"after_seq":0,"max_events":128,"max_bytes":1048576}))
        .unwrap();
    let columns = durable["columns"].as_array().unwrap();
    let cell = |row: &Value, name: &str| {
        row[columns.iter().position(|column| column == name).unwrap()].clone()
    };
    for event in service
        .run_events(run)
        .iter()
        .filter(|event| event["event"].as_str().unwrap().starts_with("tool."))
    {
        let row = durable["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| cell(row, "event_id") == event["event_id"])
            .unwrap();
        assert_eq!(
            *event,
            json!({"run_id":run,"event_id":cell(row,"event_id"),"seq":cell(row,"seq"),"event":cell(row,"event_type"),"data":serde_json::from_str::<Value>(cell(row,"payload_json").as_str().unwrap()).unwrap(),"timestamp":cell(row,"created_at_ms")})
        );
    }
}

fn response(call: Option<Value>) -> Value {
    json!({"text":if call.is_some() { "" } else { "done" },"tool_calls":call.into_iter().collect::<Vec<_>>(),"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"})
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_managed_write_terminal_read_and_fresh_sdk_reopen() {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("managed-{}", uuid::Uuid::new_v4().simple()));
    let workspace = root.join("workspace");
    let home = root.join("home");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&home).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    fs::write(workspace.join("seed.txt"), b"immutable seed\n").unwrap();
    fs::write(home.join("config.yaml"), format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\napprovals:\n  read: allow\n  write: allow\n  process: allow\n", workspace.display(), workspace.display())).unwrap();
    let mut config = AgentGatewayConfig {
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1024 * 1024, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: Default::default(),
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.approvals.process = "allow".into();
    let database = root.join("gateway.sqlite");
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &database)
        .unwrap()
        .with_workspace_home(&home);
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(response(Some(json!({"id":"write-one","name":"write_file","arguments":{"path":"one.txt","content":"managed bytes\n"}}))));
    provider.push_ok(response(Some(json!({"id":"read-one","name":"terminal","arguments":{"argv":["/bin/sh","-c","cat one.txt"],"timeout_ms":1000}}))));
    provider.push_ok(response(None));
    state.service().inject_provider_host(provider);
    let run = state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"write then read the file"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    // Retained control-plane approval history is audit data, not a Native
    // execution attestation and never a source of authority on reopen.
    let persistence = state.persistence().unwrap();
    persistence.approval_request(&json!({"id":"retained-managed-approval","run_id":run.run_id,"session_id":run.session_id,"tool_call_id":"write-one","tool_name":"write_file","arguments_json":"{}","risk_class":"write","decision_scope":"","one_time":1,"requested_at_ms":1,"expires_at_ms":0})).unwrap();
    persistence.approval_resolve(&json!({"id":"retained-managed-approval","run_id":run.run_id,"state":"approved","resolver":"synthetic-history","decision_reason":"retain historical decision only","resolved_at_ms":2})).unwrap();
    drop(persistence);
    state
        .service()
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    let events = state.service().run_events(&run.run_id);
    let facts: Vec<_> = events
        .iter()
        .map(|event| {
            (
                event["event"].clone(),
                event["data"]["error_code"].clone(),
                event["data"]["code"].clone(),
            )
        })
        .collect();
    eprintln!("event types and codes: {facts:?}");
    for name in [
        "tool.requested",
        "tool.started",
        "tool.output",
        "tool.completed",
    ] {
        assert_eq!(
            events.iter().filter(|event| event["event"] == name).count(),
            2,
            "{name}"
        );
    }
    let messages = serde_json::to_value(state.service().session_messages(&run.session_id)).unwrap();
    let results: Vec<_> = messages
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|message| message["content"].as_array().into_iter().flatten())
        .filter(|block| block["type"] == "tool_result")
        .cloned()
        .collect();
    assert_eq!(results.len(), 2);
    assert_eq!(results[1]["result"]["stdout"], "managed bytes\n");
    assert!(
        !workspace.join("one.txt").exists(),
        "managed effects must leave the authorized source unchanged"
    );
    assert_eq!(
        fs::read(workspace.join("seed.txt")).unwrap(),
        b"immutable seed\n"
    );
    let request = rustscript_agent::effects::ManagedEffectGetRequest {
        owner: rustscript_agent::effects::ManagedOwnerScope {
            profile: "gateway".into(),
            session_id: run.session_id.clone(),
            run_id: run.run_id.clone(),
        },
        call_id: "read-one".into(),
    };
    let record = state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .expect("managed receipt");
    let first_request = rustscript_agent::effects::ManagedEffectGetRequest {
        call_id: "write-one".into(),
        ..request.clone()
    };
    let first = state
        .persistence()
        .unwrap()
        .managed_effect_get(&first_request)
        .unwrap()
        .unwrap();
    let head = state
        .persistence()
        .unwrap()
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    assert_eq!(head.head_version, 3);
    assert_eq!(
        record.identity.expected_head,
        first
            .prepared
            .as_ref()
            .unwrap()
            .candidate_root
            .as_ref()
            .unwrap()
            .object_id
    );
    assert_eq!(
        record.prepared.as_ref().unwrap().parent_root,
        *first
            .prepared
            .as_ref()
            .unwrap()
            .candidate_root
            .as_ref()
            .unwrap(),
        "the observed parent reference must retain its exact durable byte and entry metadata"
    );
    let store_root = root.join(".gateway.sqlite.effects");
    assert_eq!(
        fs::read(
            store_root
                .join("trees")
                .join(&head.head_object_id)
                .join("one.txt")
        )
        .unwrap(),
        b"managed bytes\n"
    );
    assert!(
        !store_root
            .join("trees")
            .join(&first.identity.expected_head)
            .join("one.txt")
            .exists()
    );
    let replay = state
        .service()
        .replay_managed_call(request.clone())
        .unwrap();
    if let rustscript_agent::effects::ManagedCallReplay::Final {
        canonical_result, ..
    } = &replay
    {
        let full: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
        assert_eq!(full["data"]["stdout"], "managed bytes\n");
    } else {
        panic!("expected final replay");
    }
    let before = state
        .persistence()
        .unwrap()
        .message_list(&run.session_id, 0)
        .unwrap();
    let managed_messages = |messages: Value| {
        messages.as_array().unwrap().iter().filter(|message|message["tool_call_id"].as_str().is_some()).map(|message|json!({"id":message["id"],"role":message["role"],"run_id":message["run_id"],"name":message["name"],"tool_call_id":message["tool_call_id"],"parent_message_id":message["parent_message_id"],"content":message["content"],"metadata":message["metadata"],"ordinal":message["ordinal"],"finish_reason":message["finish_reason"],"token_estimate":message["token_estimate"]})).collect::<Vec<_>>()
    };
    assert_managed_canonical_readback(&state, &run.run_id);
    let live_messages = managed_messages(messages);
    let managed_events = |events: Vec<Value>| {
        events
            .into_iter()
            .filter(|event| {
                event["event"]
                    .as_str()
                    .is_some_and(|name| name.starts_with("tool."))
            })
            .collect::<Vec<_>>()
    };
    let persistence = state.persistence().unwrap();
    let approvals = persistence
        .approval_list(&run.run_id, &run.session_id)
        .unwrap();
    assert!(
        approvals["rows"].as_array().unwrap().is_empty(),
        "resolved approvals are excluded from the pending-only list"
    );
    let approval = persistence
        .approval_get("retained-managed-approval")
        .unwrap();
    assert_eq!(approval["rows"].as_array().unwrap().len(), 1);
    let state_column = approval["columns"]
        .as_array()
        .unwrap()
        .iter()
        .position(|value| value == "state")
        .unwrap();
    assert_eq!(approval["rows"][0][state_column], "approved");
    let usage = |value: Value| {
        let columns = value["columns"].as_array().unwrap();
        ["input_tokens", "output_tokens"].map(|name| {
            value["rows"][0][columns.iter().position(|column| column == name).unwrap()]
                .as_i64()
                .unwrap()
        })
    };
    let usage_before = usage(persistence.run_get(&run.run_id).unwrap());
    assert_eq!(
        usage_before,
        [0, 0],
        "scripted provider bypasses the production usage recorder; nonzero formal usage is covered by managed_reopen_preserves_nonzero_formal_provider_usage"
    );
    let cursor = events
        .iter()
        .map(|event| event["seq"].as_i64().unwrap())
        .max()
        .unwrap();
    persistence
        .delivery_advance(&run.session_id, "managed-reopen", cursor)
        .unwrap();
    let delivery = persistence
        .delivery_get(&run.session_id, "managed-reopen")
        .unwrap();
    assert_eq!(delivery["rows"].as_array().unwrap().len(), 1);
    let live_events = managed_events(events);
    drop(persistence);
    state.service().shutdown().await.unwrap();
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(config, &database)
        .unwrap()
        .with_workspace_home(&home);
    let persistence = reopened.persistence().unwrap();
    assert_eq!(
        usage(persistence.run_get(&run.run_id).unwrap()),
        usage_before
    );
    assert_eq!(
        persistence
            .approval_list(&run.run_id, &run.session_id)
            .unwrap(),
        approvals
    );
    assert_eq!(
        persistence
            .approval_get("retained-managed-approval")
            .unwrap(),
        approval
    );
    assert_eq!(
        persistence
            .delivery_get(&run.session_id, "managed-reopen")
            .unwrap(),
        delivery
    );
    drop(persistence);
    assert_eq!(
        managed_messages(
            serde_json::to_value(reopened.service().session_messages(&run.session_id)).unwrap()
        ),
        live_messages,
        "managed live and durable message contracts must agree exactly"
    );
    assert_eq!(
        managed_events(reopened.service().run_events(&run.run_id)),
        live_events,
        "managed live and durable event projections must agree exactly"
    );
    assert_eq!(
        reopened
            .persistence()
            .unwrap()
            .message_list(&run.session_id, 0)
            .unwrap(),
        before
    );
    assert_eq!(
        reopened
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap(),
        record
    );
    assert_eq!(
        reopened
            .persistence()
            .unwrap()
            .managed_workspace_head(&record.identity.workspace)
            .unwrap(),
        head
    );
    assert_eq!(
        reopened.service().replay_managed_call(request).unwrap(),
        replay
    );
    reopened.service().shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn intent_cut_never_issues_view_or_execution_and_reopens_indeterminate() {
    use rustscript_agent::effects::{ManagedCallReplay, ManagedEffectFault};
    let fixture = CutFixture::write(ManagedEffectFault::AfterIntent).await;
    let request = fixture.request();
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert!(
        record.prepared.is_none(),
        "intent cut must prevent actual execution/preparation"
    );
    assert!(record.outcome.is_none());
    assert_eq!(
        fs::read_dir(fixture.root.join(".gateway.sqlite.effects/views"))
            .unwrap()
            .count(),
        0
    );
    let head = fixture
        .state
        .persistence()
        .unwrap()
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    assert_eq!(head.head_version, 1);
    fixture.state.service().shutdown().await.unwrap();
    let CutFixture {
        root,
        home,
        config,
        state,
        ..
    } = fixture;
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(&home);
    let after = reopened
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert_eq!(
        after.identity.original_deadline_ms,
        record.identity.original_deadline_ms
    );
    assert_eq!(
        after.recovery.as_ref().unwrap().code,
        "effect_indeterminate"
    );
    assert!(matches!(
        reopened
            .service()
            .replay_managed_call(request.clone())
            .unwrap(),
        ManagedCallReplay::Indeterminate { .. }
    ));
    let events = reopened.service().run_events(&request.owner.run_id);
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "tool.started")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "tool.output")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "tool.failed")
            .count(),
        1
    );
    assert_managed_canonical_readback(&reopened, &request.owner.run_id);
    let messages = serde_json::to_value(
        reopened
            .service()
            .session_messages(&request.owner.session_id),
    )
    .unwrap();
    let recovery = after.recovery.as_ref().unwrap();
    for event in events
        .iter()
        .filter(|event| event["event"] == "tool.output" || event["event"] == "tool.failed")
    {
        assert_eq!(
            event["data"]["managed_publication"],
            json!(recovery.publication)
        );
        assert_eq!(
            event["data"]["managed_publication"].get("candidate_head"),
            Some(&Value::Null)
        );
    }
    reopened.service().shutdown().await.unwrap();
    drop(reopened);
    let again = AgentGatewayState::with_sqlite_path(
        AgentGatewayConfig::default(),
        root.join("gateway.sqlite"),
    )
    .unwrap();
    assert_eq!(
        again
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap(),
        after
    );
    assert_eq!(again.service().run_events(&request.owner.run_id), events);
    assert_eq!(
        serde_json::to_value(again.service().session_messages(&request.owner.session_id)).unwrap(),
        messages
    );
    again.service().shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn joint_sql_faults_roll_back_head_receipt_events_and_message_on_fresh_reopen() {
    use rustscript_agent::effects::ManagedEffectFault::*;
    for cut in [
        CommitAfterDecision,
        CommitAfterHead,
        CommitAfterReceipt,
        CommitAfterFirstEvent,
        CommitAfterMessage,
    ] {
        let fixture = CutFixture::write(cut).await;
        let request = fixture.request();
        let record = fixture
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        assert!(
            record.prepared.is_some(),
            "{cut:?}: prepared objects must survive SQL rollback"
        );
        assert!(
            record.outcome.is_none(),
            "{cut:?}: partial SQL must not finalize the receipt"
        );
        let head = fixture
            .state
            .persistence()
            .unwrap()
            .managed_workspace_head(&record.identity.workspace)
            .unwrap();
        assert_eq!(head.head_version, 1, "{cut:?}: head must roll back");
        assert_eq!(head.head_object_id, record.identity.expected_head);
        let before = fixture.state.service().run_events(&request.owner.run_id);
        assert_eq!(
            before
                .iter()
                .filter(|event| event["event"] == "tool.output")
                .count(),
            0,
            "{cut:?}: no live partial output"
        );
        fixture.state.service().shutdown().await.unwrap();
        let CutFixture {
            root,
            home,
            config,
            state,
            ..
        } = fixture;
        drop(state);
        let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
            .unwrap()
            .with_workspace_home(&home);
        let after = reopened
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        assert!(after.outcome.is_none());
        assert_eq!(after.prepared, record.prepared);
        assert_eq!(after.recovery.as_ref().unwrap().code, "effect_staged");
        assert_eq!(
            reopened
                .persistence()
                .unwrap()
                .managed_workspace_head(&record.identity.workspace)
                .unwrap(),
            head
        );
        let events = reopened.service().run_events(&request.owner.run_id);
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event"] == "tool.output")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event"] == "tool.failed")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event"] == "tool.completed")
                .count(),
            0
        );
        reopened.service().shutdown().await.unwrap();
    }
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn actual_terminal_before_prepared_loss_is_indeterminate_and_never_respawns() {
    use rustscript_agent::effects::{ManagedCallReplay, ManagedEffectFault::*};
    for cut in [AfterOperationBeforePrepare, AfterObjectsSynced] {
        let fixture = CutFixture::terminal(cut).await;
        let request = fixture.request();
        assert_eq!(
            fs::read(fixture.root.join("external-sentinel")).unwrap(),
            b"x"
        );
        let record = fixture
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        assert!(
            record.prepared.is_none(),
            "{cut:?}: no durable prepared proof exists"
        );
        assert!(record.outcome.is_none());
        let head = fixture
            .state
            .persistence()
            .unwrap()
            .managed_workspace_head(&record.identity.workspace)
            .unwrap();
        assert_eq!(head.head_version, 1);
        let sealed = fs::read_dir(fixture.root.join(".gateway.sqlite.effects/trees"))
            .unwrap()
            .count();
        if cut == AfterObjectsSynced {
            assert!(
                sealed >= 2,
                "physical object must exist before SQL preparation"
            );
        }
        let before = DurableRows::capture(
            &fixture.state,
            &request.owner.run_id,
            &request.owner.session_id,
        );
        fixture.state.service().shutdown().await.unwrap();
        let CutFixture {
            root,
            home,
            config,
            state,
            ..
        } = fixture;
        drop(state);
        let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
            .unwrap()
            .with_workspace_home(&home);
        for _ in 0..2 {
            assert!(matches!(
                reopened
                    .service()
                    .replay_managed_call(request.clone())
                    .unwrap(),
                ManagedCallReplay::Indeterminate { .. }
            ));
        }
        assert_eq!(fs::read(root.join("external-sentinel")).unwrap(), b"x");
        assert_eq!(
            fs::read_dir(root.join(".gateway.sqlite.effects/trees"))
                .unwrap()
                .count(),
            sealed
        );
        assert_eq!(
            reopened
                .persistence()
                .unwrap()
                .managed_workspace_head(&record.identity.workspace)
                .unwrap(),
            head
        );
        let after = reopened
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        assert_eq!(
            after.recovery.as_ref().unwrap().code,
            "effect_indeterminate"
        );
        assert_eq!(
            after.identity.original_deadline_ms,
            record.identity.original_deadline_ms
        );
        let after_rows =
            DurableRows::capture(&reopened, &request.owner.run_id, &request.owner.session_id);
        before.assert_preserved(&after_rows);
        let outputs = after_rows.seq_of("cut-write", "tool.output");
        let terminals = after_rows.seq_of("cut-write", "tool.failed");
        assert_eq!(outputs.len(), 1, "exactly one durable output");
        assert_eq!(terminals.len(), 1, "exactly one durable terminal");
        assert!(
            outputs[0] < terminals[0],
            "a started failure must publish its output before the terminal"
        );
        let recovery = after.recovery.as_ref().unwrap();
        after_rows.assert_recovery_refs(
            "cut-write",
            (&recovery.output_event.event_id, recovery.output_event.seq),
            (
                &recovery.terminal_event.event_id,
                recovery.terminal_event.seq,
            ),
            (&recovery.message.id, recovery.message.ordinal),
        );
        reopened.service().shutdown().await.unwrap();
    }
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn durable_commit_before_live_gap_replays_exact_receipt_without_terminal_retry() {
    use rustscript_agent::effects::{ManagedCallReplay, ManagedEffectFault};
    let fixture = CutFixture::terminal(ManagedEffectFault::AfterDurableBeforeLive).await;
    let request = fixture.request();
    assert_eq!(
        fs::read(fixture.root.join("external-sentinel")).unwrap(),
        b"x"
    );
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert!(record.outcome.is_some());
    let live = fixture.state.service().run_events(&request.owner.run_id);
    assert_eq!(
        live.iter()
            .filter(|event| event["event"] == "tool.output")
            .count(),
        0,
        "post-durable cut must suppress this live apply"
    );
    let head = fixture
        .state
        .persistence()
        .unwrap()
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    assert_eq!(head.head_version, 2);
    fixture.state.service().shutdown().await.unwrap();
    let CutFixture {
        root,
        home,
        config,
        state,
        ..
    } = fixture;
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(&home);
    assert_eq!(
        reopened
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap(),
        record
    );
    let first = reopened
        .service()
        .replay_managed_call(request.clone())
        .unwrap();
    assert!(matches!(first, ManagedCallReplay::Final { .. }));
    assert_eq!(
        reopened
            .service()
            .replay_managed_call(request.clone())
            .unwrap(),
        first
    );
    assert_eq!(
        reopened
            .persistence()
            .unwrap()
            .managed_workspace_head(&record.identity.workspace)
            .unwrap(),
        head
    );
    assert_eq!(fs::read(root.join("external-sentinel")).unwrap(), b"x");
    let events = reopened.service().run_events(&request.owner.run_id);
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "tool.started")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "tool.output")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "tool.completed")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "tool.failed")
            .count(),
        0
    );
    reopened.service().shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn managed_schema_parser_rejects_unknown_formats_versions_and_authority_fields() {
    use rustscript_agent::effects::{ManagedEffectFault, parse_managed_effect_yaml};
    let fixture = CutFixture::write(ManagedEffectFault::AfterPrepared).await;
    let queried = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&fixture.request())
        .unwrap();
    if queried.is_none() {
        let messages = serde_json::to_value(
            fixture
                .state
                .service()
                .session_messages(&fixture.run.session_id),
        )
        .unwrap();
        let errors: Vec<_> = messages
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|m| m["content"].as_array().into_iter().flatten())
            .filter_map(|block| block.get("error"))
            .collect();
        panic!("managed schema prevented intent: {errors:?}");
    }
    let record = queried.unwrap();
    let document = serde_json::to_string(&record).unwrap();
    assert_eq!(parse_managed_effect_yaml(&document).unwrap(), record);
    let mut value = serde_json::to_value(&record).unwrap();
    value["format"] = json!("agent.managed-effect/v2");
    assert!(
        parse_managed_effect_yaml(&value.to_string()).is_err(),
        "the production parser must enforce the exact YAML format contract"
    );
    value = serde_json::to_value(&record).unwrap();
    value["schemaVersion"] = json!(2);
    assert!(parse_managed_effect_yaml(&value.to_string()).is_err());
    value = serde_json::to_value(&record).unwrap();
    value["execution_token"] = json!("guest-fabricated");
    assert!(parse_managed_effect_yaml(&value.to_string()).is_err());
    let duplicate = document.replacen("{", "{\"format\":\"agent.managed-effect/v1\",", 1);
    assert!(parse_managed_effect_yaml(&duplicate).is_err());
    fixture.state.service().shutdown().await.unwrap();
}

struct ManagedFixture {
    root: PathBuf,
    home: PathBuf,
    config: AgentGatewayConfig,
    state: AgentGatewayState,
}
impl ManagedFixture {
    fn new(configure: impl FnOnce(&mut AgentGatewayConfig)) -> Self {
        let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
            .join(format!("managed-case-{}", uuid::Uuid::new_v4().simple()));
        let workspace = root.join("workspace");
        let home = root.join("home");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&home).unwrap();
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(home.join("config.yaml"),format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",workspace.display(),workspace.display())).unwrap();
        let mut config = AgentGatewayConfig {
            managed_workspace: Some(ManagedWorkspaceConfig {
                source_root: workspace,
                quota: ResourceQuota::new(1000, 1048576, 16).unwrap(),
                retention: ManagedRetentionLimits::default(),
                maintenance_policy: Default::default(),
            }),
            ..AgentGatewayConfig::default()
        };
        config.approvals.write = "allow".into();
        config.approvals.process = "allow".into();
        configure(&mut config);
        let state =
            AgentGatewayState::with_sqlite_path(config.clone(), root.join("gateway.sqlite"))
                .unwrap()
                .with_workspace_home(&home);
        Self {
            root,
            home,
            config,
            state,
        }
    }
    async fn calls(&self, calls: Vec<Value>) -> rustscript_agent::AdmittedRun {
        let provider = Arc::new(ScriptedProvider::new());
        for call in calls {
            provider.push_ok(response(Some(call)));
        }
        provider.push_ok(response(None));
        self.state.service().inject_provider_host(provider);
        let run = self
            .state
            .service()
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"execute the bounded fixture calls"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        self.state
            .service()
            .run_worker(run.run_id.clone(), "ignored".into())
            .await;
        run
    }
    fn request(
        run: &rustscript_agent::AdmittedRun,
        call: &str,
    ) -> rustscript_agent::effects::ManagedEffectGetRequest {
        rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: run.session_id.clone(),
                run_id: run.run_id.clone(),
            },
            call_id: call.into(),
        }
    }
    async fn reopen(self) -> Self {
        self.state.service().shutdown().await.unwrap();
        let Self {
            root,
            home,
            config,
            state,
        } = self;
        drop(state);
        let state =
            AgentGatewayState::with_sqlite_path(config.clone(), root.join("gateway.sqlite"))
                .unwrap()
                .with_workspace_home(&home);
        Self {
            root,
            home,
            config,
            state,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_native_write_reserves_aggregate_quota_before_file_publication() {
    let fixture = ManagedFixture::new(|config| {
        config.managed_workspace.as_mut().unwrap().quota = ResourceQuota::new(10, 8, 4).unwrap()
    });
    let run=fixture.calls(vec![json!({"id":"quota-write","name":"write_file","arguments":{"path":"large.txt","content":"123456789"}})]).await;
    let request = ManagedFixture::request(&run, "quota-write");
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert!(
        record.outcome.is_some(),
        "a bounded Native quota denial must commit its actual failed observation"
    );
    assert_eq!(
        record.outcome.as_ref().unwrap().disposition,
        rustscript_agent::effects::ManagedPublicationStatus::NotPublished
    );
    let views = fs::read_dir(fixture.root.join(".gateway.sqlite.effects/views"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(views.len(), 1);
    assert!(
        !views[0].join("large.txt").exists(),
        "aggregate quota must reject before the original atomic write"
    );
    let head = fixture
        .state
        .persistence()
        .unwrap()
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    assert_eq!(head.head_version, 1);
    let reopened = fixture.reopen().await;
    assert_eq!(
        reopened
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap(),
        record
    );
    reopened.state.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn terminal_mutations_feed_original_read_search_patch_and_failed_patch_keeps_parent() {
    use rustscript_agent::effects::{ManagedCallReplay, ManagedPublicationStatus};
    let fixture = ManagedFixture::new(|_| {});
    fs::write(fixture.root.join("workspace/gone.txt"), b"seed-only").unwrap();
    let run=fixture.calls(vec![
        json!({"id":"shell","name":"terminal","arguments":{"argv":["/bin/sh","-c","printf 'first\\n' > temp.txt; mv temp.txt note.txt; rm gone.txt"],"timeout_ms":1000}}),
        json!({"id":"read","name":"read_file","arguments":{"path":"note.txt"}}),
        json!({"id":"search","name":"search_files","arguments":{"pattern":"*.txt","target":"files"}}),
        json!({"id":"patch","name":"patch","arguments":{"path":"note.txt","old_string":"first","new_string":"second"}}),
        json!({"id":"failed-patch","name":"patch","arguments":{"path":"note.txt","old_string":"absent","new_string":"must-not-publish"}}),
    ]).await;
    let records = ["shell", "read", "search", "patch", "failed-patch"]
        .iter()
        .map(|call| {
            fixture
                .state
                .persistence()
                .unwrap()
                .managed_effect_get(&ManagedFixture::request(&run, call))
                .unwrap()
                .unwrap_or_else(|| {
                    panic!(
                        "missing managed record {call}; codes: {:?}",
                        fixture
                            .state
                            .service()
                            .run_events(&run.run_id)
                            .iter()
                            .map(|event| (
                                event["event"].clone(),
                                event["data"]["code"].clone(),
                                event["data"]["error"]["code"].clone()
                            ))
                            .collect::<Vec<_>>()
                    )
                })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        records[1].outcome.as_ref().unwrap().disposition,
        ManagedPublicationStatus::ReadOnly
    );
    assert_eq!(
        records[2].outcome.as_ref().unwrap().disposition,
        ManagedPublicationStatus::ReadOnly
    );
    assert_eq!(
        records[4].outcome.as_ref().unwrap().disposition,
        ManagedPublicationStatus::NotPublished
    );
    for call in ["read", "search"] {
        let ManagedCallReplay::Final {
            canonical_result, ..
        } = fixture
            .state
            .service()
            .replay_managed_call(ManagedFixture::request(&run, call))
            .unwrap()
        else {
            panic!("expected exact replay");
        };
        let full: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
        assert_eq!(full["ok"], true);
        if call == "read" {
            assert!(full["content"].as_str().unwrap().contains("first"));
        } else {
            assert!(
                full.to_string().contains("note.txt"),
                "search counters: files={:?}, dirs={:?}, matches={:?}, truncated={:?}",
                full["data"]["files_visited"],
                full["data"]["dirs_visited"],
                full["data"]["match_count"],
                full["truncated"]
            );
            assert!(!full.to_string().contains("gone.txt"));
        }
    }
    let head = fixture
        .state
        .persistence()
        .unwrap()
        .managed_workspace_head(&records[0].identity.workspace)
        .unwrap();
    assert_eq!(head.head_version, 3);
    let trees = fixture.root.join(".gateway.sqlite.effects/trees");
    assert_eq!(
        fs::read(trees.join(&head.head_object_id).join("note.txt")).unwrap(),
        b"second\n"
    );
    assert_eq!(
        fs::read(
            trees
                .join(
                    &records[0]
                        .prepared
                        .as_ref()
                        .unwrap()
                        .candidate_root
                        .as_ref()
                        .unwrap()
                        .object_id
                )
                .join("note.txt")
        )
        .unwrap(),
        b"first\n"
    );
    assert_eq!(
        fs::read(
            trees
                .join(&records[0].identity.expected_head)
                .join("gone.txt")
        )
        .unwrap(),
        b"seed-only"
    );
    assert_eq!(
        fs::read(fixture.root.join("workspace/gone.txt")).unwrap(),
        b"seed-only"
    );
    assert!(!fixture.root.join("workspace/note.txt").exists());
    let reopened = fixture.reopen().await;
    assert_eq!(
        reopened
            .state
            .persistence()
            .unwrap()
            .managed_workspace_head(&records[0].identity.workspace)
            .unwrap(),
        head
    );
    for record in &records {
        assert_eq!(
            reopened
                .state
                .persistence()
                .unwrap()
                .managed_effect_get(&ManagedFixture::request(&run, &record.identity.call_id))
                .unwrap()
                .unwrap(),
            *record
        );
    }
    reopened.state.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn large_nonzero_terminal_observation_replays_full_result_after_event_pruning_and_reopen() {
    use rustscript_agent::effects::ManagedCallReplay;
    let fixture = ManagedFixture::new(|config| {
        config.max_events_per_run = 8;
    });
    fixture
        .state
        .service()
        .set_run_limits(
            rustscript_agent::config::RunLimits::new(
                64,
                128,
                4 * 1024 * 1024,
                fixture.root.join("workspace"),
            )
            .unwrap(),
        )
        .unwrap();
    fs::write(
        fixture.root.join("workspace/prune.txt"),
        b"bounded observation",
    )
    .unwrap();
    let run=fixture.calls(vec![json!({"id":"large","name":"terminal","arguments":{"argv":["/bin/sh","-c","/usr/bin/python3 -c 'import sys; sys.stdout.write(chr(34)*350000)'; exit 7"],"timeout_ms":1000}}),json!({"id":"prune-one","name":"read_file","arguments":{"path":"prune.txt"}}),json!({"id":"prune-two","name":"read_file","arguments":{"path":"prune.txt"}})]).await;
    assert!(
        !fixture
            .state
            .service()
            .run_events(&run.run_id)
            .iter()
            .any(
                |event| event["event"] == "tool.output" && event["data"]["tool_call_id"] == "large"
            ),
        "the large call event must actually be pruned before replay"
    );
    let request = ManagedFixture::request(&run, "large");
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert!(
        record.outcome.is_some(),
        "large full result must commit without occupying the bounded SQL payload; prepared={}, state={:?}; events={:?}",
        record.prepared.is_some(),
        record.state,
        fixture
            .state
            .service()
            .run_events(&run.run_id)
            .iter()
            .map(|event| (
                event["event"].clone(),
                event["data"]["error_code"].clone(),
                event["data"]["code"].clone()
            ))
            .collect::<Vec<_>>()
    );
    let replay = fixture
        .state
        .service()
        .replay_managed_call(request.clone())
        .unwrap();
    let ManagedCallReplay::Final {
        canonical_result, ..
    } = &replay
    else {
        panic!("expected exact canonical result");
    };
    assert!(canonical_result.as_str().len() > 1024 * 1024);
    let full: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
    assert_eq!(full["ok"], true);
    assert_eq!(full["data"]["exit_code"], 7);
    assert_eq!(full["data"]["stdout"].as_str().unwrap().len(), 350000);
    assert_eq!(full["truncated"], false);
    let messages = fixture
        .state
        .persistence()
        .unwrap()
        .message_list(&run.session_id, 0)
        .unwrap();
    assert!(
        messages.to_string().len() < 128 * 1024,
        "large data belongs in the immutable canonical result, not the message projection"
    );
    let reopened = fixture.reopen().await;
    assert_eq!(
        reopened
            .state
            .service()
            .replay_managed_call(request)
            .unwrap(),
        replay
    );
    reopened.state.service().shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn readonly_exact_base_observation_survives_concurrent_head_advance_without_publication() {
    use rustscript_agent::effects::{ManagedCallReplay, ManagedPublicationStatus};
    let fixture = ManagedFixture::new(|_| {});
    fs::write(fixture.root.join("workspace/observe.txt"), b"before").unwrap();
    let gate = fixture
        .state
        .service()
        .arm_managed_call_prepare_gate("observe")
        .unwrap();
    let read = fixture
        .state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"observe base"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(response(Some(
        json!({"id":"observe","name":"read_file","arguments":{"path":"observe.txt"}}),
    )));
    provider.push_ok(response(None));
    fixture.state.service().inject_provider_host(provider);
    let reader = tokio::spawn(
        fixture
            .state
            .service()
            .run_worker(read.run_id.clone(), "ignored".into()),
    );
    let arrival = gate.wait_arrived(1);
    if arrival.is_err() {
        gate.release();
        reader.await.unwrap();
        panic!("real read did not prepare: {arrival:?}");
    }
    let write=fixture.calls(vec![json!({"id":"advance","name":"write_file","arguments":{"path":"observe.txt","content":"after"}})]).await;
    let written = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&ManagedFixture::request(&write, "advance"))
        .unwrap()
        .unwrap();
    let advanced = fixture
        .state
        .persistence()
        .unwrap()
        .managed_workspace_head(&written.identity.workspace)
        .unwrap();
    assert_eq!(advanced.head_version, 2);
    gate.release();
    reader.await.unwrap();
    drop(gate);
    let request = ManagedFixture::request(&read, "observe");
    let observation = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert_eq!(
        observation.outcome.as_ref().unwrap().disposition,
        ManagedPublicationStatus::ReadOnly
    );
    assert_eq!(observation.identity.expected_head_version, 1);
    assert_eq!(
        observation
            .outcome
            .as_ref()
            .unwrap()
            .publication
            .observed_head,
        advanced.head_object_id
    );
    assert_eq!(
        fixture
            .state
            .persistence()
            .unwrap()
            .managed_workspace_head(&written.identity.workspace)
            .unwrap(),
        advanced
    );
    let replay = fixture
        .state
        .service()
        .replay_managed_call(request.clone())
        .unwrap();
    let ManagedCallReplay::Final {
        canonical_result, ..
    } = &replay
    else {
        panic!("expected base observation");
    };
    let full: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
    assert!(full["content"].as_str().unwrap().contains("before"));
    assert!(!full["content"].as_str().unwrap().contains("after"));
    let reopened = fixture.reopen().await;
    assert_eq!(
        reopened
            .state
            .service()
            .replay_managed_call(request)
            .unwrap(),
        replay
    );
    reopened.state.service().shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn preintent_and_partial_begin_failures_leave_zero_operation_or_durable_pair() {
    use rustscript_agent::effects::ManagedEffectFault;
    for cut in [
        ManagedEffectFault::BeforeIntent,
        ManagedEffectFault::BeginAfterFirstEvent,
    ] {
        let fixture = ManagedFixture::new(|_| {});
        fixture
            .state
            .service()
            .inject_managed_effect_fault(cut)
            .unwrap();
        let sentinel = fixture.root.join("external-sentinel");
        let command = format!("printf x >> '{}'", sentinel.display());
        let run=fixture.calls(vec![json!({"id":"never","name":"terminal","arguments":{"argv":["/bin/sh","-c",command],"timeout_ms":1000}})]).await;
        let request = ManagedFixture::request(&run, "never");
        assert!(
            fixture
                .state
                .persistence()
                .unwrap()
                .managed_effect_get(&request)
                .unwrap()
                .is_none(),
            "begin failure must leave no durable intent: {cut:?}"
        );
        assert!(
            !sentinel.exists(),
            "begin failure must not execute: {cut:?}"
        );
        assert_eq!(
            fs::read_dir(fixture.root.join(".gateway.sqlite.effects/views"))
                .unwrap()
                .count(),
            0
        );
        for name in [
            "tool.requested",
            "tool.started",
            "tool.output",
            "tool.completed",
            "tool.failed",
        ] {
            assert_eq!(
                fixture
                    .state
                    .service()
                    .run_events(&run.run_id)
                    .iter()
                    .filter(|event| event["event"] == name)
                    .count(),
                0,
                "partial managed pair survived: {cut:?} {name}"
            );
        }
        let reopened = fixture.reopen().await;
        assert!(
            reopened
                .state
                .persistence()
                .unwrap()
                .managed_effect_get(&request)
                .unwrap()
                .is_none()
        );
        assert!(!sentinel.exists());
        reopened.state.service().shutdown().await.unwrap();
    }
}

#[test]
fn managed_startup_configuration_is_opt_in_and_rejects_invalid_source_or_retention() {
    let direct = AgentGatewayConfig::default();
    assert!(direct.managed_workspace.is_none());
    assert!(direct.validate().is_ok());
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("managed-config-{}", uuid::Uuid::new_v4().simple()));
    fs::create_dir(&root).unwrap();
    let mut configured = direct;
    configured.managed_workspace = Some(ManagedWorkspaceConfig {
        source_root: root,
        quota: ResourceQuota::new(1000, 1048576, 16).unwrap(),
        retention: ManagedRetentionLimits::default(),
        maintenance_policy: Default::default(),
    });
    assert!(configured.validate().is_ok());
    let mut invalid = configured.clone();
    invalid.managed_workspace.as_mut().unwrap().source_root = PathBuf::from("relative");
    assert!(
        invalid.validate().is_err(),
        "relative managed source must fail before startup"
    );
    let mut invalid = configured.clone();
    invalid
        .managed_workspace
        .as_mut()
        .unwrap()
        .retention
        .max_objects = 0;
    assert!(
        invalid.validate().is_err(),
        "zero object admission bound must fail before startup"
    );
    let mut invalid = configured;
    invalid
        .managed_workspace
        .as_mut()
        .unwrap()
        .retention
        .max_bytes = 0;
    assert!(
        invalid.validate().is_err(),
        "zero byte admission bound must fail before startup"
    );
}

/// Minimal provider that can only answer from what the run itself produced:
/// the managed producer's returned process handle is read out of the previous
/// tool result, so every continuation is a real cross-call Native operation.
struct CrossCallProvider {
    turns: std::sync::Mutex<Vec<Value>>,
    spawn_arguments: std::sync::Mutex<Option<Value>>,
    origin: std::time::Instant,
    marks: std::sync::Mutex<Vec<(usize, u128)>>,
}
impl CrossCallProvider {
    fn new() -> Self {
        Self {
            turns: std::sync::Mutex::new(Vec::new()),
            spawn_arguments: std::sync::Mutex::new(None),
            origin: std::time::Instant::now(),
            marks: std::sync::Mutex::new(Vec::new()),
        }
    }
    fn observed(&self) -> Vec<Value> {
        self.turns.lock().unwrap().clone()
    }
    fn marks(&self) -> Vec<(usize, u128)> {
        self.marks.lock().unwrap().clone()
    }
    fn spawn_arguments(&self) -> Option<Value> {
        self.spawn_arguments.lock().unwrap().clone()
    }
}
fn find_process_id(value: &Value) -> Option<String> {
    match value {
        Value::Object(fields) => {
            if let Some(Value::String(id)) = fields.get("process_id") {
                return Some(id.clone());
            }
            fields.values().find_map(find_process_id)
        }
        Value::Array(items) => items.iter().find_map(find_process_id),
        _ => None,
    }
}
fn tool_call(id: &str, name: &str, arguments: Value) -> Value {
    json!({"text":"","tool_calls":[{"id":id,"name":name,"arguments":arguments}],
        "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},
        "reasoning":"","stop_reason":"stop"})
}
fn no_call() -> Value {
    json!({"text":"done","tool_calls":[],
        "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},
        "reasoning":"","stop_reason":"stop"})
}
impl rustscript_agent::AgentProviderHost for CrossCallProvider {
    fn call(&self, request: &Value, _cancellation: &rustscript_agent::RunCancellation) -> Value {
        let mut turns = self.turns.lock().unwrap();
        turns.push(request.clone());
        let turn = turns.len();
        self.marks
            .lock()
            .unwrap()
            .push((turn, self.origin.elapsed().as_millis()));
        let handle = find_process_id(request).unwrap_or_default();
        let response = match turn {
            // No `timeout_ms`: the positive control uses the terminal tool's
            // own default lifetime (30000ms), not a test-armed 4000ms window.
            1 => {
                let arguments = json!({
                    "argv":["/bin/sh","-c","printf 'produced-body\\n' > produced.txt; sleep 0.4"],
                    "background": true
                });
                assert!(
                    !arguments
                        .as_object()
                        .expect("spawn arguments object")
                        .contains_key("timeout_ms"),
                    "positive control must omit timeout_ms: {arguments}"
                );
                *self.spawn_arguments.lock().unwrap() = Some(arguments.clone());
                tool_call("spawn", "terminal", arguments)
            }
            2 => tool_call(
                "poll",
                "process",
                json!({"action":"poll","process_id":handle}),
            ),
            3 => tool_call(
                "log",
                "process",
                json!({"action":"log","process_id":handle,"offset":0}),
            ),
            4 => tool_call(
                "wait",
                "process",
                json!({"action":"wait","process_id":handle,"timeout_ms":5000}),
            ),
            5 => tool_call(
                "read",
                "terminal",
                json!({"argv":["cat","produced.txt"],"timeout_ms":2000}),
            ),
            _ => no_call(),
        };
        json!({"ok":true,"response":response,"error":{}})
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_background_producer_and_cross_call_process_control_publish_once() {
    use rustscript_agent::effects::{
        ManagedOperationClass, ManagedPublicationStatus, ManagedWriterState,
    };
    let fixture = ManagedFixture::new(|_| {});
    let provider = Arc::new(CrossCallProvider::new());
    fixture
        .state
        .service()
        .inject_provider_host(Arc::clone(&provider) as Arc<dyn rustscript_agent::AgentProviderHost>);
    let run = fixture
        .state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"managed background producer"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    fixture
        .state
        .service()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    let persistence = fixture.state.persistence().unwrap();
    let record = |call: &str| {
        persistence
            .managed_effect_get(&ManagedFixture::request(&run, call))
            .unwrap()
            .unwrap_or_else(|| panic!("managed receipt missing for {call}"))
    };
    // Producer: a live handle transferred to the run, never a snapshot.
    let spawn = record("spawn");
    let spawn_outcome = spawn.outcome.as_ref().expect("producer committed");
    assert_eq!(
        spawn_outcome.disposition,
        ManagedPublicationStatus::ReadOnly
    );
    let spawn_prepared = spawn.prepared.as_ref().expect("producer prepared");
    assert_eq!(
        spawn_prepared.operation_class,
        ManagedOperationClass::ReadOnly
    );
    assert!(spawn_prepared.candidate_root.is_none());
    assert_eq!(spawn_prepared.writer_state, ManagedWriterState::Settled);
    let base_head = spawn_outcome.publication.base_head.clone();
    assert_eq!(base_head, spawn.identity.expected_head);
    // Continuations are same-run owned reads, not publications.
    for call in ["poll", "log"] {
        let record = record(call);
        let outcome = record.outcome.as_ref().expect("control committed");
        assert_eq!(
            outcome.disposition,
            ManagedPublicationStatus::ReadOnly,
            "{call}"
        );
        assert!(
            record
                .prepared
                .as_ref()
                .is_some_and(|prepared| prepared.candidate_root.is_none()),
            "{call} must not prepare a candidate"
        );
    }
    // The wait finalizes the produced view exactly once, on the producer base.
    let wait = record("wait");
    // R1 diagnostic (T14-644): print the typed receipt facts the failed exact
    // did not retain and could not be reconstructed from. Values come only
    // from the already-fetched managed records and the bounded result-read
    // API; no payload body, private config, token, or fixture SQLite.
    {
        let facts =
            |call: &str, record: &rustscript_agent::effects::ManagedEffectRecord| match record
                .prepared
                .as_ref()
            {
                Some(prepared) => eprintln!(
                    "R1-DIAG {call}: observation_ok={} prepared_at_ms={} disposition={:?}",
                    prepared.observation_ok,
                    prepared.prepared_at_ms,
                    record
                        .outcome
                        .as_ref()
                        .map(|outcome| outcome.disposition.clone())
                ),
                None => eprintln!("R1-DIAG {call}: prepared=missing"),
            };
        facts("spawn", &spawn);
        facts("poll", &record("poll"));
        facts("log", &record("log"));
        facts("wait", &wait);
        let gap = wait.prepared.as_ref().zip(spawn.prepared.as_ref()).map(
            |(wait_prepared, spawn_prepared)| {
                wait_prepared
                    .prepared_at_ms
                    .saturating_sub(spawn_prepared.prepared_at_ms)
            },
        );
        eprintln!("R1-DIAG wait_minus_spawn_prepared_ms={gap:?}");
        eprintln!("R1-DIAG turn_marks_ms={:?}", provider.marks());
        match fixture.state.service().read_managed_result_chunk(
            rustscript_agent::effects::ManagedResultReadRequest {
                effect_id: wait.effect_id.clone(),
                offset: 0,
                limit: 131072,
            },
        ) {
            Ok(chunk) => {
                let summary = serde_json::from_slice::<Value>(&chunk.bytes)
                    .ok()
                    .map(|value| {
                        json!({
                            "ok": value["ok"].clone(),
                            "error_code": value["error"]["code"].clone(),
                            "error_message": value["error"]["message"].clone(),
                            "data_status": value["data"]["status"].clone(),
                            "data_exit_code": value["data"]["exit_code"].clone(),
                        })
                    });
                eprintln!(
                    "R1-DIAG wait_result bytes={} eof={} total_bytes={} summary={summary:?}",
                    chunk.bytes.len(),
                    chunk.eof,
                    chunk.total_bytes
                );
            }
            Err(error) => eprintln!("R1-DIAG wait_result unavailable: {error}"),
        }
    }
    let wait_outcome = wait.outcome.as_ref().expect("wait published");
    assert_eq!(
        wait_outcome.disposition,
        ManagedPublicationStatus::Committed
    );
    let wait_prepared = wait.prepared.as_ref().expect("wait prepared");
    assert_eq!(
        wait_prepared.operation_class,
        ManagedOperationClass::TreeWrite
    );
    assert!(wait_prepared.candidate_root.is_some());
    assert_eq!(wait_outcome.publication.base_head, base_head);
    let published = wait_outcome
        .publication
        .candidate_head
        .clone()
        .expect("published head");
    assert_ne!(published, base_head, "publication must advance the head");
    // The next call reads the published tree, and the source stays untouched.
    let read = record("read");
    assert_eq!(
        read.outcome.as_ref().unwrap().disposition,
        ManagedPublicationStatus::Committed
    );
    assert_eq!(read.identity.expected_head, published);
    let messages =
        serde_json::to_value(fixture.state.service().session_messages(&run.session_id)).unwrap();
    let results: Vec<Value> = messages
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|message| message["content"].as_array().into_iter().flatten())
        .filter(|block| block["type"] == "tool_result")
        .cloned()
        .collect();
    assert_eq!(results.len(), 5);
    assert_eq!(results[0]["result"]["status"], "running");
    assert!(
        results[0]["result"]["process_id"]
            .as_str()
            .is_some_and(|id| id.len() >= 32)
    );
    assert_eq!(results[3]["result"]["status"], "exited");
    let stdout = results[4]["result"]["stdout"].as_str().unwrap_or("");
    assert!(
        stdout.contains("produced-body"),
        "the published view must carry the produced file: {stdout:?}"
    );
    assert!(
        !fixture.root.join("workspace/produced.txt").exists(),
        "managed effects never write the authorized source"
    );
    assert_eq!(
        provider.observed().len(),
        6,
        "five tool turns plus the terminating model turn"
    );
    // T14-645: the actual spawn request sent to the terminal tool must carry
    // no caller timeout, so the process lifetime is the tool default.
    let spawn_arguments = provider
        .spawn_arguments()
        .expect("positive control issued a spawn request");
    assert!(
        !spawn_arguments
            .as_object()
            .expect("spawn arguments object")
            .contains_key("timeout_ms"),
        "actual spawn request must omit timeout_ms: {spawn_arguments}"
    );
    fixture.state.service().shutdown().await.unwrap();
}

/// Minimal provider for the R1 negative control: one real background producer
/// transferred to the run, then one same-run `wait` on the returned handle.
struct DeadlineProducerProvider {
    turns: std::sync::Mutex<Vec<Value>>,
    spawn_timeout_ms: u64,
}
impl DeadlineProducerProvider {
    fn new(spawn_timeout_ms: u64) -> Self {
        Self {
            turns: std::sync::Mutex::new(Vec::new()),
            spawn_timeout_ms,
        }
    }
}
impl rustscript_agent::AgentProviderHost for DeadlineProducerProvider {
    fn call(&self, request: &Value, _cancellation: &rustscript_agent::RunCancellation) -> Value {
        let mut turns = self.turns.lock().unwrap();
        turns.push(request.clone());
        let turn = turns.len();
        let handle = find_process_id(request).unwrap_or_default();
        let response = match turn {
            1 => tool_call(
                "spawn",
                "terminal",
                json!({"argv":["/bin/sh","-c","printf 'deadline-body\\n' > produced.txt; exit 0"],
                    "background":true,"timeout_ms":self.spawn_timeout_ms}),
            ),
            2 => tool_call(
                "wait",
                "process",
                json!({"action":"wait","process_id":handle,"timeout_ms":5000}),
            ),
            _ => no_call(),
        };
        json!({"ok":true,"response":response,"error":{}})
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_background_producer_past_deadline_is_not_published() {
    // Deterministic negative control for R1 (T14-644): the producer's own
    // process lifetime is the caller's `timeout_ms` (200ms here). The child
    // exits immediately, but the later cross-call wait polls after that
    // deadline, so Native reports `deadline_elapsed` for an already-reaped
    // child. The managed wait must record that exact code and must not publish
    // a candidate. No sleep, fake process, or production clock change.
    use rustscript_agent::effects::{
        ManagedOperationClass, ManagedPublicationStatus, ManagedResultReadRequest,
    };
    let fixture = ManagedFixture::new(|_| {});
    let provider = Arc::new(DeadlineProducerProvider::new(200));
    fixture
        .state
        .service()
        .inject_provider_host(Arc::clone(&provider) as Arc<dyn rustscript_agent::AgentProviderHost>);
    let run = fixture
        .state
        .service()
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"managed producer deadline control"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    fixture
        .state
        .service()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    let persistence = fixture.state.persistence().unwrap();
    let record = |call: &str| {
        persistence
            .managed_effect_get(&ManagedFixture::request(&run, call))
            .unwrap()
            .unwrap_or_else(|| panic!("managed receipt missing for {call}"))
    };
    let spawn = record("spawn");
    let spawn_outcome = spawn.outcome.as_ref().expect("producer committed");
    assert_eq!(
        spawn_outcome.disposition,
        ManagedPublicationStatus::ReadOnly
    );
    let base_head = spawn_outcome.publication.base_head.clone();
    assert_eq!(base_head, spawn.identity.expected_head);
    let wait = record("wait");
    let wait_outcome = wait.outcome.as_ref().expect("wait receipt");
    assert_eq!(
        wait_outcome.disposition,
        ManagedPublicationStatus::NotPublished
    );
    let wait_prepared = wait.prepared.as_ref().expect("wait prepared");
    assert!(
        !wait_prepared.observation_ok,
        "an elapsed producer deadline must not be observed as ok"
    );
    assert!(
        wait_prepared.candidate_root.is_none(),
        "a failed observation must not prepare a candidate"
    );
    assert_eq!(
        wait_prepared.operation_class,
        ManagedOperationClass::TreeWrite
    );
    assert_eq!(wait_outcome.publication.base_head, base_head);
    assert!(wait_outcome.publication.candidate_head.is_none());
    let chunk = fixture
        .state
        .service()
        .read_managed_result_chunk(ManagedResultReadRequest {
            effect_id: wait.effect_id.clone(),
            offset: 0,
            limit: 131072,
        })
        .unwrap();
    let result: Value = serde_json::from_slice(&chunk.bytes).unwrap();
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"]["code"], "deadline_elapsed", "{result}");
    assert!(
        !fixture.root.join("workspace/produced.txt").exists(),
        "a deadline-expired producer view must never reach the source"
    );
    fixture.state.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_process_controls_require_own_handles_and_captured_authority() {
    // A forged handle is a per-call typed refusal: no publication, no view,
    // and never a fallback that treats the string as authority.
    let fixture = ManagedFixture::new(|_| {});
    let run = fixture
        .calls(vec![json!({"id":"forged","name":"process","arguments":{"action":"poll","process_id":"public-id-not-authority"}})])
        .await;
    let events = fixture.state.service().run_events(&run.run_id);
    assert!(
        events
            .iter()
            .any(|event| event["data"]["error_code"] == "process_not_found"),
        "a forged handle must surface the existing typed code: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| event["event"] == "tool.completed"),
        "a forged handle never completes"
    );
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&ManagedFixture::request(&run, "forged"))
        .unwrap();
    // The call did start, so a receipt exists; it must stay a non-publication
    // with no prepared candidate and no head movement.
    assert!(
        record.as_ref().is_some_and(|record| {
            record
                .prepared
                .as_ref()
                .is_some_and(|prepared| prepared.candidate_root.is_none())
                && record.outcome.as_ref().is_some_and(|outcome| {
                    outcome.disposition
                        == rustscript_agent::effects::ManagedPublicationStatus::NotPublished
                        && outcome.publication.candidate_head.is_none()
                })
        }),
        "a forged handle must not publish"
    );
    assert_eq!(
        fs::read_dir(fixture.root.join(".gateway.sqlite.effects/views"))
            .unwrap()
            .count(),
        0
    );
    fixture.state.service().shutdown().await.unwrap();
    // Without the captured process approval, the producer is refused before any
    // durable intent, Native spawn or view.
    let denied = ManagedFixture::new(|config| {
        config.approvals.process = "deny".into();
    });
    let run = denied
        .calls(vec![json!({"id":"denied","name":"terminal","arguments":{"argv":["/bin/sh","-c","exit 0"],"background":true,"timeout_ms":1000}})])
        .await;
    assert!(
        denied
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&ManagedFixture::request(&run, "denied"))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fs::read_dir(denied.root.join(".gateway.sqlite.effects/views"))
            .unwrap()
            .count(),
        0
    );
    assert!(
        !denied
            .state
            .service()
            .run_events(&run.run_id)
            .iter()
            .any(|event| event["event"] == "tool.started")
    );
    denied.state.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_requires_exact_owner_and_current_native_source_identity_and_never_reimports_missing_objects()
 {
    use rustscript_agent::effects::ManagedCallReplay;
    let fixture = ManagedFixture::new(|_| {});
    let run=fixture.calls(vec![json!({"id":"write","name":"write_file","arguments":{"path":"proof.txt","content":"original"}})]).await;
    let request = ManagedFixture::request(&run, "write");
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    let head = fixture
        .state
        .persistence()
        .unwrap()
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    let mut wrong = request.clone();
    wrong.owner.session_id = "different-session".into();
    assert!(matches!(
        fixture.state.service().replay_managed_call(wrong).unwrap(),
        ManagedCallReplay::Unavailable { .. }
    ));
    let result = fixture.root.join(".gateway.sqlite.effects/results").join(
        &record
            .outcome
            .as_ref()
            .unwrap()
            .canonical_result_ref
            .object_id,
    );
    fs::rename(&result, result.with_extension("quarantined")).unwrap();
    assert!(
        fixture
            .state
            .service()
            .replay_managed_call(request.clone())
            .is_err()
    );
    assert!(!result.exists());
    assert_eq!(
        fixture
            .state
            .persistence()
            .unwrap()
            .managed_workspace_head(&record.identity.workspace)
            .unwrap(),
        head
    );
    fs::rename(result.with_extension("quarantined"), &result).unwrap();
    fs::rename(
        fixture.root.join("workspace"),
        fixture.root.join("old-workspace"),
    )
    .unwrap();
    fs::create_dir(fixture.root.join("workspace")).unwrap();
    assert!(
        fixture
            .state
            .service()
            .replay_managed_call(request.clone())
            .is_err(),
        "saved receipt and display path cannot authorize a replaced source inode"
    );
    let reopened = fixture.reopen().await;
    assert!(
        reopened
            .state
            .service()
            .replay_managed_call(request)
            .is_err()
    );
    assert_eq!(
        reopened
            .state
            .persistence()
            .unwrap()
            .managed_workspace_head(&record.identity.workspace)
            .unwrap(),
        head
    );
    assert!(!reopened.root.join("workspace/proof.txt").exists());
    reopened.state.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_history_blocks_legacy_session_delete_with_typed_error_and_exact_readback() {
    let fixture = ManagedFixture::new(|_| {});
    let run=fixture.calls(vec![json!({"id":"retain","name":"write_file","arguments":{"path":"keep.txt","content":"retained"}})]).await;
    let request = ManagedFixture::request(&run, "retain");
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    let before = fixture
        .state
        .persistence()
        .unwrap()
        .message_list(&run.session_id, 0)
        .unwrap();
    let error = fixture
        .state
        .persistence()
        .unwrap()
        .session_delete(&run.session_id)
        .expect_err("retained effect prevents cascaded deletion");
    assert_eq!(error.code, "managed_effect_retained");
    assert_eq!(
        fixture
            .state
            .persistence()
            .unwrap()
            .message_list(&run.session_id, 0)
            .unwrap(),
        before
    );
    assert_eq!(
        fixture
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap(),
        record
    );
    let reopened = fixture.reopen().await;
    assert_eq!(
        reopened
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap(),
        record
    );
    reopened.state.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn real_guest_approval_storage_cannot_forward_any_effect_mutation_or_query() {
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap()).join(format!(
        "managed-guest-fence-{}",
        uuid::Uuid::new_v4().simple()
    ));
    fs::create_dir(&root).unwrap();
    let source = r#"
    pub fn run(context:map)->map {
        let run_id:string=context["run_id"];let session_id:string=context["session_id"];
        let commit:map=agent::approval_storage("effect.commit",{run_id:run_id.copy(),session_id:session_id.copy(),effect_id:"guest-receipt"});
        let get:map=agent::approval_storage("effect.get",{run_id:run_id.copy(),session_id:session_id.copy(),call_id:"guest-call"});
        let recover:map=agent::approval_storage("effect.recover_one",{run_id:run_id.copy(),session_id:session_id.copy(),effect_id:"guest-receipt"});
        let a:map=commit["error"];let b:map=get["error"];let c:map=recover["error"];
        let ac:string=a["code"];let bc:string=b["code"];let cc:string=c["code"];
        {kind:"run.completed",answer:ac+";"+bc+";"+cc}
    }
    "#;
    let state = AgentGatewayState::with_agent_source_and_sqlite(
        AgentGatewayConfig::default(),
        source,
        root.join("gateway.sqlite"),
    )
    .unwrap();
    let provider = Arc::new(ScriptedProvider::new());
    state.service().inject_provider_host(provider.clone());
    let run = state
        .service()
        .admit(AdmitRunRequest {
            input: json!({"message":"guest storage fence"}),
            ..Default::default()
        })
        .await
        .unwrap();
    state
        .service()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    assert_eq!(provider.call_count(), 0);
    let messages = state
        .persistence()
        .unwrap()
        .message_list(&run.session_id, 0)
        .unwrap();
    assert!(messages.to_string().contains(
        "approval_operation_invalid;approval_operation_invalid;approval_operation_invalid"
    ));
    assert!(
        !state
            .service()
            .run_events(&run.run_id)
            .iter()
            .any(|event| event["event"] == "tool.started")
    );
    assert!(!root.join(".gateway.sqlite.effects").exists());
    state.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn typed_effect_pages_and_exact_bounded_result_chunks_require_current_native_authority() {
    use rustscript_agent::effects::{
        ManagedCallReplay, ManagedEffectListRequest, ManagedResultReadRequest,
    };
    let fixture = ManagedFixture::new(|_| {});
    let run = fixture
        .calls(vec![
            json!({"id":"one","name":"write_file","arguments":{"path":"one.txt","content":"one"}}),
            json!({"id":"two","name":"write_file","arguments":{"path":"two.txt","content":"two"}}),
        ])
        .await;
    let records = ["one", "two"]
        .iter()
        .map(|call| {
            fixture
                .state
                .persistence()
                .unwrap()
                .managed_effect_get(&ManagedFixture::request(&run, call))
                .unwrap()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let request = ManagedEffectListRequest {
        workspace_id: records[0].identity.workspace.workspace_id.clone(),
        after_effect_id: None,
        limit: 1,
    };
    let first = fixture
        .state
        .service()
        .query_managed_effects(request.clone())
        .expect("formal scoped effect page must be implemented");
    assert_eq!(first.entries.len(), 1);
    assert!(first.has_more);
    assert!(first.next_cursor.is_some());
    let second = fixture
        .state
        .service()
        .query_managed_effects(ManagedEffectListRequest {
            after_effect_id: first.next_cursor.clone(),
            ..request.clone()
        })
        .unwrap();
    assert_eq!(second.entries.len(), 1);
    assert!(!second.has_more);
    assert!(second.next_cursor.is_none());
    let actual = [
        first.entries[0].effect_id.clone(),
        second.entries[0].effect_id.clone(),
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    let expected = records
        .iter()
        .map(|record| record.effect_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected);
    for limit in [0, 129] {
        assert!(
            fixture
                .state
                .service()
                .query_managed_effects(ManagedEffectListRequest {
                    limit,
                    ..request.clone()
                })
                .is_err()
        );
    }
    assert!(
        fixture
            .state
            .service()
            .query_managed_effects(ManagedEffectListRequest {
                after_effect_id: Some("../not-an-id".into()),
                ..request.clone()
            })
            .is_err()
    );
    let mut bytes = Vec::new();
    let mut offset = 0;
    for _ in 0..4096 {
        let chunk = fixture
            .state
            .service()
            .read_managed_result_chunk(ManagedResultReadRequest {
                effect_id: records[0].effect_id.clone(),
                offset,
                limit: 17,
            })
            .unwrap();
        assert!(chunk.bytes.len() <= 17);
        assert_eq!(chunk.next_offset, offset + chunk.bytes.len() as u64);
        assert!(serde_json::to_vec(&chunk).unwrap().len() < 1024 * 1024);
        bytes.extend_from_slice(&chunk.bytes);
        offset = chunk.next_offset;
        if chunk.eof {
            assert_eq!(offset, chunk.total_bytes);
            break;
        }
    }
    let ManagedCallReplay::Final {
        canonical_result, ..
    } = fixture
        .state
        .service()
        .replay_managed_call(ManagedFixture::request(&run, "one"))
        .unwrap()
    else {
        panic!("expected exact full result");
    };
    assert_eq!(bytes, canonical_result.as_str().as_bytes());
    for (offset, limit) in [(0, 0), (0, 131073), (bytes.len() as u64 + 1, 1)] {
        assert!(
            fixture
                .state
                .service()
                .read_managed_result_chunk(ManagedResultReadRequest {
                    effect_id: records[0].effect_id.clone(),
                    offset,
                    limit
                })
                .is_err()
        );
    }
    fs::rename(
        fixture.root.join("workspace"),
        fixture.root.join("previous-workspace"),
    )
    .unwrap();
    fs::create_dir(fixture.root.join("workspace")).unwrap();
    assert!(
        fixture
            .state
            .service()
            .query_managed_effects(request)
            .is_err()
    );
    assert!(
        fixture
            .state
            .service()
            .read_managed_result_chunk(ManagedResultReadRequest {
                effect_id: records[0].effect_id.clone(),
                offset: 0,
                limit: 17
            })
            .is_err()
    );
    fixture.state.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn durable_retention_capacity_survives_fresh_restart_and_denies_before_terminal_spawn() {
    let fixture = ManagedFixture::new(|config| {
        config
            .managed_workspace
            .as_mut()
            .unwrap()
            .retention
            .max_objects = 5
    });
    let first=fixture.calls(vec![json!({"id":"kept","name":"write_file","arguments":{"path":"kept.txt","content":"retained"}})]).await;
    let request = ManagedFixture::request(&first, "kept");
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert!(record.outcome.is_some());
    assert_eq!(
        fs::read_dir(fixture.root.join(".gateway.sqlite.effects/views"))
            .unwrap()
            .count(),
        0,
        "a positively settled committed view is reclaimed only after both Native lease and exact durable reference checks"
    );
    let references = fixture
        .state
        .persistence()
        .unwrap()
        .managed_object_references(&rustscript_agent::effects::ManagedObjectReferencesRequest {
            store_id: record.identity.workspace.store_id.clone(),
            object_id: record
                .outcome
                .as_ref()
                .unwrap()
                .canonical_result_ref
                .object_id
                .clone(),
        })
        .unwrap();
    assert!(references.iter().any(|reference| reference.reference_kind
        == rustscript_agent::effects::ManagedObjectReferenceKind::SelectedResult));
    let fixture = fixture.reopen().await;
    let sentinel = fixture.root.join("must-not-execute");
    let second=fixture.calls(vec![json!({"id":"denied","name":"terminal","arguments":{"argv":["/bin/sh","-c",format!("printf x >> '{}'",sentinel.display())],"timeout_ms":1000}})]).await;
    assert!(
        !sentinel.exists(),
        "durable capacity must be reserved before a new actual terminal operation, including after restart"
    );
    assert!(
        fixture
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&ManagedFixture::request(&second, "denied"))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture
            .state
            .persistence()
            .unwrap()
            .managed_workspace_head(&record.identity.workspace)
            .unwrap()
            .head_version,
        2
    );
    assert!(matches!(
        fixture
            .state
            .service()
            .replay_managed_call(request)
            .unwrap(),
        rustscript_agent::effects::ManagedCallReplay::Final { .. }
    ));
    fixture.state.service().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn large_original_arguments_use_synced_intent_detail_object_without_expanding_sql_bounds() {
    let fixture = ManagedFixture::new(|_| {});
    let content = "q".repeat(50000);
    let run=fixture.calls(vec![json!({"id":"large-argument","name":"write_file","arguments":{"path":"large.txt","content":content}})]).await;
    let request = ManagedFixture::request(&run, "large-argument");
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .expect("large argument intent/receipt must be present");
    let rustscript_agent::effects::ManagedArgumentIdentity::Object { details } =
        &record.identity.argument_identity
    else {
        panic!(
            "large original argument facts require a synced intent detail object, not expanded SQL metadata"
        );
    };
    assert_eq!(
        details.object_kind,
        rustscript_agent::effects::ManagedObjectKind::IntentDetails
    );
    let bytes = fs::read(
        fixture
            .root
            .join(".gateway.sqlite.effects/details")
            .join(&details.object_id),
    )
    .unwrap();
    let arguments: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(arguments["content"], content);
    assert_eq!(details.byte_count, bytes.len().to_string());
    assert!(serde_json::to_vec(&record).unwrap().len() < 16384);
    assert_eq!(
        record.state,
        rustscript_agent::effects::ManagedPublicationStatus::Committed
    );
    let references = fixture
        .state
        .persistence()
        .unwrap()
        .managed_object_references(&rustscript_agent::effects::ManagedObjectReferencesRequest {
            store_id: details.store_id.clone(),
            object_id: details.object_id.clone(),
        })
        .unwrap();
    assert!(references.iter().any(|reference| reference.reference_kind
        == rustscript_agent::effects::ManagedObjectReferenceKind::IntentDetails));
    let before = fixture
        .state
        .service()
        .replay_managed_call(request.clone())
        .unwrap();
    let reopened = fixture.reopen().await;
    assert_eq!(
        reopened
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap(),
        record
    );
    assert_eq!(
        reopened
            .state
            .service()
            .replay_managed_call(request)
            .unwrap(),
        before
    );
    reopened.state.service().shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
struct CutFixture {
    root: PathBuf,
    home: PathBuf,
    config: AgentGatewayConfig,
    state: AgentGatewayState,
    run: rustscript_agent::AdmittedRun,
}

#[cfg(feature = "workspace-io-fault")]
impl CutFixture {
    async fn write(cut: rustscript_agent::effects::ManagedEffectFault) -> Self {
        Self::run(cut, false).await
    }
    async fn terminal(cut: rustscript_agent::effects::ManagedEffectFault) -> Self {
        Self::run(cut, true).await
    }
    async fn run(cut: rustscript_agent::effects::ManagedEffectFault, terminal: bool) -> Self {
        let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
            .join(format!("managed-cut-{}", uuid::Uuid::new_v4().simple()));
        let workspace = root.join("workspace");
        let home = root.join("home");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&home).unwrap();
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(home.join("config.yaml"),format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",workspace.display(),workspace.display())).unwrap();
        let mut config = AgentGatewayConfig {
            managed_workspace: Some(ManagedWorkspaceConfig {
                source_root: workspace,
                quota: ResourceQuota::new(1000, 1048576, 16).unwrap(),
                retention: ManagedRetentionLimits::default(),
                maintenance_policy: Default::default(),
            }),
            ..AgentGatewayConfig::default()
        };
        config.approvals.write = "allow".into();
        config.approvals.process = "allow".into();
        let state =
            AgentGatewayState::with_sqlite_path(config.clone(), root.join("gateway.sqlite"))
                .unwrap()
                .with_workspace_home(&home);
        state.service().inject_managed_effect_fault(cut).unwrap();
        let provider = Arc::new(ScriptedProvider::new());
        let call = if terminal {
            json!({"id":"cut-write","name":"terminal","arguments":{"argv":["/bin/sh","-c",format!("printf x >> '{}'; printf 'staged evidence\\n' > cut.txt",root.join("external-sentinel").display())],"timeout_ms":1000}})
        } else {
            json!({"id":"cut-write","name":"write_file","arguments":{"path":"cut.txt","content":"staged evidence\n"}})
        };
        provider.push_ok(response(Some(call)));
        provider.push_ok(response(None));
        state.service().inject_provider_host(provider);
        let run = state
            .service()
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"write fixture file"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        state
            .service()
            .run_worker(run.run_id.clone(), "ignored".into())
            .await;
        Self {
            root,
            home,
            config,
            state,
            run,
        }
    }
    fn request(&self) -> rustscript_agent::effects::ManagedEffectGetRequest {
        rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: self.run.session_id.clone(),
                run_id: self.run.run_id.clone(),
            },
            call_id: "cut-write".into(),
        }
    }
}

/// Typed durable readback of the literal history a live attempt really left
/// behind. Used only by the two journal recovery fixtures: rows stay literal so
/// before/after comparisons never re-project identities.
#[cfg(feature = "workspace-io-fault")]
struct DurableRows {
    events: Value,
    messages: Value,
}

#[cfg(feature = "workspace-io-fault")]
impl DurableRows {
    fn capture(state: &AgentGatewayState, run: &str, session: &str) -> Self {
        let persistence = state.persistence().unwrap();
        let events = persistence
            .event_replay(&json!({"run_id":run,"after_seq":0,"max_events":256,"max_bytes":1048576}))
            .unwrap();
        let messages = persistence.message_list(session, 0).unwrap();
        Self { events, messages }
    }

    fn cell<'a>(page: &'a Value, row: &'a Value, name: &str) -> &'a Value {
        let columns = page["columns"].as_array().unwrap();
        let index = columns
            .iter()
            .position(|column| column.as_str() == Some(name))
            .unwrap();
        &row[index]
    }

    fn row_with(page: &Value, key: &str, wanted: &str) -> Option<Value> {
        page["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| Self::cell(page, row, key).as_str() == Some(wanted))
            .cloned()
    }

    fn events_for(&self, call: &str) -> Vec<Value> {
        self.events["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| {
                let payload = Self::cell(&self.events, row, "payload_json")
                    .as_str()
                    .unwrap_or("");
                serde_json::from_str::<Value>(payload)
                    .ok()
                    .is_some_and(|payload| {
                        payload.get("tool_call_id").and_then(Value::as_str) == Some(call)
                    })
            })
            .cloned()
            .collect()
    }

    fn seq_of(&self, call: &str, kind: &str) -> Vec<i64> {
        self.events_for(call)
            .iter()
            .filter(|row| Self::cell(&self.events, row, "event_type").as_str() == Some(kind))
            .map(|row| Self::cell(&self.events, row, "seq").as_i64().unwrap())
            .collect()
    }

    fn assert_recovery_refs(
        &self,
        call: &str,
        output: (&str, u64),
        terminal: (&str, u64),
        message: (&str, i64),
    ) {
        let output_row = Self::row_with(&self.events, "event_id", output.0)
            .expect("recovery output event must be durable");
        assert_eq!(
            Self::cell(&self.events, &output_row, "event_type").as_str(),
            Some("tool.output")
        );
        assert_eq!(
            Self::cell(&self.events, &output_row, "seq").as_i64(),
            Some(output.1 as i64)
        );
        let terminal_row = Self::row_with(&self.events, "event_id", terminal.0)
            .expect("recovery terminal event must be durable");
        assert_eq!(
            Self::cell(&self.events, &terminal_row, "event_type").as_str(),
            Some("tool.failed")
        );
        assert_eq!(
            Self::cell(&self.events, &terminal_row, "seq").as_i64(),
            Some(terminal.1 as i64)
        );
        let message_row = Self::row_with(&self.messages, "id", message.0)
            .expect("recovery message must be durable");
        assert_eq!(
            Self::cell(&self.messages, &message_row, "tool_call_id").as_str(),
            Some(call)
        );
        assert_eq!(
            Self::cell(&self.messages, &message_row, "ordinal").as_i64(),
            Some(message.1)
        );
    }

    fn assert_preserved(&self, after: &DurableRows) {
        for row in self.events["rows"].as_array().unwrap() {
            let event_id = Self::cell(&self.events, row, "event_id").as_str().unwrap();
            let retained = Self::row_with(&after.events, "event_id", event_id)
                .unwrap_or_else(|| panic!("pre-existing event row disappeared: {event_id}"));
            assert_eq!(
                retained, *row,
                "pre-existing event row must stay literal: {event_id}"
            );
        }
        for row in self.messages["rows"].as_array().unwrap() {
            let id = Self::cell(&self.messages, row, "id").as_str().unwrap();
            let retained = Self::row_with(&after.messages, "id", id)
                .unwrap_or_else(|| panic!("pre-existing message row disappeared: {id}"));
            assert_eq!(
                retained, *row,
                "pre-existing message row must stay literal: {id}"
            );
        }
    }
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn prepared_receipt_fresh_reopen_stays_staged_without_publication() {
    use rustscript_agent::effects::{ManagedCallReplay, ManagedEffectFault};
    let fixture = CutFixture::write(ManagedEffectFault::AfterPrepared).await;
    let request = fixture.request();
    let record = fixture
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert!(
        record.prepared.is_some(),
        "the real prepared receipt must exist"
    );
    assert!(
        record.outcome.is_none(),
        "a cut after preparation must prevent publication"
    );
    let head = fixture
        .state
        .persistence()
        .unwrap()
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    assert_eq!(head.head_version, 1);
    assert!(!fixture.root.join("workspace/cut.txt").exists());
    let before = DurableRows::capture(
        &fixture.state,
        &request.owner.run_id,
        &request.owner.session_id,
    );
    fixture.state.service().shutdown().await.unwrap();
    let CutFixture {
        root,
        home,
        config,
        state,
        ..
    } = fixture;
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(&home);
    let after = reopened
        .persistence()
        .unwrap()
        .managed_effect_get(&request)
        .unwrap()
        .unwrap();
    assert_eq!(after.prepared, record.prepared);
    assert_eq!(
        after.identity.original_deadline_ms,
        record.identity.original_deadline_ms
    );
    assert!(after.outcome.is_none());
    assert!(matches!(
        reopened
            .service()
            .replay_managed_call(request.clone())
            .unwrap(),
        ManagedCallReplay::Staged { .. }
    ));
    assert_eq!(
        reopened
            .persistence()
            .unwrap()
            .managed_workspace_head(&record.identity.workspace)
            .unwrap(),
        head
    );
    let events = reopened.service().run_events(&request.owner.run_id);
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "tool.output")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "tool.failed")
            .count(),
        1
    );
    assert_managed_canonical_readback(&reopened, &request.owner.run_id);
    // New chronology/history checks stay after the original reopen so the
    // first failure of this test remains the real recover_one collision.
    let after_rows =
        DurableRows::capture(&reopened, &request.owner.run_id, &request.owner.session_id);
    let outputs = after_rows.seq_of("cut-write", "tool.output");
    let terminals = after_rows.seq_of("cut-write", "tool.failed");
    assert_eq!(outputs.len(), 1, "exactly one durable output");
    assert_eq!(terminals.len(), 1, "exactly one durable terminal");
    assert!(
        outputs[0] < terminals[0],
        "a started failure must publish its output before the terminal"
    );
    before.assert_preserved(&after_rows);
    let recovery = after.recovery.as_ref().unwrap();
    after_rows.assert_recovery_refs(
        "cut-write",
        (&recovery.output_event.event_id, recovery.output_event.seq),
        (
            &recovery.terminal_event.event_id,
            recovery.terminal_event.seq,
        ),
        (&recovery.message.id, recovery.message.ordinal),
    );
    let messages = serde_json::to_value(
        reopened
            .service()
            .session_messages(&request.owner.session_id),
    )
    .unwrap();
    reopened.service().shutdown().await.unwrap();
    drop(reopened);
    let again = AgentGatewayState::with_sqlite_path(
        AgentGatewayConfig::default(),
        root.join("gateway.sqlite"),
    )
    .unwrap();
    assert_eq!(again.service().run_events(&request.owner.run_id), events);
    assert_eq!(
        serde_json::to_value(again.service().session_messages(&request.owner.session_id)).unwrap(),
        messages
    );
    assert_eq!(
        again
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap(),
        after
    );
    again.service().shutdown().await.unwrap();
}
