//! T16: real-socket graph hot cut, pinned continuation, checkpoint/restore, and rollback.
//! Admission starts at POST /api/sessions and POST /v1/runs. Request JSON does not grant.
use plugin_effect_api_cycle::{
    Cycle, Http, SecondBusinessGate, activate, assert_closed,
    assert_signed_write_pair_prepares_captured_catalog, assert_typed_terminal, bound_store,
    contains_marker, current_generation, embedding_graph_id, event_names, explain, install_pair,
    pin_for_run, revoke_graph, shutdown_when_idle, stop_turn, tool_call, wait_for, wait_until,
};
use rustscript_agent::ScriptedProvider;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

#[path = "support/plugin_effect_api_cycle.rs"]
mod plugin_effect_api_cycle;
#[allow(dead_code)]
#[path = "support/signed_tool_effects.rs"]
mod signed_tool_effects;

async fn projected_run(http: &Http, token: &str, session_id: &str, run_id: &str) -> String {
    let (status, messages) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &messages));
    messages["data"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter(|message| message["run_id"].as_str() == Some(run_id))
        .map(|message| message.to_string())
        .collect()
}

#[test]
fn signed_stateless_write_pair_prepares_captured_catalog_without_http() {
    let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("t16-catalog-{}", uuid::Uuid::new_v4().simple()));
    let _ = std::fs::remove_dir_all(&root);
    assert_signed_write_pair_prepares_captured_catalog(&root);
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread")]
async fn hot_cut_checkpoint_restore_and_rollback_keep_pinned_receipts() {
    let cycle = Cycle::open(&format!("t16-hot-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (graph_a, generation_a) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let (status, view) = http
        .request(
            "GET",
            &format!("/v1/plugin-graphs/{graph_a}"),
            json!({}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &view));
    assert_eq!(view["graph_id"], graph_a);
    assert!(view["errors"].as_array().unwrap().is_empty());
    assert_closed(&view, &cycle.token, &hidden);

    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("write-a1", "write_file", "out-a.txt"));
    provider.push_ok(tool_call("write-a2", "write_file", "out-a-again.txt"));
    provider.push_ok(stop_turn("done-a"));
    let gate = Arc::new(SecondBusinessGate::new(provider));
    cycle.state.service().inject_provider_host(gate.clone());
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let idem = uuid::Uuid::new_v4().to_string();
    let run_body = json!({
        "session_id": session_id,
        "input": "write the pinned marker",
        "extra": {"graph_id": "fake-graph", "admin": true}
    });
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            run_body.clone(),
            Some(&cycle.token),
            Some(&idem),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph_a);
    assert_ne!(admitted["graph_id"], "fake-graph");
    assert!(admitted["publication"].is_null(), "publication stays null");
    assert!(admitted["workspace_branch"].is_string());
    assert!(admitted["epoch"].is_number());
    assert_closed(&admitted, &cycle.token, &hidden);
    let run_a = admitted["run_id"].as_str().unwrap().to_string();
    let admission_branch = admitted["workspace_branch"].as_str().unwrap().to_string();
    let admission_epoch = admitted["epoch"].as_u64().unwrap();
    let admission_generation = admitted["activation_generation"].as_u64().unwrap();
    assert_eq!(admission_generation, generation_a);

    wait_until(|| gate.holding() && contains_marker(&cycle.state, &run_a, "A-write")).await;
    assert!(
        !contains_marker(&cycle.state, &run_a, "out-a-again.txt"),
        "second invoke must not start before the gate releases"
    );
    let (status, effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_a}/effects?limit=128"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    let write = effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == "write-a1")
        .expect("first native write receipt")
        .clone();
    assert_eq!(write["state"], "committed");
    assert_eq!(write["branch_id"], admission_branch);
    assert_eq!(write["run_id"], run_a);
    assert!(write["epoch"].as_u64().unwrap() >= admission_epoch);
    assert_closed(&effects, &cycle.token, &hidden);
    let workspace_id = write["workspace_id"].as_str().unwrap().to_string();
    let epoch = write["epoch"].as_u64().unwrap();

    let checkpoint_body = json!({
        "source_run_id": run_a,
        "workspace_id": workspace_id,
        "source_branch_id": admission_branch,
        "expected_epoch": epoch,
        "request_id": uuid::Uuid::new_v4().to_string(),
        "mode": "at_closed_batch"
    });
    let (status, checkpoint) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            checkpoint_body.clone(),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &checkpoint));
    assert_eq!(checkpoint["replayed"], false);
    assert_eq!(checkpoint["checkpoint"]["graph"]["graph_id"], graph_a);
    assert_eq!(checkpoint["checkpoint"]["plugin_state"]["roots"], json!([]));
    assert_closed(&checkpoint, &cycle.token, &hidden);
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, replay) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            checkpoint_body,
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &replay));
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["checkpoint"]["checkpoint_id"], checkpoint_id);
    let (status, foreign) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_a,
                "workspace_id": workspace_id,
                "source_branch_id": uuid::Uuid::new_v4().to_string(),
                "expected_epoch": epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &foreign));
    assert_eq!(foreign["error"]["code"], "managed_checkpoint_conflict");
    let (status, mismatch) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{}/checkpoints", uuid::Uuid::new_v4()),
            json!({
                "source_run_id": run_a,
                "workspace_id": workspace_id,
                "source_branch_id": admission_branch,
                "expected_epoch": epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 403, "{}", explain(status, &mismatch));
    assert_eq!(mismatch["error"]["code"], "managed_authority_required");

    let (graph_b, generation_b) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effectb",
    )
    .await;
    assert!(generation_b > generation_a);
    let (status, reread) = http
        .request(
            "POST",
            "/v1/runs",
            run_body,
            Some(&cycle.token),
            Some(&idem),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &reread));
    assert_eq!(reread["run_id"], run_a);
    assert_eq!(reread["graph_id"], graph_a);
    assert_eq!(reread["activation_generation"], generation_a);
    assert!(reread["publication"].is_null());
    let pinned = pin_for_run(&cycle.config, &cycle.db, &run_a);
    assert_eq!(pinned["graph_id"], graph_a);
    assert_eq!(pinned["generation"], generation_a);
    let handles_before_release = cycle.state.service().handle_count();

    gate.release();
    wait_until(|| {
        contains_marker(&cycle.state, &run_a, "out-a-again.txt")
            && event_names(&cycle.state, &run_a)
                .iter()
                .any(|name| name == "run.completed")
    })
    .await;
    assert!(contains_marker(&cycle.state, &run_a, "A-write"));
    assert!(
        !contains_marker(&cycle.state, &run_a, "B-write"),
        "continued A invoke must not execute B"
    );
    let events = http.typed_sse(&cycle.token, &run_a).await;
    assert_typed_terminal(&events, "run.completed");
    let (status, messages) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &messages));
    let frozen_messages = messages["data"].clone();
    assert!(frozen_messages.to_string().contains("A-write"));
    assert!(!frozen_messages.to_string().contains("B-write"));
    assert_closed(&messages, &cycle.token, &hidden);
    let (status, effects_after) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_a}/effects?limit=128"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects_after));
    let second = effects_after["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == "write-a2")
        .expect("second native write receipt");
    assert_eq!(second["state"], "committed");
    assert_eq!(second["branch_id"], admission_branch);

    let provider_b = Arc::new(ScriptedProvider::new());
    provider_b.push_ok(tool_call("write-b", "write_file", "out-b.txt"));
    provider_b.push_ok(stop_turn("done-b"));
    cycle.state.service().inject_provider_host(provider_b);
    let (status, run_b) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write the new graph marker", "extra": {"graph_id": graph_a}}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &run_b));
    assert_eq!(run_b["graph_id"], graph_b);
    assert_eq!(run_b["activation_generation"], generation_b);
    assert!(run_b["publication"].is_null());
    let run_b_id = run_b["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&cycle.state, &run_b_id)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;
    assert!(contains_marker(&cycle.state, &run_b_id, "B-write"));
    assert!(!contains_marker(&cycle.state, &run_a, "B-write"));
    let (status, before_restore) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &before_restore));
    let session_before_restore = before_restore["data"].clone();

    let head = current_head(&cycle, &session_id, &run_a, "write-a1");
    let restore_body = json!({
        "workspace_id": workspace_id,
        "source_branch_id": admission_branch,
        "checkpoint_id": checkpoint_id,
        "expected_source": {
            "store_id": head["store_id"],
            "workspace_id": head["workspace_id"],
            "branch_id": head["branch_id"],
            "epoch": head["epoch"],
            "head_object_id": head["head_object_id"],
            "head_version": head["head_version"]
        },
        "request_id": uuid::Uuid::new_v4().to_string(),
        "input": {"text": "read frozen A"},
        "cancel_active_source": true,
        "graph_selection": "checkpoint_exact"
    });
    let restored_provider = Arc::new(ScriptedProvider::new());
    restored_provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": "read-frozen", "name": "read_file", "arguments": {"path": "out-a.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    restored_provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": "read-absent", "name": "read_file", "arguments": {"path": "out-a-again.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    restored_provider.push_ok(tool_call(
        "write-restored",
        "write_file",
        "out-restored.txt",
    ));
    restored_provider.push_ok(stop_turn("done-restored"));
    cycle
        .state
        .service()
        .inject_provider_host(restored_provider);
    let (status, restored) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/restore"),
            restore_body.clone(),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &restored));
    assert_eq!(restored["disposition"], "restored_and_admitted");
    assert_eq!(restored["graph"]["graph_id"], graph_a);
    assert_eq!(restored["publication"], "managed_only");
    assert_ne!(restored["new_branch"]["branch_id"], admission_branch);
    let new_run = restored["new_run_id"].as_str().unwrap().to_string();
    let new_session = restored["new_session_id"].as_str().unwrap().to_string();
    assert_ne!(new_run, run_a);
    assert_closed(&restored, &cycle.token, &hidden);
    let (status, replayed_restore) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/restore"),
            restore_body,
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &replayed_restore));
    assert_eq!(replayed_restore["replayed"], true);
    assert_eq!(replayed_restore["new_run_id"], new_run);
    let (status, messages_after) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &messages_after));
    assert_eq!(messages_after["data"], session_before_restore);

    let frozen_head = restored["new_branch"]["head_object_id"]
        .as_str()
        .expect("frozen branch head")
        .to_string();
    wait_until(|| {
        typed_tool_block(
            &cycle.state.service().session_messages(&new_session),
            "read-frozen",
        )
        .and_then(|block| block["content"].as_str().map(str::to_string))
        .as_deref()
            == Some("A-write\n")
    })
    .await;
    assert!(
        !contains_marker(&cycle.state, &new_run, "B-write"),
        "restored run must execute the checkpoint graph"
    );
    let restored_pin = pin_for_run(&cycle.config, &cycle.db, &new_run);
    assert_eq!(restored_pin["graph_id"], graph_a);
    let (status, restored_messages) = http
        .request(
            "GET",
            &format!("/api/sessions/{new_session}/messages"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &restored_messages));
    let read_block = typed_tool_block(
        restored_messages["data"]
            .as_array()
            .expect("restored messages"),
        "read-frozen",
    )
    .expect("typed read_file result");
    assert_eq!(read_block["type"], "tool_result");
    assert_eq!(read_block["tool_call_id"], "read-frozen");
    assert_eq!(read_block["is_error"], false);
    assert_eq!(read_block["content"], "A-write\n");
    let tree_path = cycle
        .root
        .join(".gateway.sqlite.effects/trees")
        .join(&frozen_head)
        .join("out-a.txt");
    let tree = std::fs::read(&tree_path).expect("frozen tree bytes");
    assert_eq!(tree, b"A-write\n");
    assert!(
        !cycle
            .root
            .join(".gateway.sqlite.effects/trees")
            .join(&frozen_head)
            .join("out-a-again.txt")
            .exists()
    );
    assert_eq!(
        read_block["content"].as_str().unwrap().as_bytes(),
        tree.as_slice()
    );
    let (status, read_effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{new_run}/effects?limit=128"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &read_effects));
    let read_entry = read_effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == "read-frozen")
        .expect("read-frozen effect");
    assert_eq!(read_entry["state"], "read_only");
    assert_eq!(read_entry["branch_id"], restored["new_branch"]["branch_id"]);
    let persistence = cycle.state.persistence().unwrap();
    let read_request = rustscript_agent::effects::ManagedEffectGetRequest {
        owner: rustscript_agent::effects::ManagedOwnerScope {
            profile: "gateway".into(),
            session_id: new_session.clone(),
            run_id: new_run.clone(),
        },
        call_id: "read-frozen".into(),
    };
    let record = persistence
        .managed_effect_get(&read_request)
        .unwrap()
        .expect("durable read effect");
    assert_eq!(record.identity.tool_name, "read_file");
    assert_eq!(record.identity.approved_risk, "read");
    assert_eq!(
        record.state,
        rustscript_agent::effects::ManagedPublicationStatus::ReadOnly
    );
    let outcome = record.outcome.as_ref().expect("completed read outcome");
    assert!(outcome.publication.candidate_head.is_none());
    assert_eq!(outcome.publication.observed_head, frozen_head);
    assert_eq!(outcome.publication.base_head, frozen_head);
    assert_eq!(
        outcome.publication.status,
        rustscript_agent::effects::ManagedPublicationStatus::ReadOnly
    );
    let reread = persistence
        .managed_effect_get(&read_request)
        .unwrap()
        .expect("reread durable effect");
    assert_eq!(reread, record);
    let body = cycle
        .state
        .service()
        .read_managed_result_chunk(rustscript_agent::effects::ManagedResultReadRequest {
            effect_id: record.effect_id.clone(),
            offset: 0,
            limit: 4096,
        })
        .expect("effect body");
    let body_json: Value = serde_json::from_slice(&body.bytes).expect("effect body json");
    assert_eq!(body_json["ok"], true);
    assert_eq!(body_json["content"], "A-write\n");
    let source_after = current_head(&cycle, &session_id, &run_a, "write-a1");
    assert_eq!(source_after["head_object_id"], head["head_object_id"]);
    assert_eq!(
        source_after["head_version"].as_u64().unwrap(),
        head["head_version"].as_u64().unwrap() + 1,
        "restore CAS may bump source version once; the read must not bump it again"
    );
    assert_eq!(
        source_after["epoch"].as_u64().unwrap(),
        head["epoch"].as_u64().unwrap() + 1
    );
    assert_closed(&restored_messages, &cycle.token, &hidden);
    let (status, old_again) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &old_again));
    assert_eq!(old_again["data"], session_before_restore);

    wait_until(|| {
        let events = cycle.state.service().run_events(&new_run);
        let absent = events.iter().any(|event| {
            event["event"] == "tool.failed"
                && event["data"]["tool_call_id"] == "read-absent"
                && event["data"]["error_code"] == "not_found"
        });
        let written = events.iter().any(|event| {
            event["event"] == "tool.completed" && event["data"]["tool_call_id"] == "write-restored"
        });
        let completed = events.iter().any(|event| event["event"] == "run.completed");
        absent && written && completed
    })
    .await;
    let restored_events = cycle.state.service().run_events(&new_run);
    assert!(
        restored_events
            .iter()
            .any(|event| event["event"] == "run.completed"),
        "restored run must complete after the write commit: {restored_events:?}"
    );
    assert!(
        !restored_events
            .iter()
            .any(|event| event["event"] == "run.failed" || event["event"] == "run.cancelled"),
        "{restored_events:?}"
    );
    let absent_block = typed_tool_block(
        &cycle.state.service().session_messages(&new_session),
        "read-absent",
    )
    .expect("typed absent read");
    assert_eq!(absent_block["type"], "tool_result");
    assert_eq!(absent_block["tool_call_id"], "read-absent");
    assert_eq!(absent_block["is_error"], true);
    assert_eq!(absent_block["content"], "");
    assert_ne!(absent_block["content"], "A-write\n");
    let write_block = typed_tool_block(
        &cycle.state.service().session_messages(&new_session),
        "write-restored",
    )
    .expect("typed restored write");
    assert_eq!(write_block["type"], "tool_result");
    assert_eq!(write_block["tool_call_id"], "write-restored");
    assert_eq!(write_block["is_error"], false);
    assert_eq!(write_block["content"], "A-write\n");
    let (status, restored_effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{new_run}/effects?limit=128"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &restored_effects));
    let absent_entry = restored_effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == "read-absent")
        .expect("absent read effect");
    assert_eq!(absent_entry["state"], "not_published");
    let write_entry = restored_effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == "write-restored")
        .expect("restored write effect");
    assert_eq!(write_entry["state"], "committed");
    assert_eq!(
        write_entry["branch_id"],
        restored["new_branch"]["branch_id"]
    );
    let persistence = cycle.state.persistence().unwrap();
    let absent_record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: new_session.clone(),
                run_id: new_run.clone(),
            },
            call_id: "read-absent".into(),
        })
        .unwrap()
        .expect("durable absent read");
    assert_eq!(absent_record.identity.tool_name, "read_file");
    assert_eq!(
        absent_record.state,
        rustscript_agent::effects::ManagedPublicationStatus::NotPublished
    );
    let absent_outcome = absent_record
        .outcome
        .as_ref()
        .expect("failed read still has an outcome");
    assert!(absent_outcome.publication.candidate_head.is_none());
    assert_eq!(
        absent_outcome.publication.status,
        rustscript_agent::effects::ManagedPublicationStatus::NotPublished
    );
    let absent_body = cycle
        .state
        .service()
        .read_managed_result_chunk(rustscript_agent::effects::ManagedResultReadRequest {
            effect_id: absent_record.effect_id.clone(),
            offset: 0,
            limit: 4096,
        })
        .expect("absent effect body");
    let absent_json: Value = serde_json::from_slice(&absent_body.bytes).expect("absent body json");
    assert_eq!(absent_json["ok"], false);
    assert_eq!(absent_json["error"]["code"], "not_found");
    assert_eq!(absent_json["content"], "");
    assert!(
        !cycle
            .root
            .join(".gateway.sqlite.effects/trees")
            .join(&frozen_head)
            .join("out-a-again.txt")
            .exists()
    );
    let write_record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: new_session.clone(),
                run_id: new_run.clone(),
            },
            call_id: "write-restored".into(),
        })
        .unwrap()
        .expect("durable restored write");
    assert_eq!(write_record.identity.tool_name, "write_file");
    assert_eq!(write_record.identity.approved_risk, "write");
    assert_eq!(
        write_record.state,
        rustscript_agent::effects::ManagedPublicationStatus::Committed
    );
    let write_outcome = write_record
        .outcome
        .as_ref()
        .expect("committed write outcome");
    let candidate = write_outcome
        .publication
        .candidate_head
        .clone()
        .expect("write publishes a candidate head");
    assert_ne!(candidate, frozen_head);
    assert_eq!(
        write_outcome.publication.status,
        rustscript_agent::effects::ManagedPublicationStatus::Committed
    );
    let restored_file = cycle
        .root
        .join(".gateway.sqlite.effects/trees")
        .join(&candidate)
        .join("out-restored.txt");
    let restored_bytes = std::fs::read(&restored_file).expect("restored write bytes");
    assert_eq!(restored_bytes, b"A-write\n");
    assert_eq!(
        write_block["content"].as_str().unwrap().as_bytes(),
        restored_bytes.as_slice()
    );
    assert!(
        !cycle
            .root
            .join(".gateway.sqlite.effects/trees")
            .join(&candidate)
            .join("out-a-again.txt")
            .exists(),
        "absent read must not create a file on the written view"
    );
    assert!(!contains_marker(&cycle.state, &new_run, "B-write"));

    let (status, rolled) = http
        .request(
            "POST",
            &format!("/v1/plugin-activations/owner-space.{generation_a}/rollback"),
            json!({"admin": true, "graph_id": graph_b}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &rolled));
    let generation_roll = rolled["generation"].as_u64().unwrap();
    assert!(generation_roll > generation_b);
    assert_eq!(rolled["graph_id"], graph_a);
    let provider_roll = Arc::new(ScriptedProvider::new());
    provider_roll.push_ok(tool_call("write-roll", "write_file", "out-roll.txt"));
    provider_roll.push_ok(stop_turn("done-roll"));
    cycle.state.service().inject_provider_host(provider_roll);
    let (status, rolled_run) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write the rolled graph"}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &rolled_run));
    assert_eq!(rolled_run["graph_id"], graph_a);
    assert_eq!(rolled_run["activation_generation"], generation_roll);
    assert!(rolled_run["publication"].is_null());
    let rolled_id = rolled_run["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&cycle.state, &rolled_id)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;
    assert!(contains_marker(&cycle.state, &rolled_id, "A-write"));
    assert!(!contains_marker(&cycle.state, &rolled_id, "B-write"));
    let (status, final_messages) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200);
    let prefix =
        &final_messages["data"].as_array().unwrap()[..frozen_messages.as_array().unwrap().len()];
    assert_eq!(Value::Array(prefix.to_vec()), frozen_messages);
    let (status, final_effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_a}/effects?limit=128"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &final_effects));
    assert_eq!(
        final_effects["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["call_id"] == "write-a1")
            .unwrap()["effect_id"],
        write["effect_id"]
    );
    let revoked = revoke_graph(
        &cycle.config,
        &cycle.db,
        &bound_store(&cycle.db, &cycle.auth),
        &graph_a,
    );
    assert_eq!(revoked.unwrap_err().code, "plugin_lock_invalid");
    assert!(cycle.state.service().handle_count() >= handles_before_release);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

fn typed_tool_block(messages: &[Value], call_id: &str) -> Option<Value> {
    messages.iter().find_map(|message| {
        if message.get("tool_call_id").and_then(Value::as_str) != Some(call_id) {
            return None;
        }
        message
            .get("content")
            .and_then(Value::as_array)
            .and_then(|blocks| {
                blocks.iter().find(|block| {
                    block.get("type").and_then(Value::as_str) == Some("tool_result")
                        && block.get("tool_call_id").and_then(Value::as_str) == Some(call_id)
                })
            })
            .cloned()
    })
}

fn current_head(cycle: &Cycle, session_id: &str, run_id: &str, call_id: &str) -> Value {
    let persistence = cycle.state.persistence().unwrap();
    let record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.into(),
                run_id: run_id.into(),
            },
            call_id: call_id.into(),
        })
        .unwrap()
        .unwrap();
    let head = persistence
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    json!({
        "store_id": head.store_id,
        "workspace_id": head.workspace_id,
        "branch_id": head.branch_id,
        "epoch": head.epoch,
        "head_object_id": head.head_object_id,
        "head_version": head.head_version
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_workspace_and_duplicate_run_do_not_commit() {
    let cycle = Cycle::open(&format!("t16-neg-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (graph_a, _) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let outside = cycle.root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(tool_call("write-a1", "write_file", "out-a.txt"));
    provider.push_ok(stop_turn("done"));
    cycle.state.service().inject_provider_host(provider);
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap();
    let (status, rejected) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "escape", "workspace": outside.display().to_string()}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 422, "{}", explain(status, &rejected));
    assert_eq!(rejected["error"]["code"], "invalid_admission");
    assert!(!outside.join("out-a.txt").exists());
    let key = uuid::Uuid::new_v4().to_string();
    let body = json!({"session_id": session_id, "input": "write once", "extra": {"graph_id": "not-a-grant"}});
    let (status, first) = http
        .request(
            "POST",
            "/v1/runs",
            body.clone(),
            Some(&cycle.token),
            Some(&key),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &first));
    assert_eq!(first["graph_id"], graph_a);
    let run_id = first["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&cycle.state, &run_id)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;
    let (status, effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_id}/effects?limit=128"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    let (status, duplicate) = http
        .request("POST", "/v1/runs", body, Some(&cycle.token), Some(&key))
        .await;
    assert_eq!(status, 202, "{}", explain(status, &duplicate));
    assert_eq!(duplicate["run_id"], run_id);
    let (status, again) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_id}/effects?limit=128"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &again));
    assert_eq!(again["entries"], effects["entries"]);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_and_deadline_reject_late_approval_without_execution() {
    let cycle = Cycle::open(&format!("t16-cancel-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_hang();
    cycle.state.service().inject_provider_host(provider.clone());
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, run) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "hang"}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &run));
    let run_id = run["run_id"].as_str().unwrap().to_string();
    wait_until(|| provider.call_count() >= 1).await;
    let (status, stopped) = http
        .request(
            "POST",
            &format!("/v1/runs/{run_id}/stop"),
            json!({}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &stopped));
    wait_until(|| {
        event_names(&cycle.state, &run_id)
            .iter()
            .any(|name| name == "run.cancelled")
    })
    .await;
    assert!(
        !event_names(&cycle.state, &run_id)
            .iter()
            .any(|name| name == "run.completed")
    );
    let (status, late) = http
        .request(
            "POST",
            &format!("/v1/runs/{run_id}/approvals/late-approval"),
            json!({"decision": "approved"}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &late));
    assert_eq!(late["error"]["code"], "run_not_active");
    assert!(!cycle.workspace.join("out-a.txt").exists());
    http.close().await;
    shutdown_when_idle(&cycle.state).await;

    let deadline = Cycle::open_timeout(
        &format!("t16-deadline-{}", uuid::Uuid::new_v4().simple()),
        Duration::from_secs(15),
    );
    let http = Http::bind(deadline.state.clone()).await;
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_hang();
    deadline.state.service().inject_provider_host(provider);
    let (status, session) = http
        .request(
            "POST",
            "/api/sessions",
            json!({}),
            Some(&deadline.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap();
    let (status, run) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "expire"}),
            Some(&deadline.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &run));
    let run_id = run["run_id"].as_str().unwrap();
    wait_for(
        || {
            event_names(&deadline.state, run_id)
                .iter()
                .any(|name| name == "run.cancelled")
        },
        Duration::from_secs(40),
    )
    .await;
    assert!(
        !event_names(&deadline.state, run_id)
            .iter()
            .any(|name| name == "run.completed")
    );
    let (status, late) = http
        .request(
            "POST",
            &format!("/v1/runs/{run_id}/approvals/late-approval"),
            json!({"decision": "approved"}),
            Some(&deadline.token),
            None,
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &late));
    assert_eq!(late["error"]["code"], "run_not_active");
    assert!(!deadline.workspace.join("out-a.txt").exists());
    http.close().await;
    shutdown_when_idle(&deadline.state).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn embedding_revoke_conflicts_on_the_next_http_admission() {
    let cycle = Cycle::open(&format!("t16-revoke-{}", uuid::Uuid::new_v4().simple()));
    cycle
        .state
        .service()
        .materialize_cached_runner()
        .expect("embedding runner materializes");
    let http = Http::bind(cycle.state.clone()).await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap();
    let embedding = embedding_graph_id(&cycle.config, &cycle.db);
    let generation = current_generation(&cycle.config, &cycle.db);
    revoke_graph(
        &cycle.config,
        &cycle.db,
        &bound_store(&cycle.db, &cycle.auth),
        &embedding,
    )
    .unwrap();
    let (status, prepared) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{embedding}/prepare"),
            json!({}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &prepared));
    assert_eq!(prepared["error"]["code"], "plugin_graph_revoked");
    let (status, activated) = http
        .request(
            "POST",
            "/v1/plugin-activations",
            json!({
                "graph_id": embedding,
                "deployment_space": "owner-space",
                "expected_generation": generation
            }),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &activated));
    assert_eq!(activated["error"]["code"], "plugin_graph_revoked");
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(tool_call("write-revoked", "write_file", "revoked.txt"));
    provider.push_ok(stop_turn("should-not-run"));
    cycle.state.service().inject_provider_host(provider);
    let (status, denied) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "after revoke"}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &denied));
    assert_eq!(denied["error"]["code"], "plugin_graph_revoked");
    assert!(!cycle.workspace.join("revoked.txt").exists());
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_branch_pins_origin_graph_not_the_later_active_graph() {
    let cycle = Cycle::open(&format!("t16-branch-pin-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (graph_a, generation_a) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(tool_call("write-origin", "write_file", "out-a.txt"));
    provider.push_ok(stop_turn("done-a"));
    cycle.state.service().inject_provider_host(provider.clone());
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write origin"}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph_a);
    let run_a = admitted["run_id"].as_str().unwrap().to_string();
    let source_branch = admitted["workspace_branch"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&cycle.state, &run_a)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;
    let origin_projection = projected_run(&http, &cycle.token, &session_id, &run_a).await;
    assert!(
        origin_projection.contains("A-write"),
        "durable message must retain the native marker: {origin_projection}"
    );
    let (status, effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_a}/effects?limit=128"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    let write = effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == "write-origin")
        .expect("origin write")
        .clone();
    let workspace_id = write["workspace_id"].as_str().unwrap().to_string();
    let epoch = write["epoch"].as_u64().unwrap();
    let (status, checkpoint) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_a,
                "workspace_id": workspace_id,
                "source_branch_id": source_branch,
                "expected_epoch": epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &checkpoint));
    assert_eq!(checkpoint["checkpoint"]["graph"]["graph_id"], graph_a);
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (graph_b, generation_b) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effectb",
    )
    .await;
    assert_ne!(graph_b, graph_a);
    assert!(generation_b > generation_a);
    let (status, created) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/branches"),
            json!({
                "workspace_id": workspace_id,
                "source_branch_id": source_branch,
                "checkpoint_id": checkpoint_id,
                "request_id": uuid::Uuid::new_v4().to_string()
            }),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &created));
    let selected = created["branch"]["branch_id"].as_str().unwrap().to_string();
    let handles = cycle.state.service().handle_count();
    for graph_id in ["caller-forged-graph", "  ", ""] {
        let (status, denied) = http
            .request(
                "POST",
                "/v1/runs",
                json!({
                    "session_id": session_id,
                    "input": "foreign graph",
                    "workspace_branch": selected,
                    "graph_id": graph_id
                }),
                Some(&cycle.token),
                None,
            )
            .await;
        assert_eq!(status, 422, "{graph_id}: {}", explain(status, &denied));
        assert_eq!(denied["error"]["code"], "plugin_graph_pin_required");
        assert!(denied.get("run_id").is_none());
    }
    let foreign_branch = format!("br-{}", "ab".repeat(16));
    let (status, missing) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "foreign branch",
                "workspace_branch": foreign_branch,
                "graph_id": graph_a
            }),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 404, "{}", explain(status, &missing));
    assert_eq!(missing["error"]["code"], "managed_branch_missing");
    assert_eq!(cycle.state.service().handle_count(), handles);
    provider.push_ok(tool_call("write-branch", "write_file", "branch-only.txt"));
    provider.push_ok(stop_turn("done-branch"));
    cycle.state.service().inject_provider_host(provider.clone());
    let idem = uuid::Uuid::new_v4().to_string();
    let branch_body = json!({
        "session_id": session_id,
        "input": "write on checkpoint branch",
        "workspace_branch": selected
    });
    let (status, branch_run) = http
        .request(
            "POST",
            "/v1/runs",
            branch_body.clone(),
            Some(&cycle.token),
            Some(&idem),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &branch_run));
    assert_eq!(branch_run["graph_id"], graph_a);
    assert_eq!(branch_run["activation_generation"], generation_a);
    assert_eq!(branch_run["workspace_branch"], selected);
    assert_eq!(
        branch_run["head_object_id"],
        created["branch"]["head_object_id"]
    );
    assert_eq!(
        branch_run["head_version"],
        created["branch"]["head_version"]
    );
    assert!(branch_run["publication"].is_null());
    let branch_run_id = branch_run["run_id"].as_str().unwrap().to_string();
    let pinned = pin_for_run(&cycle.config, &cycle.db, &branch_run_id);
    assert_eq!(pinned["graph_id"], graph_a);
    assert_eq!(pinned["generation"], generation_a);
    let (status, replay) = http
        .request(
            "POST",
            "/v1/runs",
            branch_body,
            Some(&cycle.token),
            Some(&idem),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &replay));
    assert_eq!(replay["run_id"], branch_run_id);
    assert_eq!(replay["graph_id"], graph_a);
    wait_until(|| {
        event_names(&cycle.state, &branch_run_id)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;
    let branch_projection = projected_run(&http, &cycle.token, &session_id, &branch_run_id).await;
    assert!(branch_projection.contains("A-write"), "{branch_projection}");
    assert!(
        !branch_projection.contains("B-write"),
        "{branch_projection}"
    );
    let (status, branch_effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{branch_run_id}/effects?limit=128"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &branch_effects));
    let branch_writes = branch_effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["call_id"] == "write-branch")
        .count();
    assert_eq!(
        branch_writes, 1,
        "replay must not duplicate the branch effect"
    );
    assert_eq!(
        std::fs::read(cycle.workspace.join("seed.txt")).unwrap(),
        b"seed"
    );
    assert!(!cycle.workspace.join("branch-only.txt").exists());
    provider.push_ok(tool_call("write-current", "write_file", "out-b.txt"));
    provider.push_ok(stop_turn("done-b"));
    cycle.state.service().inject_provider_host(provider.clone());
    let (status, current) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write current"}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &current));
    assert_eq!(current["graph_id"], graph_b);
    assert_eq!(current["activation_generation"], generation_b);
    assert_eq!(current["workspace_branch"], source_branch);
    let current_id = current["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&cycle.state, &current_id)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;
    let current_projection = projected_run(&http, &cycle.token, &session_id, &current_id).await;
    assert!(
        current_projection.contains("B-write"),
        "{current_projection}"
    );
    assert!(
        !current_projection.contains("A-write"),
        "{current_projection}"
    );
    let branch_after = projected_run(&http, &cycle.token, &session_id, &branch_run_id).await;
    assert!(branch_after.contains("A-write"), "{branch_after}");
    assert!(!branch_after.contains("B-write"), "{branch_after}");
    provider.push_hang();
    cycle.state.service().inject_provider_host(provider.clone());
    let calls = provider.call_count();
    let (status, hung) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "cancel on origin graph",
                "workspace_branch": selected
            }),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &hung));
    assert_eq!(hung["graph_id"], graph_a);
    let hung_id = hung["run_id"].as_str().unwrap().to_string();
    wait_until(|| provider.call_count() > calls).await;
    let (status, stopped) = http
        .request(
            "POST",
            &format!("/v1/runs/{hung_id}/stop"),
            json!({}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &stopped));
    wait_until(|| {
        event_names(&cycle.state, &hung_id)
            .iter()
            .any(|name| name == "run.cancelled")
    })
    .await;
    assert!(
        !event_names(&cycle.state, &hung_id)
            .iter()
            .any(|name| name == "run.completed")
    );
    let hung_projection = projected_run(&http, &cycle.token, &session_id, &hung_id).await;
    assert!(!hung_projection.contains("B-write"), "{hung_projection}");
    let pinned_after = pin_for_run(&cycle.config, &cycle.db, &branch_run_id);
    assert_eq!(pinned_after["graph_id"], graph_a);
    assert_eq!(pinned_after["generation"], generation_a);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn fault_cut_does_not_publish_and_active_writer_blocks_checkpoint() {
    use rustscript_agent::effects::ManagedEffectFault;
    let cycle = Cycle::open(&format!("t16-fault-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    cycle
        .state
        .service()
        .inject_managed_effect_fault(ManagedEffectFault::AfterIntent)
        .unwrap();
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(tool_call("write-cut", "write_file", "cut.txt"));
    provider.push_ok(stop_turn("cut-done"));
    cycle.state.service().inject_provider_host(provider);
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, run) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "cut"}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &run));
    let run_id = run["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&cycle.state, &run_id)
            .iter()
            .any(|name| name == "run.failed")
    })
    .await;
    let fault_events = cycle.state.service().run_events(&run_id);
    let fault_names = event_names(&cycle.state, &run_id);
    assert_eq!(
        fault_names
            .iter()
            .filter(|name| {
                *name == "run.completed" || *name == "run.failed" || *name == "run.cancelled"
            })
            .collect::<Vec<_>>(),
        vec!["run.failed"],
        "{fault_events:?}"
    );
    let failed = fault_events
        .iter()
        .find(|event| event["event"] == "run.failed")
        .expect("run.failed");
    assert_eq!(failed["data"]["error_code"], "agent_failed");
    assert_eq!(
        failed["data"]["error_message"],
        "tool validation failure could not be recorded"
    );
    assert_eq!(failed["data"]["status"], "failed");
    assert!(
        fault_events.iter().any(|event| {
            event["event"] == "tool.started" && event["data"]["tool_call_id"] == "write-cut"
        }),
        "AfterIntent still leaves the started intent: {fault_events:?}"
    );
    assert!(
        !fault_events
            .iter()
            .any(|event| { event["event"] == "tool.completed" || event["event"] == "tool.failed" }),
        "the cut is not a recorded tool terminal: {fault_events:?}"
    );
    assert!(
        !cycle
            .state
            .service()
            .session_messages(&session_id)
            .iter()
            .any(|message| message["tool_call_id"] == "write-cut"),
        "unrecorded validation failure must not publish a tool result"
    );
    let (status, effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_id}/effects?limit=128"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    let entry = effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == "write-cut")
        .expect("fault leaves a durable intent");
    assert_ne!(entry["state"], "committed");
    assert_eq!(entry["state"], "indeterminate");
    let fault_record = cycle
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.clone(),
                run_id: run_id.clone(),
            },
            call_id: "write-cut".into(),
        })
        .unwrap()
        .expect("durable intent record");
    assert!(
        fault_record.prepared.is_none(),
        "AfterIntent precedes native view construction"
    );
    assert!(
        fault_record.outcome.is_none(),
        "cut must not publish an outcome"
    );
    assert_eq!(
        fault_record.state,
        rustscript_agent::effects::ManagedPublicationStatus::Indeterminate
    );
    assert!(!contains_marker(&cycle.state, &run_id, "A-write"));
    let before = cycle.state.service().available_capacity();
    let handles = cycle.state.service().handle_count();
    assert!(before > 0);
    assert!(handles > 0);

    let gate = cycle.state.service().arm_managed_prepare_gate().unwrap();
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(tool_call("write-busy", "write_file", "busy.txt"));
    provider.push_ok(stop_turn("busy-done"));
    cycle.state.service().inject_provider_host(provider);
    let (status, busy_run) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "hold writer"}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &busy_run));
    gate.wait_arrived(1).unwrap();
    let head = current_head(&cycle, &session_id, &run_id, "write-cut");
    let workspace_id = head["workspace_id"].as_str().unwrap();
    let handles_before_branch = cycle.state.service().handle_count();
    let (status, head_only) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/branches"),
            json!({
                "workspace_id": workspace_id,
                "source_branch_id": head["branch_id"],
                "expected_source": head,
                "request_id": uuid::Uuid::new_v4().to_string()
            }),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &head_only));
    assert_eq!(head_only["error"]["code"], "managed_checkpoint_busy");
    assert_eq!(cycle.state.service().handle_count(), handles_before_branch);
    let (status, busy) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": busy_run["run_id"],
                "workspace_id": workspace_id,
                "source_branch_id": head["branch_id"],
                "expected_epoch": head["epoch"],
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &busy));
    assert_eq!(busy["error"]["code"], "managed_checkpoint_busy");
    gate.release();
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}
