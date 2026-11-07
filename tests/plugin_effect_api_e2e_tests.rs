//! T16: real-socket graph hot cut, pinned continuation, checkpoint/restore, and rollback.
//! Admission starts at POST /api/sessions and POST /v1/runs. Request JSON does not grant.
use plugin_effect_api_cycle::{
    Cycle, Http, SecondBusinessGate, TypedEvent, activate, assert_closed,
    assert_signed_write_pair_prepares_captured_catalog, assert_typed_terminal, bound_store,
    contains_marker, current_generation, embedding_graph_id, event_names, explain, install_package,
    install_pair, pin_for_run, revoke_graph, shutdown_when_idle, stop_turn, tool_call, wait_for,
    wait_until,
};
use rustscript_agent::{CancellationReason, ScriptedProvider};
use serde_json::{Value, json};
use signed_tool_effects::{LIBRARY_LEAF_DIR, LIBRARY_TOOL_DIR, LIBRARY_TOOL_ID};
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
    assert_eq!(admitted["publication"], json!("not_published"));
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
    assert_eq!(reread["publication"], json!("not_published"));
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
    assert_eq!(run_b["publication"], json!("not_published"));
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
    assert_eq!(rolled_run["publication"], json!("not_published"));
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
    revoke_graph(
        &cycle.config,
        &cycle.db,
        &bound_store(&cycle.db, &cycle.auth),
        &graph_a,
    )
    .expect("supported solo signed tool graph revokes");
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

async fn pending_real_approval(http: &Http, token: &str, run_id: &str, bound: Duration) -> Value {
    let deadline = std::time::Instant::now() + bound;
    loop {
        let (status, body) = http
            .request(
                "GET",
                &format!("/v1/runs/{run_id}/approvals"),
                json!(null),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{}", explain(status, &body));
        if let Some(approval) = body["approvals"].as_array().and_then(|rows| rows.first()) {
            return approval.clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "real pending approval did not appear inside {bound:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn decide_approval_http(
    http: &Http,
    token: &str,
    run_id: &str,
    approval_id: &str,
    decision: &str,
) -> (u16, Value) {
    http.request(
        "POST",
        &format!("/v1/runs/{run_id}/approvals/{approval_id}"),
        json!({"decision": decision}),
        Some(token),
        None,
    )
    .await
}

fn typed_event_facts(cycle: &Cycle, run_id: &str) -> Vec<(String, u64, String)> {
    cycle
        .state
        .service()
        .run_events(run_id)
        .iter()
        .map(|event| {
            (
                event["event_id"]
                    .as_str()
                    .expect("typed event id")
                    .to_string(),
                event["seq"].as_u64().expect("typed event seq"),
                event["event"]
                    .as_str()
                    .expect("typed event name")
                    .to_string(),
            )
        })
        .collect()
}

fn cancelled_reason(cycle: &Cycle, run_id: &str) -> Option<String> {
    cycle
        .state
        .service()
        .run_events(run_id)
        .iter()
        .find(|event| event["event"] == "run.cancelled")
        .and_then(|event| event.pointer("/data/reason"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn assert_sse_matches_typed(
    cycle: &Cycle,
    events: &[TypedEvent],
    run_id: &str,
    terminal: &str,
    reason: &str,
) {
    assert_typed_terminal(events, terminal);
    let typed = cycle.state.service().run_events(run_id);
    assert_eq!(
        events.len(),
        typed.len(),
        "SSE replay must mirror the typed run log"
    );
    for (event, record) in events.iter().zip(typed.iter()) {
        assert_eq!(
            event.event_id,
            record["event_id"].as_str().expect("typed event id"),
            "SSE event identity must match typed persistence"
        );
        assert_eq!(event.seq, record["seq"].as_u64().expect("typed seq"));
        assert_eq!(event.name, record["event"].as_str().expect("typed name"));
    }
    let mut ids: Vec<&str> = events.iter().map(|event| event.event_id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), events.len(), "event ids must be unique");
    let last = events.last().expect("terminal SSE event");
    assert_eq!(
        last.reason.as_deref(),
        Some(reason),
        "typed terminal reason must survive SSE"
    );
}

fn assert_durable_events_match(cycle: &Cycle, events: &[TypedEvent], run_id: &str) {
    let persistence = cycle.state.persistence().expect("typed persistence");
    let durable = persistence
        .event_replay(&json!({
            "run_id": run_id,
            "after_seq": 0,
            "max_events": 512,
            "max_bytes": 1_048_576
        }))
        .expect("durable event readback");
    let columns = durable["columns"]
        .as_array()
        .expect("durable event columns");
    let cell = |row: &Value, name: &str| -> Value {
        row[columns
            .iter()
            .position(|column| column.as_str() == Some(name))
            .unwrap_or_else(|| panic!("durable event column {name} missing"))]
        .clone()
    };
    let rows = durable["rows"].as_array().expect("durable event rows");
    assert_eq!(
        rows.len(),
        events.len(),
        "durable event rows must match the SSE replay"
    );
    for (event, row) in events.iter().zip(rows.iter()) {
        assert_eq!(
            cell(row, "event_id").as_str(),
            Some(event.event_id.as_str()),
            "durable event id must match SSE"
        );
        assert_eq!(
            cell(row, "seq").as_u64(),
            Some(event.seq),
            "durable event seq must match SSE"
        );
        assert_eq!(
            cell(row, "event_type").as_str(),
            Some(event.name.as_str()),
            "durable event name must match SSE"
        );
        if event.terminal {
            let payload: Value = serde_json::from_str(
                cell(row, "payload_json")
                    .as_str()
                    .expect("durable event payload"),
            )
            .expect("durable event payload json");
            assert_eq!(
                payload["reason"].as_str(),
                event.reason.as_deref(),
                "durable terminal reason must match SSE"
            );
        }
    }
}

async fn typed_messages(http: &Http, cycle: &Cycle, token: &str, session_id: &str) -> Vec<Value> {
    let (status, body) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &body));
    let data = body["data"].as_array().expect("message data array").clone();
    let typed = cycle.state.service().session_messages(session_id);
    assert_eq!(
        Value::Array(data.clone()),
        Value::Array(typed.clone()),
        "GET messages must equal the typed session projection"
    );
    let persistence = cycle.state.persistence().expect("typed persistence");
    let durable = persistence
        .message_list(session_id, 0)
        .expect("durable message readback");
    let columns = durable["columns"]
        .as_array()
        .expect("durable message columns");
    let cell = |row: &Value, name: &str| -> Value {
        row[columns
            .iter()
            .position(|column| column.as_str() == Some(name))
            .unwrap_or_else(|| panic!("durable message column {name} missing"))]
        .clone()
    };
    let rows = durable["rows"].as_array().expect("durable message rows");
    assert_eq!(
        rows.len(),
        typed.len(),
        "durable message count must match the typed projection"
    );
    for (message, row) in typed.iter().zip(rows.iter()) {
        assert_eq!(cell(row, "id"), message["id"], "durable message id");
        assert_eq!(cell(row, "role"), message["role"], "durable message role");
        assert_eq!(
            cell(row, "run_id"),
            message["run_id"],
            "durable message owner"
        );
        let stored: Value = serde_json::from_str(
            cell(row, "content_json")
                .as_str()
                .expect("durable message content"),
        )
        .expect("durable message content json");
        assert_eq!(stored, message["content"], "durable committed body");
    }
    for message in &typed {
        assert!(
            message["id"].as_str().is_some_and(|id| !id.is_empty()),
            "committed message id is required"
        );
        assert!(
            matches!(
                message["role"].as_str(),
                Some("user" | "assistant" | "tool")
            ),
            "committed message role is typed"
        );
    }
    data
}

fn assert_no_tool_execution(cycle: &Cycle, run_id: &str, call_id: &str, messages: &[Value]) {
    assert!(
        event_names(&cycle.state, run_id)
            .iter()
            .all(|name| !name.starts_with("tool.")),
        "no Native tool lifecycle event may exist: {:?}",
        event_names(&cycle.state, run_id)
    );
    assert!(
        typed_tool_block(messages, call_id).is_none(),
        "no tool result may be published for the unexecuted call"
    );
    assert!(
        messages.iter().all(|message| {
            message["role"] != "tool" || message["tool_call_id"].as_str() != Some(call_id)
        }),
        "no tool-role message may carry the unexecuted call"
    );
}

async fn run_effect_entries(http: &Http, token: &str, run_id: &str) -> Vec<Value> {
    let (status, body) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_id}/effects?limit=128"),
            json!(null),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &body));
    body["entries"].as_array().cloned().unwrap_or_default()
}

/// Healthy control: the same managed tool with a real user approval resolved
/// inside the original clock must commit a receipt, publish real tool output,
/// and advance the managed branch head.
async fn healthy_user_approved_write(
    cycle: &Cycle,
    http: &Http,
    graph: &str,
    session_id: &str,
    call_id: &str,
    file: &str,
    input: &str,
) -> (String, Value) {
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(tool_call(call_id, "write_file", file));
    provider.push_ok(stop_turn("control-done"));
    cycle.state.service().inject_provider_host(provider.clone());
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": input}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph);
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let branch = admitted["workspace_branch"]
        .as_str()
        .expect("managed branch")
        .to_string();
    let approval =
        pending_real_approval(http, &cycle.token, &run_id, Duration::from_secs(10)).await;
    assert_eq!(approval["state"], "pending");
    assert_eq!(approval["run_id"], run_id);
    assert_eq!(approval["session_id"], session_id);
    assert_eq!(approval["tool_name"], "write_file");
    assert_eq!(approval["risk_class"], "write");
    let approval_id = approval["approval_id"]
        .as_str()
        .expect("approval id")
        .to_string();
    assert!(!approval_id.is_empty());
    let (status, resolved) =
        decide_approval_http(http, &cycle.token, &run_id, &approval_id, "approved").await;
    assert_eq!(status, 200, "{}", explain(status, &resolved));
    assert_eq!(resolved["state"], "approved");
    wait_until(|| {
        event_names(&cycle.state, &run_id)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;
    assert_eq!(
        provider.call_count(),
        2,
        "healthy control uses exactly one follow-up turn"
    );

    let entries = run_effect_entries(http, &cycle.token, &run_id).await;
    let record = entries
        .iter()
        .find(|entry| entry["call_id"] == call_id)
        .expect("committed managed receipt");
    assert_eq!(record["state"], "committed");
    assert_eq!(record["branch_id"], branch);

    let messages = typed_messages(http, cycle, &cycle.token, session_id).await;
    let block = typed_tool_block(&messages, call_id).expect("real tool output");
    assert_eq!(block["type"], "tool_result");
    assert_eq!(block["tool_call_id"], call_id);
    assert_eq!(block["is_error"], false);
    assert_eq!(block["content"], "A-write\n", "healthy tool output");
    assert!(messages.iter().any(|message| {
        message["run_id"].as_str() == Some(run_id.as_str())
            && message["role"] == "user"
            && message.to_string().contains(input)
    }));

    let head = current_head(cycle, session_id, &run_id, call_id);
    assert_eq!(head["branch_id"], branch);
    let admission_version = admitted["head_version"].as_u64().unwrap_or(0);
    assert!(
        head["head_version"].as_u64().unwrap_or(0) > admission_version,
        "healthy write advances the managed branch head"
    );
    println!(
        "HEALTHY_SUMMARY {}",
        json!({
            "provider_calls": provider.call_count(),
            "receipt_state": record["state"],
            "tool_output_bytes": block["content"].as_str().map(str::len).unwrap_or(0),
            "messages": messages.len(),
            "head_version": head["head_version"],
        })
    );
    (run_id, head)
}

/// Negative lifecycle: a real pending user approval is closed by the original
/// owner stop or the original admission deadline; only then is the real
/// approval id approved over HTTP. The decision must be rejected and no Native
/// effect, tool output, receipt, token, branch movement or projection drift may
/// follow. Each argument is one distinct frozen identity of that single
/// cancelled admission, so a bag struct would only rename the same facts.
#[allow(clippy::too_many_arguments)]
async fn assert_cancelled_late_approval_no_effect(
    cycle: &Cycle,
    http: &Http,
    phase: &str,
    graph: &str,
    session_id: &str,
    control_head: &Value,
    control_run: &str,
    control_call: &str,
    input: &str,
    call_id: &str,
    file: &str,
    natural_deadline: bool,
) {
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(tool_call(call_id, "write_file", file));
    provider.push_ok(stop_turn("must-not-run"));
    cycle.state.service().inject_provider_host(provider.clone());
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": input}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph);
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let control_branch = control_head["branch_id"].as_str().unwrap();
    assert_eq!(
        admitted["workspace_branch"].as_str(),
        Some(control_branch),
        "negative run must stay on the control branch"
    );
    assert_eq!(
        admitted["head_object_id"], control_head["head_object_id"],
        "negative admission must start from the control head"
    );
    assert_eq!(
        admitted["head_version"], control_head["head_version"],
        "negative admission must start from the control head version"
    );

    let approval =
        pending_real_approval(http, &cycle.token, &run_id, Duration::from_secs(10)).await;
    assert_eq!(approval["state"], "pending");
    assert_eq!(approval["run_id"], run_id);
    assert_eq!(approval["session_id"], session_id);
    assert_eq!(approval["tool_name"], "write_file");
    assert_eq!(approval["risk_class"], "write");
    let approval_id = approval["approval_id"]
        .as_str()
        .expect("approval id")
        .to_string();
    assert!(!approval_id.is_empty());

    let handle = cycle.state.service().handle(&run_id).expect("live handle");
    let root = handle.cancellation();
    let original_deadline = root.deadline_instant();
    if natural_deadline {
        let original = original_deadline.expect("admission deadline on the original root");
        let remain = original.saturating_duration_since(std::time::Instant::now());
        assert!(!remain.is_zero(), "pending must be observed before expiry");
        assert!(
            remain <= cycle.config.run_timeout,
            "pending must be observed inside the unchanged clock"
        );
    }

    let messages_at_pending = typed_messages(http, cycle, &cycle.token, session_id).await;
    if natural_deadline {
        wait_for(
            || {
                event_names(&cycle.state, &run_id)
                    .iter()
                    .any(|name| name == "run.cancelled")
            },
            Duration::from_secs(40),
        )
        .await;
    } else {
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
    }
    assert!(
        !event_names(&cycle.state, &run_id)
            .iter()
            .any(|name| name == "run.completed"),
        "the run must stay cancelled"
    );
    let expected_reason = if natural_deadline {
        "deadline"
    } else {
        "requested"
    };
    assert_eq!(
        cancelled_reason(cycle, &run_id).as_deref(),
        Some(expected_reason),
        "the original terminal reason must be preserved"
    );
    if natural_deadline {
        let original = original_deadline.expect("admission deadline on the original root");
        assert!(
            root.deadline_passed(),
            "the original deadline elapsed naturally"
        );
        assert_eq!(
            root.requested(),
            Some(CancellationReason::Deadline),
            "the request must be the original deadline reason, not a manual stop"
        );
        assert_eq!(root.deadline_instant(), Some(original));
    } else {
        assert_eq!(
            root.requested(),
            Some(CancellationReason::Requested),
            "the owner stop must be the original cancellation reason"
        );
    }

    let events_at_terminal = typed_event_facts(cycle, &run_id);
    let messages_at_terminal = typed_messages(http, cycle, &cycle.token, session_id).await;
    assert!(
        messages_at_terminal.iter().any(|message| {
            message["role"] == "assistant" && message["content"].to_string().contains(call_id)
        }),
        "the real provider tool request must remain recorded"
    );
    let head_before = current_head(cycle, session_id, control_run, control_call);
    assert_eq!(
        head_before["head_object_id"],
        control_head["head_object_id"]
    );
    assert_eq!(head_before["head_version"], control_head["head_version"]);

    let (status, late) =
        decide_approval_http(http, &cycle.token, &run_id, &approval_id, "approved").await;
    assert_eq!(status, 409, "{}", explain(status, &late));
    assert_eq!(late["error"]["code"], "run_not_active");

    let stored = cycle
        .state
        .persistence()
        .expect("typed persistence")
        .approval_get(&approval_id)
        .expect("durable approval row");
    assert_eq!(stored["rows"][0][0], approval_id);
    assert_ne!(
        stored["rows"][0][7], "approved",
        "late approval must not be durably committed"
    );

    assert_eq!(
        provider.call_count(),
        1,
        "late approval must not trigger another provider turn"
    );
    assert_no_tool_execution(cycle, &run_id, call_id, &messages_at_terminal);
    let entries = run_effect_entries(http, &cycle.token, &run_id).await;
    assert!(
        entries.iter().all(|entry| entry["call_id"] != call_id),
        "no committed Native receipt may exist for the unexecuted call"
    );

    let events_after_late = typed_event_facts(cycle, &run_id);
    assert_eq!(
        events_after_late, events_at_terminal,
        "late approval must not append or rewrite run events"
    );
    let messages_after_late = typed_messages(http, cycle, &cycle.token, session_id).await;
    assert_eq!(
        messages_after_late, messages_at_terminal,
        "late approval must not rewrite the committed message projection"
    );
    assert_eq!(
        messages_at_terminal, messages_at_pending,
        "the cancellation terminal must not delete or rewrite committed messages"
    );
    let head_after = current_head(cycle, session_id, control_run, control_call);
    assert_eq!(head_after, head_before, "managed branch head must not move");
    assert_eq!(head_after["head_object_id"], control_head["head_object_id"]);
    assert_eq!(head_after["head_version"], control_head["head_version"]);

    let sse = http.typed_sse(&cycle.token, &run_id).await;
    assert_sse_matches_typed(cycle, &sse, &run_id, "run.cancelled", expected_reason);
    assert_durable_events_match(cycle, &sse, &run_id);
    assert!(
        messages_at_terminal.iter().any(|message| {
            message["run_id"].as_str() == Some(run_id.as_str())
                && message["role"] == "user"
                && message.to_string().contains(input)
        }),
        "the admitted user message stays committed"
    );
    println!(
        "LIFECYCLE_SUMMARY {}",
        json!({
            "phase": phase,
            "terminal_events": sse.iter().filter(|event| event.terminal).count(),
            "terminal_reason": expected_reason,
            "event_count": sse.len(),
            "tool_events": 0,
            "provider_calls": provider.call_count(),
            "committed_receipts_for_call": entries.iter().filter(|entry| entry["call_id"] == call_id).count(),
            "messages": messages_at_terminal.len(),
            "branch_head_version": head_after["head_version"],
            "approval_state": stored["rows"][0][7],
            "late_approval_status": status,
        })
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_and_deadline_reject_late_approval_without_execution() {
    let cycle = Cycle::open_required_with_approvals(
        &format!("t16-cancel-{}", uuid::Uuid::new_v4().simple()),
        Duration::from_secs(900),
        "ask",
        Some("user"),
    );
    let http = Http::bind(cycle.state.clone()).await;
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (graph, _) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (control_run, control_head) = healthy_user_approved_write(
        &cycle,
        &http,
        &graph,
        &session_id,
        "write-control",
        "out-control.txt",
        "healthy control write",
    )
    .await;
    assert!(!cycle.workspace.join("out-control.txt").exists());
    assert_cancelled_late_approval_no_effect(
        &cycle,
        &http,
        "stop",
        &graph,
        &session_id,
        &control_head,
        &control_run,
        "write-control",
        "late write after owner stop",
        "write-late-stop",
        "out-late-stop.txt",
        false,
    )
    .await;
    assert!(!cycle.workspace.join("out-late-stop.txt").exists());
    http.close().await;
    shutdown_when_idle(&cycle.state).await;

    let deadline = Cycle::open_with_approvals(
        &format!("t16-deadline-{}", uuid::Uuid::new_v4().simple()),
        Duration::from_secs(15),
        "ask",
        Some("user"),
    );
    let http = Http::bind(deadline.state.clone()).await;
    install_pair(&http, &deadline.token, &deadline.source).await;
    let (graph, _) = activate(
        &http,
        &deadline.token,
        &deadline.config,
        &deadline.db,
        "org.rustscript.tools.effecta",
    )
    .await;
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
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (control_run, control_head) = healthy_user_approved_write(
        &deadline,
        &http,
        &graph,
        &session_id,
        "write-control",
        "out-control.txt",
        "healthy control write",
    )
    .await;
    assert!(!deadline.workspace.join("out-control.txt").exists());
    assert_cancelled_late_approval_no_effect(
        &deadline,
        &http,
        "deadline",
        &graph,
        &session_id,
        &control_head,
        &control_run,
        "write-control",
        "late write after original deadline",
        "write-late-deadline",
        "out-late-deadline.txt",
        true,
    )
    .await;
    assert!(!deadline.workspace.join("out-late-deadline.txt").exists());
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
    assert_eq!(branch_run["publication"], json!("not_published"));
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
    // The Native-origin AfterIntent cut now traps the caller VM through the
    // host error boundary, so the run terminal carries the exact host failure
    // instead of the obsolete validation-accounting fallback.
    assert_eq!(
        failed["data"]["error_message"],
        "run host failure: managed fixture cut after durable intent"
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

// Pure-leaf negative control: a stateless read through the phase-A pure leaf,
// cut by the existing AfterIntent fault, must not publish, must not leave a
// committed effect, and must not move the active graph.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn pure_leaf_read_after_intent_cut_publishes_nothing_and_keeps_active_graph() {
    use rustscript_agent::effects::{
        ManagedEffectFault, ManagedEffectGetRequest, ManagedOwnerScope, ManagedPublicationStatus,
    };
    let link = open_phase_a_managed_link("leaf-cut").await;
    link.state
        .service()
        .inject_managed_effect_fault(ManagedEffectFault::AfterIntent)
        .unwrap();
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(tool_call("read-leaf-cut", "read_file", "note.txt"));
    provider.push_ok(stop_turn("cut-done"));
    link.state.service().inject_provider_host(provider);
    let (status, admitted) = link
        .http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": link.session_id, "input": "cut the pure-leaf read"}),
            Some(&link.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], link.graph);
    assert_eq!(admitted["activation_generation"], link.generation);
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&link.state, &run_id).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    let cut_events = link.state.service().run_events(&run_id);
    assert!(
        cut_events.iter().any(|event| {
            event["event"] == "tool.started" && event["data"]["tool_call_id"] == "read-leaf-cut"
        }),
        "AfterIntent still leaves the started read intent: {cut_events:?}"
    );
    assert!(
        !cut_events
            .iter()
            .any(|event| event["event"] == "tool.completed" || event["event"] == "tool.failed"),
        "the cut is not a recorded tool terminal: {cut_events:?}"
    );
    assert!(
        !link
            .state
            .service()
            .session_messages(&link.session_id)
            .iter()
            .any(|message| message["tool_call_id"] == "read-leaf-cut"),
        "the cut pure-leaf read must not publish a tool result"
    );
    let projection = projected_run(&link.http, &link.token, &link.session_id, &run_id).await;
    assert!(
        !projection.contains("libA:hello"),
        "the cut read must not publish leaf-labeled bytes: {projection}"
    );
    let (status, effects) = link
        .http
        .request(
            "GET",
            &format!("/v1/runs/{run_id}/effects?limit=128"),
            json!(null),
            Some(&link.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    assert!(
        !effects["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["call_id"] == "read-leaf-cut" && entry["state"] == "committed"),
        "the cut must not leave a committed effect: {effects:?}"
    );
    if let Some(record) = link
        .state
        .persistence()
        .unwrap()
        .managed_effect_get(&ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: link.session_id.clone(),
                run_id: run_id.clone(),
            },
            call_id: "read-leaf-cut".into(),
        })
        .unwrap()
    {
        assert!(
            record.prepared.is_none(),
            "AfterIntent precedes native view construction"
        );
        assert!(record.outcome.is_none(), "cut must not publish an outcome");
        assert_ne!(
            record.state,
            ManagedPublicationStatus::Committed,
            "cut must not leave a committed effect"
        );
    }
    // The active graph does not move: the same pinned program still serves the
    // next read on the same graph generation.
    assert_eq!(admitted["graph_id"], link.graph);
    let after = Arc::new(ScriptedProvider::new());
    after.push_ok(tool_call("read-leaf-after", "read_file", "note.txt"));
    after.push_ok(stop_turn("done-after"));
    link.state.service().inject_provider_host(after);
    let (status, readmitted) = link
        .http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": link.session_id, "input": "read after the cut"}),
            Some(&link.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &readmitted));
    assert_eq!(readmitted["graph_id"], link.graph);
    assert_eq!(readmitted["activation_generation"], link.generation);
    let after_id = readmitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&link.state, &after_id)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;
    let after_projection =
        projected_run(&link.http, &link.token, &link.session_id, &after_id).await;
    assert!(
        after_projection.contains("libA:hello"),
        "{after_projection}"
    );
    link.http.close().await;
    shutdown_when_idle(&link.state).await;
}

// 421 phase A service cut: one AcceptedPublisher stateless read tool plus one
// pure leaf library. The service prepare/activate path must keep the combined
// program, the managed run must return the leaf-labeled bytes through the
// original commit path, the linked tool plus its single pure leaf must be a
// checkpointable inventory that names its own captured graph generation,
// revoking A must block the next run, and the shared-leaf graph C must keep
// reading.
#[tokio::test(flavor = "multi_thread")]
async fn phase_a_library_graph_reads_labels_revoke_blocks_and_shared_leaf_still_reads() {
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rustscript_agent::plugins::{
        InstallAuthorization, PackageStore, PublisherKey, trusted_tool_package_root,
    };

    const LEAF_ID: &str = "org.rustscript.lib.phasetext";
    const TOOL_A_ID: &str = "org.rustscript.tools.phasea";
    const TOOL_C_ID: &str = "org.rustscript.tools.phasec";
    let leaf_manifest = format!(
        "format: rustscript.plugin/v1\nid: {LEAF_ID}\nversion: 1.0.0\nkind: library\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.library/v1\nhost_abi: agent.cap/v1\nentry:\n  path: format.rss\n  export: format\ndependencies: []\ncapabilities: []\neffects:\n  contract: agent.effects/v1\n  entries:\n    format:\n      direct: []\n      delegated: []\n"
    );
    let tool_manifest = |id: &str| {
        format!(
            "format: rustscript.plugin/v1\nid: {id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: text\n    id: {LEAF_ID}\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
        )
    };
    let run_source = r#"use bytes;
use text::{format};
fn map_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}

fn map_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}

fn map_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}

fn map_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}

pub fn run(context: map) -> map {
    let prepared: map = agent_runtime::tool_prepare(map_map(context, "prepare"));
    if map_string(prepared, "kind", "") == "replay" => {
        map_map(prepared, "result")
    } else if map_bool(prepared, "ok", false) == false => {
        prepared
    } else => {
        let token: string = map_string(prepared, "execution_token", "");
        let arguments: map = map_map(context, "arguments");
        let path: string = map_string(arguments, "path", "");
        let meta: map = cap::fs_metadata(token, path);
        if map_bool(meta, "ok", false) == false => {
            meta
        } else => {
            let file_len: int = map_int(meta, "len", 0);
            let limit: int = file_len;
            let read: map = cap::fs_read_range(token, path, 0, limit);
            if map_bool(read, "ok", false) == false => {
                read
            } else => {
                let payload: bytes = read.bytes;
                let labeled: string = format(bytes::to_utf8(payload));
                let result: map = { ok: true, content: labeled, data: {}, error: null, truncated: false, artifacts: [] };
                let committed: map = agent_runtime::tool_commit(token, result);
                if map_string(committed, "kind", "") == "committed" => {
                    map_map(committed, "result")
                } else => {
                    committed
                }
            }
        }
    }
}
"#;

    // The fixtures are signed with this test's own accepted key, so the
    // cycle is built here with that key: the service revalidates every
    // capture against its own bound policy on read.
    use rustscript_agent::{
        AgentGatewayConfig, AgentGatewayState,
        config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
        effects::ResourceQuota,
    };
    use std::path::PathBuf;
    struct PhaseACycle {
        workspace: PathBuf,
        source: PathBuf,
        db: PathBuf,
        token: String,
        config: AgentGatewayConfig,
        auth: InstallAuthorization,
        state: AgentGatewayState,
    }
    let label = format!("t421-liblink-{}", uuid::Uuid::new_v4().simple());
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap()).join(label);
    let _ = std::fs::remove_dir_all(&root);
    let workspace = root.join("workspace");
    let home = root.join("workspace-home");
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(workspace.join("seed.txt"), b"seed").unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home, &source] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let token = uuid::Uuid::new_v4().to_string();
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.run_timeout = Duration::from_secs(900);
    let db = root.join("gateway.sqlite");
    let cycle = PhaseACycle {
        workspace: workspace.clone(),
        source: source.clone(),
        db: db.clone(),
        token: token.clone(),
        config: config.clone(),
        auth: auth.clone(),
        state: AgentGatewayState::with_sqlite_path(config, &db)
            .unwrap()
            .with_workspace_home(&home)
            .with_plugin_control(auth, source, "owner-space")
            .unwrap(),
    };
    let store = PackageStore::open(trusted_tool_package_root(&cycle.db)).unwrap();
    let stage = |dir: &str, manifest: &str, files: &[(&str, &[u8])]| {
        let package = cycle.source.join(dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
        for (name, body) in files {
            std::fs::write(package.join(name), body).unwrap();
        }
        let payload = store.signature_payload(&package).unwrap();
        std::fs::write(
            package.join("signature.ed25519"),
            pair.sign(&payload).as_ref(),
        )
        .unwrap();
        store.install(&package, &cycle.auth).unwrap();
    };
    stage(
        "package-phaselib",
        &leaf_manifest,
        &[(
            "format.rss",
            b"pub fn format(value: string) -> string { \"libA:\" + value }\n".as_slice(),
        )],
    );
    for (dir, id) in [("package-phasea", TOOL_A_ID), ("package-phasec", TOOL_C_ID)] {
        stage(
            dir,
            &tool_manifest(id),
            &[
                ("run.rss", run_source.as_bytes()),
                (
                    "catalog.rss",
                    include_bytes!("../rss/tools/types.rss").as_slice(),
                ),
            ],
        );
    }

    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    let (graph_a, generation_a) =
        activate(&http, &cycle.token, &cycle.config, &cycle.db, TOOL_A_ID).await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    std::fs::write(cycle.workspace.join("note.txt"), b"hello").unwrap();

    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(tool_call("read-lib-a", "read_file", "note.txt"));
    provider.push_ok(stop_turn("done-a"));
    cycle.state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "read note through the leaf library"}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph_a);
    assert_eq!(admitted["activation_generation"], generation_a);
    let run_a = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&cycle.state, &run_a)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;
    let projection = projected_run(&http, &cycle.token, &session_id, &run_a).await;
    assert!(projection.contains("libA:hello"), "{projection}");
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
    let read = effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == "read-lib-a")
        .expect("native read receipt through the library link")
        .clone();
    assert_eq!(read["state"], "read_only");
    let workspace_id = read["workspace_id"].as_str().unwrap().to_string();
    let branch_id = read["branch_id"].as_str().unwrap().to_string();
    let epoch = read["epoch"].as_u64().unwrap();
    assert_closed(&effects, &cycle.token, &hidden);

    let (status, checkpoint) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_a,
                "workspace_id": workspace_id,
                "source_branch_id": branch_id,
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
    assert_eq!(
        checkpoint["checkpoint"]["graph"]["captured_activation_generation"],
        generation_a
    );
    assert_eq!(checkpoint["checkpoint"]["plugin_state"]["roots"], json!([]));

    revoke_graph(
        &cycle.config,
        &cycle.db,
        &bound_store(&cycle.db, &cycle.auth),
        &graph_a,
    )
    .unwrap();
    let (status, prepared) = http
        .request(
            "POST",
            &format!("/v1/plugin-graphs/{graph_a}/prepare"),
            json!({}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &prepared));
    assert_eq!(prepared["error"]["code"], "plugin_graph_revoked");
    let denied_provider = Arc::new(ScriptedProvider::new());
    denied_provider.push_ok(tool_call("write-revoked", "write_file", "revoked.txt"));
    denied_provider.push_ok(stop_turn("should-not-run"));
    cycle.state.service().inject_provider_host(denied_provider);
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

    let (graph_c, generation_c) =
        activate(&http, &cycle.token, &cycle.config, &cycle.db, TOOL_C_ID).await;
    assert!(generation_c > generation_a);
    let provider_c = Arc::new(ScriptedProvider::new());
    provider_c.push_ok(tool_call("read-lib-c", "read_file", "note.txt"));
    provider_c.push_ok(stop_turn("done-c"));
    cycle.state.service().inject_provider_host(provider_c);
    let (status, run_c) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "read through the shared leaf"}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &run_c));
    assert_eq!(run_c["graph_id"], graph_c);
    let run_c_id = run_c["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&cycle.state, &run_c_id)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;
    let projection_c = projected_run(&http, &cycle.token, &session_id, &run_c_id).await;
    assert!(projection_c.contains("libA:hello"), "{projection_c}");
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

// ---------------------------------------------------------------------------
// 456 F4: the managed production cut of the phase-A tool + pure leaf. A real
// signed tool carries the captured managed catalog, a real run is admitted and
// pinned, and a write request is handed to the actual Native boundary.
// ---------------------------------------------------------------------------
struct PhaseALink {
    workspace: std::path::PathBuf,
    db: std::path::PathBuf,
    store: rustscript_agent::plugins::PackageStore,
    token: String,
    state: rustscript_agent::AgentGatewayState,
    http: Http,
    graph: String,
    generation: u64,
    session_id: String,
}

async fn open_phase_a_managed_link(label: &str) -> PhaseALink {
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rustscript_agent::plugins::{
        InstallAuthorization, PackageStore, PublisherKey, trusted_tool_package_root,
    };
    use rustscript_agent::{
        AgentGatewayConfig, AgentGatewayState,
        config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
        effects::ResourceQuota,
    };

    const LEAF_ID: &str = "org.rustscript.lib.phasetext";
    const TOOL_A_ID: &str = "org.rustscript.tools.phasea";
    let leaf_manifest = format!(
        "format: rustscript.plugin/v1\nid: {LEAF_ID}\nversion: 1.0.0\nkind: library\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.library/v1\nhost_abi: agent.cap/v1\nentry:\n  path: format.rss\n  export: format\ndependencies: []\ncapabilities: []\neffects:\n  contract: agent.effects/v1\n  entries:\n    format:\n      direct: []\n      delegated: []\n"
    );
    let tool_manifest = format!(
        "format: rustscript.plugin/v1\nid: {TOOL_A_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: text\n    id: {LEAF_ID}\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
    );
    let run_source = r#"use bytes;
use text::{format};
fn map_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}

fn map_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}

fn map_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}

fn map_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}

pub fn run(context: map) -> map {
    let prepared: map = agent_runtime::tool_prepare(map_map(context, "prepare"));
    if map_string(prepared, "kind", "") == "replay" => {
        map_map(prepared, "result")
    } else if map_bool(prepared, "ok", false) == false => {
        prepared
    } else => {
        let token: string = map_string(prepared, "execution_token", "");
        let arguments: map = map_map(context, "arguments");
        let path: string = map_string(arguments, "path", "");
        let meta: map = cap::fs_metadata(token, path);
        if map_bool(meta, "ok", false) == false => {
            meta
        } else => {
            let file_len: int = map_int(meta, "len", 0);
            let read: map = cap::fs_read_range(token, path, 0, file_len);
            if map_bool(read, "ok", false) == false => {
                read
            } else => {
                let payload: bytes = read.bytes;
                let labeled: string = format(bytes::to_utf8(payload));
                let result: map = { ok: true, content: labeled, data: {}, error: null, truncated: false, artifacts: [] };
                let committed: map = agent_runtime::tool_commit(token, result);
                if map_string(committed, "kind", "") == "committed" => {
                    map_map(committed, "result")
                } else => {
                    committed
                }
            }
        }
    }
}
"#;

    let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("t456-{label}-{}", uuid::Uuid::new_v4().simple()));
    let _ = std::fs::remove_dir_all(&root);
    let workspace = root.join("workspace");
    let home = root.join("workspace-home");
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(workspace.join("seed.txt"), b"seed").unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home, &source] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let token = uuid::Uuid::new_v4().to_string();
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    // 461: the undeclared-process case must be refused by the managed effect
    // fence, not by the risk approval gate, so the execute class is permitted
    // here exactly like the in-crate managed fixtures.
    config.approvals.process = "allow".into();
    config.run_timeout = Duration::from_secs(900);
    let db = root.join("gateway.sqlite");
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    let store = PackageStore::open(trusted_tool_package_root(&db)).unwrap();
    let stage = |dir: &str, manifest: &str, files: &[(&str, &[u8])]| {
        let package = source.join(dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
        for (name, body) in files {
            std::fs::write(package.join(name), body).unwrap();
        }
        let payload = store.signature_payload(&package).unwrap();
        std::fs::write(
            package.join("signature.ed25519"),
            pair.sign(&payload).as_ref(),
        )
        .unwrap();
        store.install(&package, &auth).unwrap();
    };
    stage(
        "package-phaselib",
        &leaf_manifest,
        &[(
            "format.rss",
            b"pub fn format(value: string) -> string { \"libA:\" + value }\n".as_slice(),
        )],
    );
    stage(
        "package-phasea",
        &tool_manifest,
        &[
            ("run.rss", run_source.as_bytes()),
            (
                "catalog.rss",
                include_bytes!("../rss/tools/types.rss").as_slice(),
            ),
        ],
    );
    let http = Http::bind(state.clone()).await;
    let (graph, generation) = activate(&http, &token, &config, &db, TOOL_A_ID).await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    std::fs::write(workspace.join("note.txt"), b"hello").unwrap();
    PhaseALink {
        workspace,
        db,
        store,
        token,
        state,
        http,
        graph,
        generation,
        session_id,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn phase_a_native_boundary_denies_undeclared_write_after_real_pin() {
    let link = open_phase_a_managed_link("write-denied").await;
    // Positive control: the same real pin returns the leaf-labeled read.
    let reader = Arc::new(ScriptedProvider::new());
    reader.push_ok(tool_call("read-lib-a", "read_file", "note.txt"));
    reader.push_ok(stop_turn("done-read"));
    link.state.service().inject_provider_host(reader);
    let (status, admitted) = link
        .http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": link.session_id, "input": "read through the leaf"}),
            Some(&link.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], link.graph);
    assert_eq!(admitted["activation_generation"], link.generation);
    let run_a = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&link.state, &run_a).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    let read_events = link.state.service().run_events(&run_a);
    assert!(
        read_events
            .iter()
            .any(|event| event["event"] == "run.completed"),
        "positive read run must complete: {read_events:?}"
    );
    let projection = projected_run(&link.http, &link.token, &link.session_id, &run_a).await;
    assert!(projection.contains("libA:hello"), "{projection}");

    // The same pinned read-only program receives an undeclared write request.
    let writer = Arc::new(ScriptedProvider::new());
    writer.push_ok(tool_call("write-denied", "write_file", "denied-write.txt"));
    writer.push_ok(stop_turn("done-write"));
    link.state.service().inject_provider_host(writer);
    let (status, admitted) = link
        .http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": link.session_id, "input": "write through the read-only pin"}),
            Some(&link.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], link.graph);
    let run_w = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&link.state, &run_w).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    let events = link.state.service().run_events(&run_w);
    // The pinned read-only capture declares only workspace.fs.read, so the
    // Native managed-authority check refuses the write before any effect. With
    // the production "allow" write policy the harness requests the Native
    // attestation first; `checked_managed_policy` -> `seal_call_policy` returns
    // "managed undeclared effect", which the harness surfaces as this exact
    // terminal policy rejection (never as a successful tool call).
    let refusal = events.iter().find(|event| {
        (event["event"] == "run.failed"
            && event["data"]["error_message"] == "native policy facts rejected this action")
            || (event["event"] == "tool.failed"
                && event["data"]["tool_call_id"] == "write-denied"
                && event["data"]["error_code"] == "managed_effect_denied")
    });
    assert!(
        refusal.is_some(),
        "the undeclared write must be refused at the Native boundary: {events:?}"
    );
    assert!(
        !events.iter().any(|event| event["event"] == "run.completed"),
        "a refused write must not complete the run: {events:?}"
    );
    assert!(
        !events.iter().any(|event| {
            event["event"] == "tool.completed" && event["data"]["tool_call_id"] == "write-denied"
        }),
        "a refused write must not report a completed tool call: {events:?}"
    );
    assert!(
        !link.workspace.join("denied-write.txt").exists(),
        "no write may reach the workspace"
    );
    let (status, effects) = link
        .http
        .request(
            "GET",
            &format!("/v1/runs/{run_w}/effects?limit=128"),
            json!(null),
            Some(&link.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    assert!(
        !effects["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["call_id"] == "write-denied"),
        "a refused write must not register a managed effect: {effects}"
    );
    link.http.close().await;
    shutdown_when_idle(&link.state).await;
    let _ = std::fs::remove_dir_all(link.db.parent().unwrap());
}

// ---------------------------------------------------------------------------
// 461: real Service F4 stages on the same signed captured pinned graph A.
// The provider hook pauses the actual run worker after admission sealed the
// pin and built the live host bridge, but before the Native boundary begins.
// ---------------------------------------------------------------------------
struct PausingToolProvider {
    entered: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    release: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    call_id: String,
    tool_name: String,
    arguments: Value,
    step: std::sync::atomic::AtomicUsize,
}

fn pausing_tool_provider(
    call_id: &str,
    tool_name: &str,
    arguments: Value,
) -> (
    Arc<PausingToolProvider>,
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
) {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    (
        Arc::new(PausingToolProvider {
            entered: std::sync::Mutex::new(Some(entered_tx)),
            release: std::sync::Mutex::new(Some(release_rx)),
            call_id: call_id.to_string(),
            tool_name: tool_name.to_string(),
            arguments,
            step: std::sync::atomic::AtomicUsize::new(0),
        }),
        entered_rx,
        release_tx,
    )
}

impl rustscript_agent::AgentProviderHost for PausingToolProvider {
    fn call(&self, _request: &Value, _cancellation: &rustscript_agent::RunCancellation) -> Value {
        if self.step.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
            return json!({"ok": true, "response": stop_turn("after-tool"), "error": {}});
        }
        if let Some(entered) = self
            .entered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = entered.send(());
        }
        if let Some(release) = self
            .release
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            release
                .recv_timeout(Duration::from_secs(60))
                .expect("fixture must release the paused provider turn");
        }
        json!({
            "ok": true,
            "response": json!({
                "text": "",
                "tool_calls": [{
                    "id": self.call_id,
                    "name": self.tool_name,
                    "arguments": self.arguments,
                }],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                "reasoning": "",
                "stop_reason": "tool_calls"
            }),
            "error": {}
        })
    }
}

fn terminal_event(events: &[Value]) -> Option<Value> {
    events
        .iter()
        .find(|event| {
            matches!(
                event["event"].as_str(),
                Some("run.completed") | Some("run.failed") | Some("run.cancelled")
            )
        })
        .cloned()
}

#[tokio::test(flavor = "multi_thread")]
async fn phase_a_service_begin_denies_revoke_between_pin_and_native_begin() {
    let link = open_phase_a_managed_link("service-revoke-begin").await;
    let (provider, entered, release) =
        pausing_tool_provider("service-read-1", "read_file", json!({"path": "note.txt"}));
    link.state.service().inject_provider_host(provider);
    let (status, admitted) = link
        .http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": link.session_id, "input": "read pinned A after its graph is revoked"}),
            Some(&link.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(
        admitted["graph_id"], link.graph,
        "the run must be admitted on the same captured graph A: {admitted}"
    );
    assert_eq!(admitted["activation_generation"], link.generation);
    let run = admitted["run_id"].as_str().unwrap().to_string();
    entered
        .recv_timeout(Duration::from_secs(60))
        .expect("the worker must reach the provider after sealing the pin");

    // Real same-control-store revocation of the exact admitted graph, while the
    // live run holds its sealed pin and host bridge and has not begun the tool.
    let config = (**link.state.service().config()).clone();
    revoke_graph(&config, &link.db, &link.store, &link.graph)
        .expect("graph A must revoke through the narrow topology");
    release.send(()).expect("release the paused provider turn");

    wait_until(|| terminal_event(&link.state.service().run_events(&run)).is_some()).await;
    let events = link.state.service().run_events(&run);
    println!("phase_a_service begin evidence: {events:?}");
    assert!(
        !events.iter().any(|event| event["event"] == "tool.started"),
        "a revoked graph must not start the pinned call: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| event["event"] == "tool.completed"),
        "a revoked graph must not complete the pinned call: {events:?}"
    );
    let terminal = terminal_event(&events).expect("terminal event");
    assert_ne!(
        terminal["event"], "run.completed",
        "a revoked pinned run must not complete: {terminal}"
    );
    assert!(
        events
            .iter()
            .any(|event| event.to_string().contains("plugin_graph_revoked")),
        "the refusal must be the exact typed graph revocation: {events:?}"
    );
    assert!(
        !projected_run(&link.http, &link.token, &link.session_id, &run)
            .await
            .contains("libA:hello"),
        "the revoked leaf must never deliver its labeled bytes"
    );
    let (status, effects) = link
        .http
        .request(
            "GET",
            &format!("/v1/runs/{run}/effects?limit=128"),
            json!(null),
            Some(&link.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    assert!(
        !effects["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["call_id"] == "service-read-1"),
        "a refused begin must not register a managed effect: {effects}"
    );
    link.http.close().await;
    shutdown_when_idle(&link.state).await;
    let _ = std::fs::remove_dir_all(link.db.parent().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn phase_a_service_cancel_root_denies_before_native_begin_after_pin() {
    let link = open_phase_a_managed_link("service-cancel").await;
    let (provider, entered, release) =
        pausing_tool_provider("service-read-2", "read_file", json!({"path": "note.txt"}));
    link.state.service().inject_provider_host(provider);
    let (status, admitted) = link
        .http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": link.session_id, "input": "cancel the pinned run before its tool begins"}),
            Some(&link.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], link.graph);
    let run = admitted["run_id"].as_str().unwrap().to_string();
    entered
        .recv_timeout(Duration::from_secs(60))
        .expect("the worker must reach the provider after sealing the pin");

    // The run's own admitted cancellation root, not a fixture-created clock.
    let (status, stopped) = link
        .http
        .request(
            "POST",
            &format!("/v1/runs/{run}/stop"),
            json!({}),
            Some(&link.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &stopped));
    release.send(()).expect("release the paused provider turn");

    wait_until(|| terminal_event(&link.state.service().run_events(&run)).is_some()).await;
    let events = link.state.service().run_events(&run);
    println!("phase_a_service cancel evidence: {events:?}");
    let terminal = terminal_event(&events).expect("terminal event");
    assert_eq!(
        terminal["event"], "run.cancelled",
        "the admitted cancellation root must cancel the pinned run: {terminal}"
    );
    assert!(
        !events.iter().any(|event| event["event"] == "tool.started"),
        "a cancelled run must not start the pinned call: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| event["event"] == "tool.completed"),
        "a cancelled run must not complete the pinned call: {events:?}"
    );
    assert!(
        !events.iter().any(|event| event["event"] == "run.completed"),
        "a cancelled run must not report success: {events:?}"
    );
    let (status, effects) = link
        .http
        .request(
            "GET",
            &format!("/v1/runs/{run}/effects?limit=128"),
            json!(null),
            Some(&link.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    assert!(
        !effects["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["call_id"] == "service-read-2"),
        "a cancelled begin must not register a managed effect: {effects}"
    );
    assert!(
        !projected_run(&link.http, &link.token, &link.session_id, &run)
            .await
            .contains("libA:hello"),
        "the cancelled leaf must never deliver its labeled bytes"
    );
    link.http.close().await;
    shutdown_when_idle(&link.state).await;
    let _ = std::fs::remove_dir_all(link.db.parent().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn phase_a_service_terminal_argv_denies_undeclared_process_effect() {
    let link = open_phase_a_managed_link("service-process").await;
    let sentinel = link
        .workspace
        .parent()
        .unwrap()
        .join("process-spawn-sentinel");
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({
        "text": "",
        "tool_calls": [{
            "id": "service-process-1",
            "name": "terminal",
            "arguments": {
                "argv": ["/bin/sh", "-c", format!("printf x > '{}'", sentinel.display())],
                "timeout_ms": 1000
            }
        }],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    provider.push_ok(stop_turn("after-process"));
    link.state.service().inject_provider_host(provider);
    let (status, admitted) = link
        .http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": link.session_id, "input": "spawn under the read-only pinned graph"}),
            Some(&link.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], link.graph);
    let run = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| terminal_event(&link.state.service().run_events(&run)).is_some()).await;
    let events = link.state.service().run_events(&run);
    println!("phase_a_service process evidence: {events:?}");
    let terminal = terminal_event(&events).expect("terminal event");
    assert_ne!(
        terminal["event"], "run.completed",
        "an undeclared process effect must not complete: {terminal}"
    );
    assert!(
        !events.iter().any(|event| {
            event["event"] == "tool.completed"
                && event["data"]["tool_call_id"] == "service-process-1"
        }),
        "the undeclared process call must not complete: {events:?}"
    );
    assert!(
        events.iter().any(|event| {
            event.to_string().contains("managed_effect_denied")
                || event["data"]["error_message"] == "native policy facts rejected this action"
        }),
        "the refusal must be the typed managed-effect fence: {events:?}"
    );
    assert!(
        !sentinel.exists(),
        "the process must be refused before any OS spawn"
    );
    let (status, effects) = link
        .http
        .request(
            "GET",
            &format!("/v1/runs/{run}/effects?limit=128"),
            json!(null),
            Some(&link.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    assert!(
        !effects["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["call_id"] == "service-process-1"),
        "a refused process must not register a managed effect: {effects}"
    );
    link.http.close().await;
    shutdown_when_idle(&link.state).await;
    let _ = std::fs::remove_dir_all(link.db.parent().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn pure_leaf_checkpoint_restore_pins_captured_generation_not_active_graph() {
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rustscript_agent::plugins::{
        InstallAuthorization, PackageStore, PublisherKey, trusted_tool_package_root,
    };
    use rustscript_agent::{
        AgentGatewayConfig, AgentGatewayState,
        config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
        effects::ResourceQuota,
    };
    use std::path::PathBuf;

    const LEAF_ID: &str = "org.rustscript.lib.phasetext";
    const TOOL_A_ID: &str = "org.rustscript.tools.phasea";
    const TOOL_C_ID: &str = "org.rustscript.tools.phasec";
    let leaf_manifest = format!(
        "format: rustscript.plugin/v1\nid: {LEAF_ID}\nversion: 1.0.0\nkind: library\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.library/v1\nhost_abi: agent.cap/v1\nentry:\n  path: format.rss\n  export: format\ndependencies: []\ncapabilities: []\neffects:\n  contract: agent.effects/v1\n  entries:\n    format:\n      direct: []\n      delegated: []\n"
    );
    let tool_manifest = |id: &str| {
        format!(
            "format: rustscript.plugin/v1\nid: {id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: text\n    id: {LEAF_ID}\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
        )
    };
    let run_source = r#"use bytes;
use text::{format};
fn map_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}

fn map_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}

fn map_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}

fn map_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}

pub fn run(context: map) -> map {
    let prepared: map = agent_runtime::tool_prepare(map_map(context, "prepare"));
    if map_string(prepared, "kind", "") == "replay" => {
        map_map(prepared, "result")
    } else if map_bool(prepared, "ok", false) == false => {
        prepared
    } else => {
        let token: string = map_string(prepared, "execution_token", "");
        let arguments: map = map_map(context, "arguments");
        let path: string = map_string(arguments, "path", "");
        let meta: map = cap::fs_metadata(token, path);
        if map_bool(meta, "ok", false) == false => {
            meta
        } else => {
            let file_len: int = map_int(meta, "len", 0);
            let limit: int = file_len;
            let read: map = cap::fs_read_range(token, path, 0, limit);
            if map_bool(read, "ok", false) == false => {
                read
            } else => {
                let payload: bytes = read.bytes;
                let labeled: string = format(bytes::to_utf8(payload));
                let result: map = { ok: true, content: labeled, data: {}, error: null, truncated: false, artifacts: [] };
                let committed: map = agent_runtime::tool_commit(token, result);
                if map_string(committed, "kind", "") == "committed" => {
                    map_map(committed, "result")
                } else => {
                    committed
                }
            }
        }
    }
}
"#;
    struct RestoreCycle {
        workspace: PathBuf,
        source: PathBuf,
        db: PathBuf,
        token: String,
        config: AgentGatewayConfig,
        state: AgentGatewayState,
    }
    let label = format!("t605-leaf-restore-{}", uuid::Uuid::new_v4().simple());
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap()).join(label);
    let _ = std::fs::remove_dir_all(&root);
    let workspace = root.join("workspace");
    let home = root.join("workspace-home");
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(workspace.join("seed.txt"), b"seed").unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home, &source] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let token = uuid::Uuid::new_v4().to_string();
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.run_timeout = Duration::from_secs(900);
    let db = root.join("gateway.sqlite");
    let cycle = RestoreCycle {
        workspace: workspace.clone(),
        source: source.clone(),
        db: db.clone(),
        token: token.clone(),
        config: config.clone(),
        state: AgentGatewayState::with_sqlite_path(config, &db)
            .unwrap()
            .with_workspace_home(&home)
            .with_plugin_control(auth.clone(), source, "owner-space")
            .unwrap(),
    };
    let store = PackageStore::open(trusted_tool_package_root(&cycle.db)).unwrap();
    let stage = |dir: &str, manifest: &str, files: &[(&str, &[u8])]| {
        let package = cycle.source.join(dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
        for (name, body) in files {
            std::fs::write(package.join(name), body).unwrap();
        }
        let payload = store.signature_payload(&package).unwrap();
        std::fs::write(
            package.join("signature.ed25519"),
            pair.sign(&payload).as_ref(),
        )
        .unwrap();
        store.install(&package, &auth).unwrap();
    };
    stage(
        "package-phaselib",
        &leaf_manifest,
        &[(
            "format.rss",
            b"pub fn format(value: string) -> string { \"libA:\" + value }\n".as_slice(),
        )],
    );
    for (dir, id) in [("package-phasea", TOOL_A_ID), ("package-phasec", TOOL_C_ID)] {
        stage(
            dir,
            &tool_manifest(id),
            &[
                ("run.rss", run_source.as_bytes()),
                (
                    "catalog.rss",
                    include_bytes!("../rss/tools/types.rss").as_slice(),
                ),
            ],
        );
    }

    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    let (graph_a, generation_a) =
        activate(&http, &cycle.token, &cycle.config, &cycle.db, TOOL_A_ID).await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    std::fs::write(cycle.workspace.join("note.txt"), b"hello").unwrap();

    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(tool_call("read-leaf-a", "read_file", "note.txt"));
    provider.push_ok(stop_turn("done-a"));
    cycle.state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "read note through the leaf library"}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph_a);
    assert_eq!(admitted["activation_generation"], generation_a);
    let run_a = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&cycle.state, &run_a)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;
    let projection = projected_run(&http, &cycle.token, &session_id, &run_a).await;
    assert!(projection.contains("libA:hello"), "{projection}");
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
    let read = effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == "read-leaf-a")
        .expect("native read receipt through the leaf link")
        .clone();
    assert_eq!(read["state"], "read_only");
    let workspace_id = read["workspace_id"].as_str().unwrap().to_string();
    let source_branch = read["branch_id"].as_str().unwrap().to_string();
    let epoch = read["epoch"].as_u64().unwrap();
    assert_closed(&effects, &cycle.token, &hidden);

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
    assert_eq!(
        checkpoint["checkpoint"]["graph"]["captured_activation_generation"],
        generation_a
    );
    assert_eq!(checkpoint["checkpoint"]["plugin_state"]["roots"], json!([]));
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();

    std::fs::write(
        cycle.workspace.join("note.txt"),
        b"changed-after-checkpoint",
    )
    .unwrap();
    let (graph_c, generation_c) =
        activate(&http, &cycle.token, &cycle.config, &cycle.db, TOOL_C_ID).await;
    assert_ne!(graph_c, graph_a);
    assert!(
        generation_c > generation_a,
        "activating the second leaf tool must move the active pointer"
    );
    assert_eq!(current_generation(&cycle.config, &cycle.db), generation_c);

    let persistence = cycle.state.persistence().unwrap();
    let record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.clone(),
                run_id: run_a.clone(),
            },
            call_id: "read-leaf-a".into(),
        })
        .unwrap()
        .expect("durable read receipt");
    let head = persistence
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    let expected_source = json!({
        "store_id": head.store_id,
        "workspace_id": head.workspace_id,
        "branch_id": head.branch_id,
        "epoch": head.epoch,
        "head_object_id": head.head_object_id,
        "head_version": head.head_version
    });

    let restored_provider = Arc::new(ScriptedProvider::new());
    restored_provider.push_ok(tool_call("read-restored", "read_file", "note.txt"));
    restored_provider.push_ok(stop_turn("done-restored"));
    cycle
        .state
        .service()
        .inject_provider_host(restored_provider);
    let (status, restored) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/restore"),
            json!({
                "workspace_id": workspace_id,
                "source_branch_id": source_branch,
                "checkpoint_id": checkpoint_id,
                "expected_source": expected_source,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "input": {"text": "read frozen leaf note"},
                "cancel_active_source": true,
                "graph_selection": "checkpoint_exact"
            }),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &restored));
    assert_eq!(restored["disposition"], "restored_and_admitted");
    assert_eq!(restored["graph"]["graph_id"], graph_a);
    assert_eq!(
        restored["graph"]["captured_activation_generation"],
        generation_a
    );
    assert_eq!(restored["publication"], "managed_only");
    assert_ne!(
        restored["new_branch"]["branch_id"], source_branch,
        "restore must land on a new branch"
    );
    let new_run = restored["new_run_id"].as_str().unwrap().to_string();
    let new_session = restored["new_session_id"].as_str().unwrap().to_string();
    assert_ne!(new_run, run_a);
    assert_closed(&restored, &cycle.token, &hidden);
    wait_until(|| {
        event_names(&cycle.state, &new_run)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;
    let restored_projection = projected_run(&http, &cycle.token, &new_session, &new_run).await;
    assert!(
        restored_projection.contains("libA:hello"),
        "restored run must read the frozen checkpoint bytes: {restored_projection}"
    );
    assert!(
        !restored_projection.contains("changed-after-checkpoint"),
        "restored run must not see post-checkpoint workspace bytes: {restored_projection}"
    );
    let pinned = pin_for_run(&cycle.config, &cycle.db, &new_run);
    assert_eq!(pinned["graph_id"], graph_a);
    assert_eq!(
        pinned["generation"], generation_a,
        "restored run must pin the checkpoint-captured generation, not the active graph"
    );
    assert_ne!(
        pinned["generation"], generation_c,
        "pinned generation must differ from the moved active pointer"
    );
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pure_leaf_checkpoint_restore_rejects_foreign_token_without_admission() {
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rustscript_agent::plugins::{
        InstallAuthorization, PackageStore, PublisherKey, trusted_tool_package_root,
    };
    use rustscript_agent::{
        AgentGatewayConfig, AgentGatewayState,
        config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
        effects::ResourceQuota,
    };
    use std::path::PathBuf;

    const LEAF_ID: &str = "org.rustscript.lib.phasetext";
    const TOOL_A_ID: &str = "org.rustscript.tools.phasea";
    let leaf_manifest = format!(
        "format: rustscript.plugin/v1\nid: {LEAF_ID}\nversion: 1.0.0\nkind: library\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.library/v1\nhost_abi: agent.cap/v1\nentry:\n  path: format.rss\n  export: format\ndependencies: []\ncapabilities: []\neffects:\n  contract: agent.effects/v1\n  entries:\n    format:\n      direct: []\n      delegated: []\n"
    );
    let tool_manifest = |id: &str| {
        format!(
            "format: rustscript.plugin/v1\nid: {id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: text\n    id: {LEAF_ID}\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
        )
    };
    let run_source = r#"use bytes;
use text::{format};
fn map_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}

fn map_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}

fn map_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}

fn map_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}

pub fn run(context: map) -> map {
    let prepared: map = agent_runtime::tool_prepare(map_map(context, "prepare"));
    if map_string(prepared, "kind", "") == "replay" => {
        map_map(prepared, "result")
    } else if map_bool(prepared, "ok", false) == false => {
        prepared
    } else => {
        let token: string = map_string(prepared, "execution_token", "");
        let arguments: map = map_map(context, "arguments");
        let path: string = map_string(arguments, "path", "");
        let meta: map = cap::fs_metadata(token, path);
        if map_bool(meta, "ok", false) == false => {
            meta
        } else => {
            let file_len: int = map_int(meta, "len", 0);
            let limit: int = file_len;
            let read: map = cap::fs_read_range(token, path, 0, limit);
            if map_bool(read, "ok", false) == false => {
                read
            } else => {
                let payload: bytes = read.bytes;
                let labeled: string = format(bytes::to_utf8(payload));
                let result: map = { ok: true, content: labeled, data: {}, error: null, truncated: false, artifacts: [] };
                let committed: map = agent_runtime::tool_commit(token, result);
                if map_string(committed, "kind", "") == "committed" => {
                    map_map(committed, "result")
                } else => {
                    committed
                }
            }
        }
    }
}
"#;
    struct RestoreCycle {
        workspace: PathBuf,
        source: PathBuf,
        db: PathBuf,
        token: String,
        config: AgentGatewayConfig,
        state: AgentGatewayState,
    }
    let label = format!("t607-leaf-auth-{}", uuid::Uuid::new_v4().simple());
    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap()).join(label);
    let _ = std::fs::remove_dir_all(&root);
    let workspace = root.join("workspace");
    let home = root.join("workspace-home");
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(workspace.join("seed.txt"), b"seed").unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home, &source] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let token = uuid::Uuid::new_v4().to_string();
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.run_timeout = Duration::from_secs(900);
    let db = root.join("gateway.sqlite");
    let cycle = RestoreCycle {
        workspace: workspace.clone(),
        source: source.clone(),
        db: db.clone(),
        token: token.clone(),
        config: config.clone(),
        state: AgentGatewayState::with_sqlite_path(config.clone(), &db)
            .unwrap()
            .with_workspace_home(&home)
            .with_plugin_control(auth.clone(), source, "owner-space")
            .unwrap(),
    };
    let store = PackageStore::open(trusted_tool_package_root(&cycle.db)).unwrap();
    let stage = |dir: &str, manifest: &str, files: &[(&str, &[u8])]| {
        let package = cycle.source.join(dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
        for (name, body) in files {
            std::fs::write(package.join(name), body).unwrap();
        }
        let payload = store.signature_payload(&package).unwrap();
        std::fs::write(
            package.join("signature.ed25519"),
            pair.sign(&payload).as_ref(),
        )
        .unwrap();
        store.install(&package, &auth).unwrap();
    };
    stage(
        "package-phaselib",
        &leaf_manifest,
        &[(
            "format.rss",
            b"pub fn format(value: string) -> string { \"libA:\" + value }\n".as_slice(),
        )],
    );
    stage(
        "package-phasea",
        &tool_manifest(TOOL_A_ID),
        &[
            ("run.rss", run_source.as_bytes()),
            (
                "catalog.rss",
                include_bytes!("../rss/tools/types.rss").as_slice(),
            ),
        ],
    );

    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    let (graph_a, generation_a) =
        activate(&http, &cycle.token, &cycle.config, &cycle.db, TOOL_A_ID).await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    std::fs::write(cycle.workspace.join("note.txt"), b"hello").unwrap();

    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(tool_call("read-leaf-a", "read_file", "note.txt"));
    provider.push_ok(stop_turn("done-a"));
    cycle.state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "read note through the leaf library"}),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph_a);
    assert_eq!(admitted["activation_generation"], generation_a);
    let run_a = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&cycle.state, &run_a)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;
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
    let read = effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == "read-leaf-a")
        .expect("native read receipt through the leaf link")
        .clone();
    let workspace_id = read["workspace_id"].as_str().unwrap().to_string();
    let source_branch = read["branch_id"].as_str().unwrap().to_string();
    let epoch = read["epoch"].as_u64().unwrap();
    assert_closed(&effects, &cycle.token, &hidden);

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
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();

    let persistence = cycle.state.persistence().unwrap();
    let record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.clone(),
                run_id: run_a.clone(),
            },
            call_id: "read-leaf-a".into(),
        })
        .unwrap()
        .expect("durable read receipt");
    let head = persistence
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    let expected_source = json!({
        "store_id": head.store_id,
        "workspace_id": head.workspace_id,
        "branch_id": head.branch_id,
        "epoch": head.epoch,
        "head_object_id": head.head_object_id,
        "head_version": head.head_version
    });

    let generation_before = current_generation(&cycle.config, &cycle.db);
    assert_eq!(generation_before, generation_a);
    let (status, sessions_before) = http
        .request(
            "GET",
            "/api/sessions",
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &sessions_before));
    let session_count_before = sessions_before["data"].as_array().unwrap().len();

    // Cross-workspace negative control on the same gateway: path carries a
    // workspace id this token does not own while the body still points at
    // the real checkpoint.
    let foreign_workspace_id = uuid::Uuid::new_v4().to_string();
    assert_ne!(foreign_workspace_id, workspace_id);
    let restore_body = json!({
        "workspace_id": workspace_id,
        "source_branch_id": source_branch,
        "checkpoint_id": checkpoint_id,
        "expected_source": expected_source,
        "request_id": uuid::Uuid::new_v4().to_string(),
        "input": {"text": "foreign restore attempt"},
        "cancel_active_source": true,
        "graph_selection": "checkpoint_exact"
    });
    let (status, denied) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{foreign_workspace_id}/restore"),
            restore_body,
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(
        status, 403,
        "cross-workspace restore must be refused: {denied}"
    );
    assert_eq!(denied["error"]["code"], "managed_authority_required");
    assert!(
        denied["new_run_id"].is_null(),
        "refused restore must not admit a run: {denied}"
    );
    assert!(
        denied["disposition"].is_null(),
        "refused restore must carry no disposition: {denied}"
    );
    assert_closed(&denied, &cycle.token, &hidden);
    assert_eq!(
        current_generation(&cycle.config, &cycle.db),
        generation_before,
        "refused restore must not move the active graph"
    );
    let (status, sessions_after) = http
        .request(
            "GET",
            "/api/sessions",
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &sessions_after));
    assert_eq!(
        sessions_after["data"].as_array().unwrap().len(),
        session_count_before,
        "refused restore must not admit a new session/run"
    );
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
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

// S2 commit: one stateless caller plus one already-admitted run-scoped
// schema-1 callee over the real socket. The child writes a single state value
// and reads the same value back inside one parent effect commit. No new effect
// kind, no schema field, no checkpoint protocol: the child state ops ride the
// existing workspace.fs.read / workspace.fs.write allow entries.
#[tokio::test(flavor = "multi_thread")]
async fn stateless_caller_commits_stateful_child_write_and_reads_it_back() {
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rustscript_agent::{
        AgentGatewayConfig, AgentGatewayState,
        config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
        effects::ResourceQuota,
        plugins::{InstallAuthorization, PackageStore, PublisherKey, trusted_tool_package_root},
    };

    const CALLER_ID: &str = "org.rustscript.tools.s2commite2ecaller";
    const CALLEE_ID: &str = "org.rustscript.tools.s2commite2ecallee";
    const CALL_ID: &str = "s2-state-call";
    const S2_VALUE: &str = "s2-state-1";

    const CALLER_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"},offset:{type:"integer",minimum:1},limit:{type:"integer",minimum:1}},required:["path"],additionalProperties:false}"#;
    const CALLEE_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false}"#;

    // The RSS below hardcodes the same "s2-state-1" document value that
    // S2_VALUE asserts on; keep them in sync.
    const S2_CALLER_SOURCE: &str = r#"fn s2c_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s2c_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}
fn s2c_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s2c_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let prepare: map = s2c_map(context, "prepare");
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if s2c_string(prepared, "kind", "") == "replay" => {
        s2c_map(prepared, "result")
    } else => {
        if s2c_bool(prepared, "ok", false) == false => {
            prepared
        } else => {
            let token: string = s2c_string(prepared, "execution_token", "");
            let arguments: map = s2c_map(context, "arguments");
            let path: string = s2c_string(arguments, "path", "");
            let meta: map = cap::fs_metadata(token, path);
            if s2c_bool(meta, "ok", false) == false => {
                meta
            } else => {
                let caller_len: int = s2c_int(meta, "len", 0);
                let canonical: string = json::encode(arguments);
                let child: map = agent_runtime::invoke_pinned_plugin_child({ canonical_arguments: canonical });
                if s2c_bool(child, "ok", false) == false => {
                    let failed: map = { ok: false, content: "", data: {}, error: { code: s2c_string(child, "code", "child_failed"), message: s2c_string(child, "message", "child failed") }, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, failed)
                } else => {
                    let result: map = { ok: true, content: "s2caller:" + s2c_string(child, "canonical_result", ""), data: { caller_len: caller_len }, error: null, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, result)
                }
            }
        }
    }
}
"#;

    const S2_CALLEE_SOURCE: &str = r#"fn s2s_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s2s_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s2s_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let current: map = state::read();
    if s2s_bool(current, "ok", false) == false => {
        current
    } else => {
        let revision: int = s2s_int(current, "revision", 0);
        let document: string = json::encode({ s2: "s2-state-1" });
        let written: map = state::write(revision, document);
        if s2s_bool(written, "ok", false) == false => {
            written
        } else => {
            let reread: map = state::read();
            let written_ok: bool = s2s_bool(written, "ok", false);
            let reread_ok: bool = s2s_bool(reread, "ok", false);
            let written_revision: int = s2s_int(written, "revision", 0);
            let reread_revision: int = s2s_int(reread, "revision", 1);
            let reread_document: string = s2s_string(reread, "document", "");
            let same: bool = written_ok && reread_ok && reread_revision == written_revision && reread_document == document;
            { ok: same, content: "s2:" + document, data: { same: same }, error: null, truncated: false, artifacts: [] }
        }
    }
}
"#;

    fn s2_catalog(tool: &str, schema: &str) -> String {
        // The caller descriptor must echo the admitted host descriptor for
        // read_file exactly: seal_call_policy refuses a captured descriptor
        // that differs from the run's frozen registry snapshot.
        format!(
            "pub fn managed_authority_catalog(context: map) -> map {{\n    {{\n        declarations: [{{ tool_name: \"{tool}\", operation: \"workspace_read\" }}],\n        descriptors: [{{\n            name: \"{tool}\",\n            description: \"Read bounded text from a workspace file\",\n            toolset: \"coding\",\n            risk_class: \"read\",\n            schema: {schema}\n        }}]\n    }}\n}}\n"
        )
    }

    let caller_manifest = format!(
        "format: rustscript.plugin/v1\nid: {CALLER_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: child\n    id: {CALLEE_ID}\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated:\n        - dependency: child\n          entry: run\n          allow:\n            - kind: workspace.fs.read\n              scope: bound_workspace\n              recovery: none\n            - kind: workspace.fs.write\n              scope: bound_workspace\n              recovery: none\n"
    );
    let callee_manifest = format!(
        "format: rustscript.plugin/v1\nid: {CALLEE_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\n  - workspace.write\nstate:\n  scope: run\n  schema: 1\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
    );

    let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("t16-s2commit-{}", uuid::Uuid::new_v4().simple()));
    let _ = std::fs::remove_dir_all(&root);
    let workspace = root.join("workspace");
    let home = root.join("workspace-home");
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(workspace.join("note.txt"), b"s2-note").unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home, &source] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let token = uuid::Uuid::new_v4().to_string();
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.run_timeout = Duration::from_secs(900);
    let db = root.join("gateway.sqlite");
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    let store = PackageStore::open(trusted_tool_package_root(&db)).unwrap();
    for (dir, manifest, run_source, catalog) in [
        (
            "package-s2caller",
            caller_manifest.as_str(),
            S2_CALLER_SOURCE,
            s2_catalog("read_file", CALLER_SCHEMA),
        ),
        (
            "package-s2callee",
            callee_manifest.as_str(),
            S2_CALLEE_SOURCE,
            s2_catalog("read_file", CALLEE_SCHEMA),
        ),
    ] {
        let package = source.join(dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
        std::fs::write(package.join("run.rss"), run_source).unwrap();
        std::fs::write(package.join("catalog.rss"), catalog).unwrap();
        let payload = store.signature_payload(&package).unwrap();
        std::fs::write(
            package.join("signature.ed25519"),
            pair.sign(&payload).as_ref(),
        )
        .unwrap();
        store.install(&package, &auth).unwrap();
    }
    let http = Http::bind(state.clone()).await;
    let hidden = [workspace.as_path(), source.as_path()];
    let (graph, generation) = activate(&http, &token, &config, &db, CALLER_ID).await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();

    let provider = Arc::new(ScriptedProvider::new());
    // Exact declared arguments: derive_child_request validates the original
    // parent object against both the caller and the callee descriptors.
    provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": CALL_ID, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    provider.push_ok(stop_turn("s2-done"));
    state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "commit one stateful child value"}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph);
    assert_eq!(admitted["activation_generation"], generation);
    assert_closed(&admitted, &token, &hidden);
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&state, &run_id).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    assert!(
        event_names(&state, &run_id)
            .iter()
            .any(|name| name == "run.completed"),
        "the S2 run must complete: {:?}",
        state.service().run_events(&run_id)
    );

    // The committed parent result carries the child-written state value.
    let projection = projected_run(&http, &token, &session_id, &run_id).await;
    assert!(
        projection.contains(S2_VALUE),
        "the committed parent must carry the child-written value: {projection}"
    );

    // One parent effect row with the complete delegation proof. The parent
    // writes no tree files, so the operation class stays read-only; the
    // callee root advance below proves the state commit rode the same
    // transaction.
    let persistence = state.persistence().unwrap();
    let record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.clone(),
                run_id: run_id.clone(),
            },
            call_id: CALL_ID.into(),
        })
        .unwrap()
        .expect("the single parent effect row must exist");
    assert_eq!(
        record.state,
        rustscript_agent::effects::ManagedPublicationStatus::ReadOnly
    );
    assert!(
        record.outcome.is_some(),
        "the parent must own a final outcome"
    );
    let delegation = serde_json::to_value(
        record
            .delegation
            .as_ref()
            .expect("delegation proof missing"),
    )
    .unwrap();
    assert_eq!(delegation["phase"], "complete");
    assert_eq!(delegation["proof"]["parent_call_id"], CALL_ID);
    assert_eq!(delegation["proof"]["edge_alias"], "child");
    assert_eq!(delegation["proof"]["callee_code"]["package_id"], CALLEE_ID);

    // The callee run root advanced by exactly one revision and holds the
    // written value: the read-back inside the child matches durable state.
    let state_store = rustscript_agent::plugins::PluginStateStore::open(Arc::clone(&persistence));
    let snapshot = state_store
        .binding(&run_id)
        .unwrap()
        .expect("the callee run binding must exist");
    assert_eq!(snapshot.binding.plugin_id, CALLEE_ID);
    assert_eq!(snapshot.binding.revision, 2, "{snapshot:?}");
    assert_eq!(snapshot.payload.to_json(), json!({"s2": S2_VALUE}));

    http.close().await;
    shutdown_when_idle(&state).await;
}

// S2 checkpoint/restore: the admitted stateless caller plus its run-scoped
// schema-1 callee writes one value, checkpoints with the callee root, restores
// onto a new branch, and the next run reads that same value back from the
// captured root. Existing protocol fields only: no new schema field, no new
// effect kind, no second protocol.
#[tokio::test(flavor = "multi_thread")]
async fn s2_stateful_child_checkpoint_restores_the_same_value_on_a_new_branch() {
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rustscript_agent::{
        AgentGatewayConfig, AgentGatewayState,
        config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
        effects::ResourceQuota,
        plugins::{InstallAuthorization, PackageStore, PublisherKey, trusted_tool_package_root},
    };

    const CALLER_ID: &str = "org.rustscript.tools.s2ckptcaller";
    const CALLEE_ID: &str = "org.rustscript.tools.s2ckptcallee";
    const CALL_ID: &str = "s2-state-call";
    const S2_VALUE: &str = "s2-state-1";

    const CALLER_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"},offset:{type:"integer",minimum:1},limit:{type:"integer",minimum:1}},required:["path"],additionalProperties:false}"#;
    const CALLEE_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false}"#;

    const S2_CALLER_SOURCE: &str = r#"fn s2k_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s2k_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}
fn s2k_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s2k_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let prepare: map = s2k_map(context, "prepare");
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if s2k_string(prepared, "kind", "") == "replay" => {
        s2k_map(prepared, "result")
    } else => {
        if s2k_bool(prepared, "ok", false) == false => {
            prepared
        } else => {
            let token: string = s2k_string(prepared, "execution_token", "");
            let arguments: map = s2k_map(context, "arguments");
            let path: string = s2k_string(arguments, "path", "");
            let meta: map = cap::fs_metadata(token, path);
            if s2k_bool(meta, "ok", false) == false => {
                meta
            } else => {
                let caller_len: int = s2k_int(meta, "len", 0);
                let canonical: string = json::encode(arguments);
                let child: map = agent_runtime::invoke_pinned_plugin_child({ canonical_arguments: canonical });
                if s2k_bool(child, "ok", false) == false => {
                    let failed: map = { ok: false, content: "", data: {}, error: { code: s2k_string(child, "code", "child_failed"), message: s2k_string(child, "message", "child failed") }, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, failed)
                } else => {
                    let result: map = { ok: true, content: "s2caller:" + s2k_string(child, "canonical_result", ""), data: { caller_len: caller_len }, error: null, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, result)
                }
            }
        }
    }
}
"#;

    // The first run seeds the callee root; every later run on a restored
    // binding only reads the captured document back and proves it equals the
    // seeded value.
    const S2_CALLEE_SOURCE: &str = r#"fn s2k_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s2k_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s2k_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let current: map = state::read();
    if s2k_bool(current, "ok", false) == false => {
        current
    } else => {
        let revision: int = s2k_int(current, "revision", 0);
        let prior: string = s2k_string(current, "document", "");
        let expected: string = json::encode({ s2: "s2-state-1" });
        if prior == expected => {
            { ok: true, content: "s2-restored:" + prior, data: { same: true }, error: null, truncated: false, artifacts: [] }
        } else => {
            let written: map = state::write(revision, expected);
            if s2k_bool(written, "ok", false) == false => {
                written
            } else => {
                { ok: true, content: "s2-wrote:" + expected, data: { same: true }, error: null, truncated: false, artifacts: [] }
            }
        }
    }
}
"#;

    fn s2_catalog(tool: &str, schema: &str) -> String {
        format!(
            "pub fn managed_authority_catalog(context: map) -> map {{\n    {{\n        declarations: [{{ tool_name: \"{tool}\", operation: \"workspace_read\" }}],\n        descriptors: [{{\n            name: \"{tool}\",\n            description: \"Read bounded text from a workspace file\",\n            toolset: \"coding\",\n            risk_class: \"read\",\n            schema: {schema}\n        }}]\n    }}\n}}\n"
        )
    }

    let caller_manifest = format!(
        "format: rustscript.plugin/v1\nid: {CALLER_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: child\n    id: {CALLEE_ID}\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated:\n        - dependency: child\n          entry: run\n          allow:\n            - kind: workspace.fs.read\n              scope: bound_workspace\n              recovery: none\n            - kind: workspace.fs.write\n              scope: bound_workspace\n              recovery: none\n"
    );
    let callee_manifest = format!(
        "format: rustscript.plugin/v1\nid: {CALLEE_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\n  - workspace.write\nstate:\n  scope: run\n  schema: 1\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
    );

    let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("t16-s2ckpt-{}", uuid::Uuid::new_v4().simple()));
    let _ = std::fs::remove_dir_all(&root);
    let workspace = root.join("workspace");
    let home = root.join("workspace-home");
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(workspace.join("note.txt"), b"s2-note").unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home, &source] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let token = uuid::Uuid::new_v4().to_string();
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.run_timeout = Duration::from_secs(900);
    let db = root.join("gateway.sqlite");
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    let store = PackageStore::open(trusted_tool_package_root(&db)).unwrap();
    for (dir, manifest, run_source, catalog) in [
        (
            "package-s2ckptcaller",
            caller_manifest.as_str(),
            S2_CALLER_SOURCE,
            s2_catalog("read_file", CALLER_SCHEMA),
        ),
        (
            "package-s2ckptcallee",
            callee_manifest.as_str(),
            S2_CALLEE_SOURCE,
            s2_catalog("read_file", CALLEE_SCHEMA),
        ),
    ] {
        let package = source.join(dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
        std::fs::write(package.join("run.rss"), run_source).unwrap();
        std::fs::write(package.join("catalog.rss"), catalog).unwrap();
        let payload = store.signature_payload(&package).unwrap();
        std::fs::write(
            package.join("signature.ed25519"),
            pair.sign(&payload).as_ref(),
        )
        .unwrap();
        store.install(&package, &auth).unwrap();
    }
    let http = Http::bind(state.clone()).await;
    let hidden = [workspace.as_path(), source.as_path()];
    let (graph, generation) = activate(&http, &token, &config, &db, CALLER_ID).await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();

    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": CALL_ID, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    provider.push_ok(stop_turn("s2-done"));
    state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "commit one stateful child value"}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph);
    assert_eq!(admitted["activation_generation"], generation);
    assert_closed(&admitted, &token, &hidden);
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&state, &run_id).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    let projection = projected_run(&http, &token, &session_id, &run_id).await;
    assert!(
        event_names(&state, &run_id)
            .iter()
            .any(|name| name == "run.completed"),
        "the S2 run must complete: {:?} projection: {}",
        state.service().run_events(&run_id),
        projection
    );
    assert!(
        projection.contains("s2-wrote:") && projection.contains(S2_VALUE),
        "the first run must write the state value: {projection}"
    );

    let persistence = state.persistence().unwrap();
    let record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.clone(),
                run_id: run_id.clone(),
            },
            call_id: CALL_ID.into(),
        })
        .unwrap()
        .expect("the single parent effect row must exist");
    let (status, effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_id}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    let receipt = effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == CALL_ID)
        .expect("parent effect receipt")
        .clone();
    let workspace_id = receipt["workspace_id"].as_str().unwrap().to_string();
    let source_branch = receipt["branch_id"].as_str().unwrap().to_string();
    let epoch = receipt["epoch"].as_u64().unwrap();

    let (status, checkpoint) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_id,
                "workspace_id": workspace_id,
                "source_branch_id": source_branch,
                "expected_epoch": epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &checkpoint));
    assert_eq!(checkpoint["checkpoint"]["graph"]["graph_id"], graph);
    assert_eq!(
        checkpoint["checkpoint"]["graph"]["captured_activation_generation"],
        generation
    );
    let coverage = &checkpoint["checkpoint"]["plugin_state"];
    assert_eq!(
        coverage["kind"], "stateful",
        "the admitted S2 graph checkpoints as a stateful graph: {coverage}"
    );
    assert_eq!(
        coverage["package_id"], CALLEE_ID,
        "the covered state owner is the locked callee, not the caller: {coverage}"
    );
    let roots = coverage["roots"].as_array().unwrap();
    assert_eq!(
        roots.len(),
        1,
        "exactly one run-scoped callee root: {coverage}"
    );
    assert_eq!(roots[0]["owner_kind"], "run");
    assert_eq!(roots[0]["package_id"], CALLEE_ID);
    assert!(
        roots[0]["revision"].as_u64().unwrap() >= 1,
        "a written root always has a revision: {}",
        roots[0]
    );
    let checkpoint_root = roots[0]["immutable_root_id"].as_str().unwrap().to_string();
    assert!(!checkpoint_root.is_empty());
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_closed(&checkpoint, &token, &hidden);

    let head = persistence
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    let expected_source = json!({
        "store_id": head.store_id,
        "workspace_id": head.workspace_id,
        "branch_id": head.branch_id,
        "epoch": head.epoch,
        "head_object_id": head.head_object_id,
        "head_version": head.head_version
    });

    let restored_provider = Arc::new(ScriptedProvider::new());
    restored_provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": "read-restored", "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    restored_provider.push_ok(stop_turn("s2-restored-done"));
    state.service().inject_provider_host(restored_provider);
    let (status, restored) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/restore"),
            json!({
                "workspace_id": workspace_id,
                "source_branch_id": source_branch,
                "checkpoint_id": checkpoint_id,
                "expected_source": expected_source,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "input": {"text": "read the checkpointed callee value"},
                "cancel_active_source": true,
                "graph_selection": "checkpoint_exact"
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &restored));
    assert_eq!(restored["disposition"], "restored_and_admitted");
    assert_eq!(restored["graph"]["graph_id"], graph);
    assert_ne!(
        restored["new_branch"]["branch_id"], source_branch,
        "restore must land on a new branch"
    );
    let new_run = restored["new_run_id"].as_str().unwrap().to_string();
    let new_session = restored["new_session_id"].as_str().unwrap().to_string();
    assert_ne!(new_run, run_id);
    assert_closed(&restored, &token, &hidden);
    wait_until(|| {
        event_names(&state, &new_run).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    assert!(
        event_names(&state, &new_run)
            .iter()
            .any(|name| name == "run.completed"),
        "the restored run must complete: {:?}",
        state.service().run_events(&new_run)
    );
    let restored_projection = projected_run(&http, &token, &new_session, &new_run).await;
    assert!(
        restored_projection.contains("s2-restored:") && restored_projection.contains(S2_VALUE),
        "the restored run must read the same value back: {restored_projection}"
    );
    assert!(
        !restored_projection.contains("s2-wrote:"),
        "the restored run must read the captured root, not write a new value: {restored_projection}"
    );
    let state_store = rustscript_agent::plugins::PluginStateStore::open(Arc::clone(&persistence));
    let snapshot = state_store
        .binding(&new_run)
        .unwrap()
        .expect("the restored run must carry the callee run binding");
    assert_eq!(snapshot.binding.plugin_id, CALLEE_ID);
    assert_eq!(
        snapshot.binding.object_id, checkpoint_root,
        "the restored binding must reference the checkpointed immutable root"
    );
    assert_eq!(snapshot.payload.to_json(), json!({"s2": S2_VALUE}));
    let pinned = pin_for_run(&config, &db, &new_run);
    assert_eq!(pinned["graph_id"], graph);
    assert_eq!(pinned["generation"], generation);

    http.close().await;
    shutdown_when_idle(&state).await;
}

// S1 checkpoint/restore over the real socket: one stateless caller plus its
// locked stateless callee. The checkpoint re-proves the captured read link,
// restores onto a new branch, and a new run re-executes the captured callee
// against the checkpoint's immutable tree while a different S1 pair is active.
#[tokio::test(flavor = "multi_thread")]
async fn s1_stateless_child_checkpoint_restores_captured_read_on_a_new_branch() {
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rustscript_agent::{
        AgentGatewayConfig, AgentGatewayState,
        config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
        effects::ResourceQuota,
        plugins::{InstallAuthorization, PackageStore, PublisherKey, trusted_tool_package_root},
    };
    use std::path::PathBuf;

    const CALLER_A_ID: &str = "org.rustscript.tools.s1ckptcaller";
    const CALLEE_A_ID: &str = "org.rustscript.tools.s1ckptcallee";
    const CALLER_B_ID: &str = "org.rustscript.tools.s1ckptcallerb";
    const CALLEE_B_ID: &str = "org.rustscript.tools.s1ckptcalleeb";
    const CALL_A: &str = "read-s1-a";
    const CALL_RESTORED: &str = "read-s1-restored";
    const NOTE: &str = "s1-note";

    const CALLER_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"},offset:{type:"integer",minimum:1},limit:{type:"integer",minimum:1}},required:["path"],additionalProperties:false}"#;
    const CALLEE_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false}"#;

    const CALLER_SOURCE: &str = r#"fn s1_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s1_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}
fn s1_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s1_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let prepare: map = s1_map(context, "prepare");
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if s1_string(prepared, "kind", "") == "replay" => {
        s1_map(prepared, "result")
    } else => {
        if s1_bool(prepared, "ok", false) == false => {
            prepared
        } else => {
            let token: string = s1_string(prepared, "execution_token", "");
            let arguments: map = s1_map(context, "arguments");
            let path: string = s1_string(arguments, "path", "");
            let meta: map = cap::fs_metadata(token, path);
            if s1_bool(meta, "ok", false) == false => {
                meta
            } else => {
                let caller_len: int = s1_int(meta, "len", 0);
                let canonical: string = json::encode(arguments);
                let child: map = agent_runtime::invoke_pinned_plugin_child({ canonical_arguments: canonical });
                if s1_bool(child, "ok", false) == false => {
                    let failed: map = { ok: false, content: "", data: {}, error: { code: s1_string(child, "code", "child_failed"), message: s1_string(child, "message", "child failed") }, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, failed)
                } else => {
                    let result: map = { ok: true, content: "s1caller:" + s1_string(child, "canonical_result", ""), data: { caller_len: caller_len }, error: null, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, result)
                }
            }
        }
    }
}
"#;

    fn s1_callee_source(tag: &str) -> String {
        format!(
            r#"fn s1_string(value: map, key: string, fallback: string) -> string {{
    let mut result: string = fallback;
    if value.has(key) {{
        if type(value[key]) == "string" {{
            let coerced: string = value[key];
            result = coerced;
        }}
    }}
    result
}}
fn s1_map(value: map, key: string) -> map {{
    let mut result: map = {{}};
    if value.has(key) {{
        if type(value[key]) == "map" {{
            let coerced: map = value[key];
            result = coerced;
        }}
    }}
    result
}}
fn s1_int(value: map, key: string, fallback: int) -> int {{
    let mut result: int = fallback;
    if value.has(key) {{
        if type(value[key]) == "int" {{
            let coerced: int = value[key];
            result = coerced;
        }}
    }}
    result
}}
fn s1_bool(value: map, key: string, fallback: bool) -> bool {{
    let mut result: bool = fallback;
    if value.has(key) {{
        if type(value[key]) == "bool" {{
            let coerced: bool = value[key];
            result = coerced;
        }}
    }}
    result
}}
pub fn run(context: map) -> map {{
    let arguments: map = s1_map(context, "arguments");
    let path: string = s1_string(arguments, "path", "");
    let meta: map = cap::fs_metadata("", path);
    if s1_bool(meta, "ok", false) == false => {{
        meta
    }} else => {{
        let len: int = s1_int(meta, "len", 0);
        let read: map = cap::fs_read_range("", path, 0, len);
        if s1_bool(read, "ok", false) == false => {{
            read
        }} else => {{
            let text: string = bytes::to_utf8(read.bytes);
            {{ ok: true, content: text, data: {{ callee: true, ctag: "{tag}" }}, error: null, truncated: false, artifacts: [] }}
        }}
    }}
}}
"#
        )
    }

    fn s1_catalog(tool: &str, schema: &str) -> String {
        format!(
            "pub fn managed_authority_catalog(context: map) -> map {{\n    {{\n        declarations: [{{ tool_name: \"{tool}\", operation: \"workspace_read\" }}],\n        descriptors: [{{\n            name: \"{tool}\",\n            description: \"Read bounded text from a workspace file\",\n            toolset: \"coding\",\n            risk_class: \"read\",\n            schema: {schema}\n        }}]\n    }}\n}}\n"
        )
    }

    fn s1_caller_manifest(id: &str, callee: &str) -> String {
        format!(
            "format: rustscript.plugin/v1\nid: {id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: child\n    id: {callee}\n    version: 1.0.0\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated:\n        - dependency: child\n          entry: run\n          allow:\n            - kind: workspace.fs.read\n              scope: bound_workspace\n              recovery: none\n"
        )
    }

    fn s1_callee_manifest(id: &str) -> String {
        format!(
            "format: rustscript.plugin/v1\nid: {id}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
        )
    }

    let root = PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("t16-s1ckpt-{}", uuid::Uuid::new_v4().simple()));
    let _ = std::fs::remove_dir_all(&root);
    let workspace = root.join("workspace");
    let home = root.join("workspace-home");
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(workspace.join("note.txt"), NOTE.as_bytes()).unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home, &source] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let token = uuid::Uuid::new_v4().to_string();
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.run_timeout = Duration::from_secs(900);
    let db = root.join("gateway.sqlite");
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    let store = PackageStore::open(trusted_tool_package_root(&db)).unwrap();
    let stage = |dir: &str, manifest: &str, run_source: &str, catalog: &str| {
        let package = source.join(dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
        std::fs::write(package.join("run.rss"), run_source).unwrap();
        std::fs::write(package.join("catalog.rss"), catalog).unwrap();
        let payload = store.signature_payload(&package).unwrap();
        std::fs::write(
            package.join("signature.ed25519"),
            pair.sign(&payload).as_ref(),
        )
        .unwrap();
        store.install(&package, &auth).unwrap();
    };
    stage(
        "package-s1callera",
        &s1_caller_manifest(CALLER_A_ID, CALLEE_A_ID),
        CALLER_SOURCE,
        &s1_catalog("read_file", CALLER_SCHEMA),
    );
    stage(
        "package-s1calleea",
        &s1_callee_manifest(CALLEE_A_ID),
        &s1_callee_source("A-captured"),
        &s1_catalog("read_file", CALLEE_SCHEMA),
    );
    stage(
        "package-s1callerb",
        &s1_caller_manifest(CALLER_B_ID, CALLEE_B_ID),
        CALLER_SOURCE,
        &s1_catalog("read_file", CALLER_SCHEMA),
    );
    stage(
        "package-s1calleeb",
        &s1_callee_manifest(CALLEE_B_ID),
        &s1_callee_source("B-active"),
        &s1_catalog("read_file", CALLEE_SCHEMA),
    );

    let http = Http::bind(state.clone()).await;
    let hidden = [workspace.as_path(), source.as_path()];
    let (graph_a, generation_a) = activate(&http, &token, &config, &db, CALLER_A_ID).await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();

    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": CALL_A, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    provider.push_ok(stop_turn("s1-done"));
    state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "read through the captured stateless child"}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph_a);
    assert_eq!(admitted["activation_generation"], generation_a);
    let run_a = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&state, &run_a).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    assert!(
        event_names(&state, &run_a)
            .iter()
            .any(|name| name == "run.completed"),
        "the admitted S1 run must complete: {:?}",
        state.service().run_events(&run_a)
    );
    let projection = projected_run(&http, &token, &session_id, &run_a).await;
    assert!(
        projection.contains("s1caller:")
            && projection.contains(NOTE)
            && projection.contains("A-captured"),
        "the admitted S1 run must perform the captured read: {projection}"
    );
    let (status, effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_a}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    let read = effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == CALL_A)
        .expect("native read receipt through the S1 link")
        .clone();
    assert_eq!(read["state"], "read_only");
    let workspace_id = read["workspace_id"].as_str().unwrap().to_string();
    let source_branch = read["branch_id"].as_str().unwrap().to_string();
    let epoch = read["epoch"].as_u64().unwrap();
    assert_closed(&effects, &token, &hidden);

    let (status, history_before) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &history_before));
    let history_before = history_before["data"].clone();

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
            Some(&token),
            None,
        )
        .await;
    assert_eq!(
        201,
        status,
        "the admitted S1 link must checkpoint as a stateless inventory: {}",
        explain(status, &checkpoint)
    );
    assert_eq!(checkpoint["checkpoint"]["graph"]["graph_id"], graph_a);
    assert_eq!(
        checkpoint["checkpoint"]["graph"]["captured_activation_generation"],
        generation_a
    );
    assert_eq!(checkpoint["checkpoint"]["graph"]["package_id"], CALLER_A_ID);
    let coverage = &checkpoint["checkpoint"]["plugin_state"];
    assert_eq!(
        coverage["kind"], "stateless_builtin",
        "S1 has no state root and keeps the stateless inventory: {coverage}"
    );
    assert_eq!(coverage["package_id"], CALLER_A_ID);
    assert!(coverage["manifest_state_absent"].as_bool().unwrap());
    assert!(coverage["state_effects_absent"].as_bool().unwrap());
    assert_eq!(coverage["roots"], json!([]));
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_closed(&checkpoint, &token, &hidden);

    // The live source bytes move and a different S1 pair becomes active; the
    // restored read must still come from the checkpoint's immutable tree and
    // the captured callee.
    std::fs::write(workspace.join("note.txt"), b"s1-changed-after-checkpoint").unwrap();
    let (graph_b, generation_b) = activate(&http, &token, &config, &db, CALLER_B_ID).await;
    assert_ne!(graph_b, graph_a);
    assert!(generation_b > generation_a);

    let persistence = state.persistence().unwrap();
    let record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.clone(),
                run_id: run_a.clone(),
            },
            call_id: CALL_A.into(),
        })
        .unwrap()
        .expect("durable read receipt");
    let head = persistence
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    let expected_source = json!({
        "store_id": head.store_id,
        "workspace_id": head.workspace_id,
        "branch_id": head.branch_id,
        "epoch": head.epoch,
        "head_object_id": head.head_object_id,
        "head_version": head.head_version
    });
    let restored_provider = Arc::new(ScriptedProvider::new());
    restored_provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": CALL_RESTORED, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    restored_provider.push_ok(stop_turn("s1-restored-done"));
    state.service().inject_provider_host(restored_provider);
    let (status, restored) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/restore"),
            json!({
                "workspace_id": workspace_id,
                "source_branch_id": source_branch,
                "checkpoint_id": checkpoint_id,
                "expected_source": expected_source.clone(),
                "request_id": uuid::Uuid::new_v4().to_string(),
                "input": {"text": "read the checkpointed stateless child"},
                "cancel_active_source": true,
                "graph_selection": "checkpoint_exact"
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(
        202,
        status,
        "the captured S1 link must restore: {}",
        explain(status, &restored)
    );
    assert_eq!(restored["disposition"], "restored_and_admitted");
    assert_eq!(restored["graph"]["graph_id"], graph_a);
    assert_eq!(
        restored["graph"]["captured_activation_generation"],
        generation_a
    );
    assert_eq!(
        restored["graph"]["package_id"], CALLER_A_ID,
        "restore keeps the captured caller identity"
    );
    assert_ne!(
        restored["new_branch"]["branch_id"], source_branch,
        "restore must land on a new branch"
    );
    assert_eq!(
        restored["new_branch"]["head_object_id"],
        checkpoint["checkpoint"]["frozen_root"]["object_id"],
        "the new branch starts at the checkpoint's immutable root"
    );
    let new_run = restored["new_run_id"].as_str().unwrap().to_string();
    let new_session = restored["new_session_id"].as_str().unwrap().to_string();
    assert_ne!(new_run, run_a);
    assert_closed(&restored, &token, &hidden);
    wait_until(|| {
        event_names(&state, &new_run).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    assert!(
        event_names(&state, &new_run)
            .iter()
            .any(|name| name == "run.completed"),
        "the restored S1 run must complete: {:?}",
        state.service().run_events(&new_run)
    );
    let restored_projection = projected_run(&http, &token, &new_session, &new_run).await;
    assert!(
        restored_projection.contains("s1caller:")
            && restored_projection.contains(NOTE)
            && restored_projection.contains("A-captured"),
        "the restored run must re-execute the captured callee on the frozen tree: {restored_projection}"
    );
    assert!(
        !restored_projection.contains("s1-changed-after-checkpoint"),
        "the restored run must not read post-checkpoint source bytes: {restored_projection}"
    );
    assert!(
        !restored_projection.contains("B-active"),
        "the restored run must not use the later active S1 callee: {restored_projection}"
    );
    let pinned = pin_for_run(&config, &db, &new_run);
    assert_eq!(pinned["graph_id"], graph_a);
    assert_eq!(pinned["generation"], generation_a);
    assert_ne!(pinned["generation"], generation_b);

    let restored_record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: new_session.clone(),
                run_id: new_run.clone(),
            },
            call_id: CALL_RESTORED.into(),
        })
        .unwrap()
        .expect("the restored child call must own an effect row");
    let delegation = serde_json::to_value(
        restored_record
            .delegation
            .as_ref()
            .expect("delegation proof missing"),
    )
    .unwrap();
    assert_eq!(delegation["phase"], "complete");
    assert_eq!(delegation["proof"]["parent_call_id"], CALL_RESTORED);
    assert_eq!(delegation["proof"]["edge_alias"], "child");
    assert_eq!(
        delegation["proof"]["callee_code"]["package_id"],
        CALLEE_A_ID
    );
    assert_eq!(
        restored_record.identity.code.graph_id, graph_a,
        "the restored effect belongs to the captured graph"
    );
    assert_eq!(
        restored_record.identity.code.activation_generation,
        generation_a
    );
    let control = rustscript_agent::plugins::PluginControlStore::new(&persistence);
    let lock = control.load_lock(&graph_a).unwrap().lock;
    let locked_callee = lock
        .packages
        .iter()
        .find(|package| package.id == CALLEE_A_ID)
        .expect("the retained lock names its captured callee");
    assert_eq!(
        delegation["proof"]["callee_code"]["artifact_id"], locked_callee.artifact_id,
        "the restored run must call the callee the checkpoint lock captured"
    );

    let (status, restored_messages) = http
        .request(
            "GET",
            &format!("/api/sessions/{new_session}/messages"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &restored_messages));
    let restored_messages = restored_messages["data"].as_array().unwrap();
    let prefix_len = checkpoint["checkpoint"]["history"]["message_count"]
        .as_u64()
        .unwrap() as usize;
    let prefix = &restored_messages[..prefix_len];
    assert!(
        prefix.iter().all(|message| {
            message["metadata"]["origin"]["checkpoint_id"] == json!(checkpoint_id)
        }),
        "every restored prefix row names its checkpoint origin"
    );
    assert!(
        prefix.iter().any(|message| {
            message["tool_call_id"] == json!(CALL_A) && message.to_string().contains(NOTE)
        }),
        "the captured tool result stays in the restored history: {restored_messages:?}"
    );
    let (status, history_after) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &history_after));
    assert_eq!(
        history_after["data"], history_before,
        "restore keeps the source session history read-only"
    );
    let source_metadata = state
        .service()
        .run_context(&run_a)
        .expect("the source run context stays readable")
        .metadata;
    let restored_metadata = state
        .service()
        .run_context(&new_run)
        .expect("the restored run context stays readable")
        .metadata;
    assert_eq!(
        restored_metadata["approval_settings"], source_metadata["approval_settings"],
        "restore keeps the original approval policy"
    );

    http.close().await;
    shutdown_when_idle(&state).await;
}

/// Negative control for the stateful restore path: the same gateway and the
/// same authenticated token ask to restore a real, written stateful child
/// checkpoint through a workspace id the token does not own. The transport
/// path and the body agree on that foreign id, so only the managed authority
/// can refuse; nothing may be admitted and the active graph must not move.
#[tokio::test(flavor = "multi_thread")]
async fn s2_stateful_checkpoint_restore_refuses_a_foreign_workspace() {
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rustscript_agent::{
        AgentGatewayConfig, AgentGatewayState,
        config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
        effects::ResourceQuota,
        plugins::{InstallAuthorization, PackageStore, PublisherKey, trusted_tool_package_root},
    };

    const CALLER_ID: &str = "org.rustscript.tools.s2authcaller";
    const CALLEE_ID: &str = "org.rustscript.tools.s2authcallee";
    const CALL_ID: &str = "s2-auth-call";
    const S2_VALUE: &str = "s2-state-1";

    const CALLER_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"},offset:{type:"integer",minimum:1},limit:{type:"integer",minimum:1}},required:["path"],additionalProperties:false}"#;
    const CALLEE_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false}"#;

    const S2A_CALLER_SOURCE: &str = r#"fn s2a_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s2a_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}
fn s2a_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s2a_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let prepare: map = s2a_map(context, "prepare");
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if s2a_string(prepared, "kind", "") == "replay" => {
        s2a_map(prepared, "result")
    } else => {
        if s2a_bool(prepared, "ok", false) == false => {
            prepared
        } else => {
            let token: string = s2a_string(prepared, "execution_token", "");
            let arguments: map = s2a_map(context, "arguments");
            let path: string = s2a_string(arguments, "path", "");
            let meta: map = cap::fs_metadata(token, path);
            if s2a_bool(meta, "ok", false) == false => {
                meta
            } else => {
                let caller_len: int = s2a_int(meta, "len", 0);
                let canonical: string = json::encode(arguments);
                let child: map = agent_runtime::invoke_pinned_plugin_child({ canonical_arguments: canonical });
                if s2a_bool(child, "ok", false) == false => {
                    let failed: map = { ok: false, content: "", data: {}, error: { code: s2a_string(child, "code", "child_failed"), message: s2a_string(child, "message", "child failed") }, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, failed)
                } else => {
                    let result: map = { ok: true, content: "s2acaller:" + s2a_string(child, "canonical_result", ""), data: { caller_len: caller_len }, error: null, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, result)
                }
            }
        }
    }
}
"#;

    // The callee writes one run-scoped state root on the first run; the
    // checkpoint then captures a root whose revision is at least one.
    const S2A_CALLEE_SOURCE: &str = r#"fn s2a_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s2a_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s2a_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let current: map = state::read();
    if s2a_bool(current, "ok", false) == false => {
        current
    } else => {
        let revision: int = s2a_int(current, "revision", 0);
        let prior: string = s2a_string(current, "document", "");
        let expected: string = json::encode({ s2: "s2-state-1" });
        if prior == expected => {
            { ok: true, content: "s2-restored:" + prior, data: { same: true }, error: null, truncated: false, artifacts: [] }
        } else => {
            let written: map = state::write(revision, expected);
            if s2a_bool(written, "ok", false) == false => {
                written
            } else => {
                { ok: true, content: "s2-wrote:" + expected, data: { same: true }, error: null, truncated: false, artifacts: [] }
            }
        }
    }
}
"#;

    fn s2a_catalog(tool: &str, schema: &str) -> String {
        format!(
            "pub fn managed_authority_catalog(context: map) -> map {{\n    {{\n        declarations: [{{ tool_name: \"{tool}\", operation: \"workspace_read\" }}],\n        descriptors: [{{\n            name: \"{tool}\",\n            description: \"Read bounded text from a workspace file\",\n            toolset: \"coding\",\n            risk_class: \"read\",\n            schema: {schema}\n        }}]\n    }}\n}}\n"
        )
    }

    let caller_manifest = format!(
        "format: rustscript.plugin/v1\nid: {CALLER_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: child\n    id: {CALLEE_ID}\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated:\n        - dependency: child\n          entry: run\n          allow:\n            - kind: workspace.fs.read\n              scope: bound_workspace\n              recovery: none\n            - kind: workspace.fs.write\n              scope: bound_workspace\n              recovery: none\n"
    );
    let callee_manifest = format!(
        "format: rustscript.plugin/v1\nid: {CALLEE_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\n  - workspace.write\nstate:\n  scope: run\n  schema: 1\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
    );

    let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("t16-s2auth-{}", uuid::Uuid::new_v4().simple()));
    let _ = std::fs::remove_dir_all(&root);
    let workspace = root.join("workspace");
    let home = root.join("workspace-home");
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(workspace.join("note.txt"), b"s2-auth-note").unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home, &source] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let token = uuid::Uuid::new_v4().to_string();
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.run_timeout = Duration::from_secs(900);
    let db = root.join("gateway.sqlite");
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    let store = PackageStore::open(trusted_tool_package_root(&db)).unwrap();
    for (dir, manifest, run_source, catalog) in [
        (
            "package-s2authcaller",
            caller_manifest.as_str(),
            S2A_CALLER_SOURCE,
            s2a_catalog("read_file", CALLER_SCHEMA),
        ),
        (
            "package-s2authcallee",
            callee_manifest.as_str(),
            S2A_CALLEE_SOURCE,
            s2a_catalog("read_file", CALLEE_SCHEMA),
        ),
    ] {
        let package = source.join(dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
        std::fs::write(package.join("run.rss"), run_source).unwrap();
        std::fs::write(package.join("catalog.rss"), catalog).unwrap();
        let payload = store.signature_payload(&package).unwrap();
        std::fs::write(
            package.join("signature.ed25519"),
            pair.sign(&payload).as_ref(),
        )
        .unwrap();
        store.install(&package, &auth).unwrap();
    }
    let http = Http::bind(state.clone()).await;
    let hidden = [workspace.as_path(), source.as_path()];
    let (graph, generation) = activate(&http, &token, &config, &db, CALLER_ID).await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();

    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": CALL_ID, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    provider.push_ok(stop_turn("s2-auth-done"));
    state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write one stateful child value"}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph);
    assert_eq!(admitted["activation_generation"], generation);
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&state, &run_id).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    let projection = projected_run(&http, &token, &session_id, &run_id).await;
    assert!(
        projection.contains("s2-wrote:") && projection.contains(S2_VALUE),
        "the seeding run must write the state value: {projection}"
    );

    let persistence = state.persistence().unwrap();
    let record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.clone(),
                run_id: run_id.clone(),
            },
            call_id: CALL_ID.into(),
        })
        .unwrap()
        .expect("the single parent effect row must exist");
    let (status, effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_id}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    let receipt = effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == CALL_ID)
        .expect("parent effect receipt")
        .clone();
    let workspace_id = receipt["workspace_id"].as_str().unwrap().to_string();
    let source_branch = receipt["branch_id"].as_str().unwrap().to_string();
    let epoch = receipt["epoch"].as_u64().unwrap();

    let (status, checkpoint) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_id,
                "workspace_id": workspace_id,
                "source_branch_id": source_branch,
                "expected_epoch": epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &checkpoint));
    let coverage = &checkpoint["checkpoint"]["plugin_state"];
    assert_eq!(
        coverage["kind"], "stateful",
        "the negative control needs a real stateful checkpoint: {coverage}"
    );
    assert_eq!(coverage["package_id"], CALLEE_ID);
    let roots = coverage["roots"].as_array().unwrap();
    assert_eq!(
        roots.len(),
        1,
        "exactly one run-scoped callee root: {coverage}"
    );
    assert!(
        roots[0]["revision"].as_u64().unwrap() >= 1,
        "the captured stateful root must carry a written revision: {}",
        roots[0]
    );
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_closed(&checkpoint, &token, &hidden);

    let head_before = persistence
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    let head_store = head_before.store_id.clone();
    let head_branch = head_before.branch_id.clone();
    let head_epoch = head_before.epoch;
    let head_object = head_before.head_object_id.clone();
    let head_version = head_before.head_version;
    let generation_before = current_generation(&config, &db);
    let pin_before = pin_for_run(&config, &db, &run_id);
    assert_eq!(pin_before["graph_id"], graph);
    assert_eq!(pin_before["generation"], generation);
    let (status, sessions_before) = http
        .request("GET", "/api/sessions", json!(null), Some(&token), None)
        .await;
    assert_eq!(status, 200, "{}", explain(status, &sessions_before));
    let session_count_before = sessions_before["data"].as_array().unwrap().len();

    // A well-formed workspace id that this token's managed authority never
    // issued. Path and body name it together, so the transport-level
    // path/body equality check cannot be the reason for a refusal; the body
    // still carries the real checkpoint id, source branch, store and head CAS.
    let foreign_workspace_id = format!("ws-{}", uuid::Uuid::new_v4().simple());
    assert_ne!(foreign_workspace_id, workspace_id);
    let (status, denied) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{foreign_workspace_id}/restore"),
            json!({
                "workspace_id": foreign_workspace_id,
                "source_branch_id": source_branch,
                "checkpoint_id": checkpoint_id,
                "expected_source": {
                    "store_id": head_store,
                    "workspace_id": foreign_workspace_id,
                    "branch_id": head_branch,
                    "epoch": head_epoch,
                    "head_object_id": head_object,
                    "head_version": head_version
                },
                "request_id": uuid::Uuid::new_v4().to_string(),
                "input": {"text": "restore a stateful checkpoint through a foreign workspace"},
                "cancel_active_source": true,
                "graph_selection": "checkpoint_exact"
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(
        status,
        403,
        "a foreign workspace id must not reach the stateful checkpoint: {}",
        explain(status, &denied)
    );
    assert_eq!(
        denied["error"]["code"], "managed_authority_required",
        "the refusal must come from managed authority, not from a request-shape check: {denied}"
    );
    assert!(
        denied["new_run_id"].is_null() && denied["disposition"].is_null(),
        "a refused stateful restore must not admit a run: {denied}"
    );
    assert!(
        denied.get("checkpoint").is_none() && denied.get("plugin_state").is_none(),
        "a refused restore must not return checkpoint metadata: {denied}"
    );
    assert_closed(&denied, &token, &hidden);

    assert_eq!(
        current_generation(&config, &db),
        generation_before,
        "a refused stateful restore must not move the active graph"
    );
    let pin_after = pin_for_run(&config, &db, &run_id);
    assert_eq!(pin_after["graph_id"], graph);
    assert_eq!(
        pin_after["generation"], generation,
        "the admitted run must still pin the original generation"
    );
    let head_after = persistence
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    assert_eq!(
        (
            head_after.store_id.as_str(),
            head_after.branch_id.as_str(),
            head_after.epoch,
            head_after.head_object_id.as_str(),
            head_after.head_version
        ),
        (
            head_store.as_str(),
            head_branch.as_str(),
            head_epoch,
            head_object.as_str(),
            head_version
        ),
        "a refused stateful restore must not move the source branch head"
    );
    let (status, sessions_after) = http
        .request("GET", "/api/sessions", json!(null), Some(&token), None)
        .await;
    assert_eq!(status, 200, "{}", explain(status, &sessions_after));
    assert_eq!(
        sessions_after["data"].as_array().unwrap().len(),
        session_count_before,
        "a refused stateful restore must not admit a new session or run"
    );

    http.close().await;
    shutdown_when_idle(&state).await;
}

// Stateful restore fault cut: restore the admitted S2 checkpoint, then cut the
// restored run's first read with the existing AfterIntent fault. The cut must
// not publish, must not leave a committed effect, and must not replace the
// restored root.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn s2_stateful_restore_read_after_intent_cut_keeps_the_restored_root() {
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rustscript_agent::{
        AgentGatewayConfig, AgentGatewayState,
        config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
        effects::{
            ManagedEffectFault, ManagedEffectGetRequest, ManagedOwnerScope,
            ManagedPublicationStatus, ResourceQuota,
        },
        plugins::{
            InstallAuthorization, PackageStore, PluginStateStore, PublisherKey,
            trusted_tool_package_root,
        },
    };

    const CALLER_ID: &str = "org.rustscript.tools.s2cutcaller";
    const CALLEE_ID: &str = "org.rustscript.tools.s2cutcallee";
    const SEED_CALL: &str = "s2-cut-seed";
    const CUT_CALL_ID: &str = "s2-cut-read";
    const S2_VALUE: &str = "s2-state-1";

    const CALLER_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"},offset:{type:"integer",minimum:1},limit:{type:"integer",minimum:1}},required:["path"],additionalProperties:false}"#;
    const CALLEE_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false}"#;

    const S2C_CALLER_SOURCE: &str = r#"fn s2c_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s2c_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}
fn s2c_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s2c_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let prepare: map = s2c_map(context, "prepare");
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if s2c_string(prepared, "kind", "") == "replay" => {
        s2c_map(prepared, "result")
    } else => {
        if s2c_bool(prepared, "ok", false) == false => {
            prepared
        } else => {
            let token: string = s2c_string(prepared, "execution_token", "");
            let arguments: map = s2c_map(context, "arguments");
            let path: string = s2c_string(arguments, "path", "");
            let meta: map = cap::fs_metadata(token, path);
            if s2c_bool(meta, "ok", false) == false => {
                meta
            } else => {
                let caller_len: int = s2c_int(meta, "len", 0);
                let canonical: string = json::encode(arguments);
                let child: map = agent_runtime::invoke_pinned_plugin_child({ canonical_arguments: canonical });
                if s2c_bool(child, "ok", false) == false => {
                    let failed: map = { ok: false, content: "", data: {}, error: { code: s2c_string(child, "code", "child_failed"), message: s2c_string(child, "message", "child failed") }, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, failed)
                } else => {
                    let result: map = { ok: true, content: "s2ccaller:" + s2c_string(child, "canonical_result", ""), data: { caller_len: caller_len }, error: null, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, result)
                }
            }
        }
    }
}
"#;

    // The seed run writes the state value; the restored run only reads the
    // captured document back, so any write on the restored branch would be a
    // replaced root, not a read.
    const S2C_CALLEE_SOURCE: &str = r#"fn s2c_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s2c_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s2c_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let current: map = state::read();
    if s2c_bool(current, "ok", false) == false => {
        current
    } else => {
        let revision: int = s2c_int(current, "revision", 0);
        let prior: string = s2c_string(current, "document", "");
        let expected: string = json::encode({ s2: "s2-state-1" });
        if prior == expected => {
            { ok: true, content: "s2-restored:" + prior, data: { same: true }, error: null, truncated: false, artifacts: [] }
        } else => {
            let written: map = state::write(revision, expected);
            if s2c_bool(written, "ok", false) == false => {
                written
            } else => {
                { ok: true, content: "s2-wrote:" + expected, data: { same: true }, error: null, truncated: false, artifacts: [] }
            }
        }
    }
}
"#;

    fn s2c_catalog(tool: &str, schema: &str) -> String {
        format!(
            "pub fn managed_authority_catalog(context: map) -> map {{\n    {{\n        declarations: [{{ tool_name: \"{tool}\", operation: \"workspace_read\" }}],\n        descriptors: [{{\n            name: \"{tool}\",\n            description: \"Read bounded text from a workspace file\",\n            toolset: \"coding\",\n            risk_class: \"read\",\n            schema: {schema}\n        }}]\n    }}\n}}\n"
        )
    }

    let caller_manifest = format!(
        "format: rustscript.plugin/v1\nid: {CALLER_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: child\n    id: {CALLEE_ID}\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated:\n        - dependency: child\n          entry: run\n          allow:\n            - kind: workspace.fs.read\n              scope: bound_workspace\n              recovery: none\n            - kind: workspace.fs.write\n              scope: bound_workspace\n              recovery: none\n"
    );
    let callee_manifest = format!(
        "format: rustscript.plugin/v1\nid: {CALLEE_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\n  - workspace.write\nstate:\n  scope: run\n  schema: 1\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
    );

    let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("t16-s2cut-{}", uuid::Uuid::new_v4().simple()));
    let _ = std::fs::remove_dir_all(&root);
    let workspace = root.join("workspace");
    let home = root.join("workspace-home");
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(workspace.join("note.txt"), b"s2-cut-note").unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home, &source] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let token = uuid::Uuid::new_v4().to_string();
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.run_timeout = Duration::from_secs(900);
    let db = root.join("gateway.sqlite");
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    let store = PackageStore::open(trusted_tool_package_root(&db)).unwrap();
    for (dir, manifest, run_source, catalog) in [
        (
            "package-s2cutcaller",
            caller_manifest.as_str(),
            S2C_CALLER_SOURCE,
            s2c_catalog("read_file", CALLER_SCHEMA),
        ),
        (
            "package-s2cutcallee",
            callee_manifest.as_str(),
            S2C_CALLEE_SOURCE,
            s2c_catalog("read_file", CALLEE_SCHEMA),
        ),
    ] {
        let package = source.join(dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
        std::fs::write(package.join("run.rss"), run_source).unwrap();
        std::fs::write(package.join("catalog.rss"), catalog).unwrap();
        let payload = store.signature_payload(&package).unwrap();
        std::fs::write(
            package.join("signature.ed25519"),
            pair.sign(&payload).as_ref(),
        )
        .unwrap();
        store.install(&package, &auth).unwrap();
    }
    let http = Http::bind(state.clone()).await;
    let hidden = [workspace.as_path(), source.as_path()];
    let (graph, generation) = activate(&http, &token, &config, &db, CALLER_ID).await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();

    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": SEED_CALL, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    provider.push_ok(stop_turn("s2-cut-seeded"));
    state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "seed one stateful child value"}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph);
    assert_eq!(admitted["activation_generation"], generation);
    assert_closed(&admitted, &token, &hidden);
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&state, &run_id).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    let projection = projected_run(&http, &token, &session_id, &run_id).await;
    assert!(
        event_names(&state, &run_id)
            .iter()
            .any(|name| name == "run.completed"),
        "the seed run must complete: {:?} projection: {}",
        state.service().run_events(&run_id),
        projection
    );
    assert!(
        projection.contains("s2-wrote:") && projection.contains(S2_VALUE),
        "the seed run must write the state value: {projection}"
    );

    let persistence = state.persistence().unwrap();
    let record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.clone(),
                run_id: run_id.clone(),
            },
            call_id: SEED_CALL.into(),
        })
        .unwrap()
        .expect("the seed parent effect row must exist");
    let (status, effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_id}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    let receipt = effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == SEED_CALL)
        .expect("seed parent effect receipt")
        .clone();
    let workspace_id = receipt["workspace_id"].as_str().unwrap().to_string();
    let source_branch = receipt["branch_id"].as_str().unwrap().to_string();
    let epoch = receipt["epoch"].as_u64().unwrap();

    let (status, checkpoint) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_id,
                "workspace_id": workspace_id,
                "source_branch_id": source_branch,
                "expected_epoch": epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &checkpoint));
    let coverage = &checkpoint["checkpoint"]["plugin_state"];
    assert_eq!(
        coverage["kind"], "stateful",
        "the cut needs a real stateful checkpoint: {coverage}"
    );
    assert_eq!(coverage["package_id"], CALLEE_ID);
    let roots = coverage["roots"].as_array().unwrap();
    assert_eq!(
        roots.len(),
        1,
        "exactly one run-scoped callee root: {coverage}"
    );
    assert!(
        roots[0]["revision"].as_u64().unwrap() >= 1,
        "the admitted checkpoint must capture a written revision: {}",
        roots[0]
    );
    let checkpoint_root = roots[0]["immutable_root_id"].as_str().unwrap().to_string();
    assert!(!checkpoint_root.is_empty());
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_closed(&checkpoint, &token, &hidden);

    let head = persistence
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    let expected_source = json!({
        "store_id": head.store_id,
        "workspace_id": head.workspace_id,
        "branch_id": head.branch_id,
        "epoch": head.epoch,
        "head_object_id": head.head_object_id,
        "head_version": head.head_version
    });

    let state_store = PluginStateStore::open(Arc::clone(&persistence));

    // The restored run's first read is paused at the model turn, so the fault
    // is armed only after the restore admission already returned and the
    // restored binding exists — never before the checkpoint was restored.
    let (provider, entered, release) =
        pausing_tool_provider(CUT_CALL_ID, "read_file", json!({"path": "note.txt"}));
    state.service().inject_provider_host(provider);
    let (status, restored) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/restore"),
            json!({
                "workspace_id": workspace_id,
                "source_branch_id": source_branch,
                "checkpoint_id": checkpoint_id,
                "expected_source": expected_source,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "input": {"text": "read the checkpointed callee value"},
                "cancel_active_source": true,
                "graph_selection": "checkpoint_exact"
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &restored));
    assert_eq!(restored["disposition"], "restored_and_admitted");
    assert_eq!(restored["graph"]["graph_id"], graph);
    let new_branch = restored["new_branch"]["branch_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        new_branch, source_branch,
        "restore must land on a new branch"
    );
    let new_run = restored["new_run_id"].as_str().unwrap().to_string();
    let new_session = restored["new_session_id"].as_str().unwrap().to_string();
    assert_ne!(new_run, run_id);
    assert_closed(&restored, &token, &hidden);

    let restored_snapshot = state_store
        .binding(&new_run)
        .unwrap()
        .expect("the restored run must carry the callee run binding");
    assert_eq!(restored_snapshot.binding.plugin_id, CALLEE_ID);
    assert_eq!(
        restored_snapshot.binding.object_id, checkpoint_root,
        "the restored binding must reference the checkpointed immutable root"
    );
    assert_eq!(restored_snapshot.binding.checkpoint_id, checkpoint_id);
    assert_eq!(restored_snapshot.payload.to_json(), json!({"s2": S2_VALUE}));
    let restored_revision = restored_snapshot.binding.revision;

    let mut restored_identity = record.identity.workspace.clone();
    restored_identity.branch_id = new_branch.clone();
    let restored_head_before = persistence
        .managed_workspace_head(&restored_identity)
        .unwrap();

    entered
        .recv_timeout(Duration::from_secs(60))
        .expect("the restored run must reach its first model turn before the read starts");
    state
        .service()
        .inject_managed_effect_fault(ManagedEffectFault::AfterIntent)
        .unwrap();
    release.send(()).unwrap();

    wait_until(|| {
        event_names(&state, &new_run).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    let cut_events = state.service().run_events(&new_run);
    let cut_names = event_names(&state, &new_run);
    assert_eq!(
        cut_names
            .iter()
            .filter(|name| {
                *name == "run.completed" || *name == "run.failed" || *name == "run.cancelled"
            })
            .collect::<Vec<_>>(),
        vec!["run.failed"],
        "the cut restore run must only fail, never complete: {cut_events:?}"
    );
    assert!(
        cut_events.iter().any(|event| {
            event["event"] == "tool.started" && event["data"]["tool_call_id"] == CUT_CALL_ID
        }),
        "AfterIntent still leaves the started read intent: {cut_events:?}"
    );
    assert!(
        !cut_events
            .iter()
            .any(|event| { event["event"] == "tool.completed" || event["event"] == "tool.failed" }),
        "the cut is not a recorded tool terminal: {cut_events:?}"
    );
    assert!(
        !state
            .service()
            .session_messages(&new_session)
            .iter()
            .any(|message| message["tool_call_id"] == CUT_CALL_ID),
        "the cut restore read must not publish a tool result"
    );
    let cut_projection = projected_run(&http, &token, &new_session, &new_run).await;
    assert!(
        !cut_projection.contains("s2-restored:") && !cut_projection.contains(S2_VALUE),
        "the cut must not publish the restored bytes: {cut_projection}"
    );

    let (status, cut_effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{new_run}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &cut_effects));
    let cut_entry = cut_effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == CUT_CALL_ID)
        .expect("the cut read leaves a durable intent");
    assert_ne!(
        cut_entry["state"], "committed",
        "the cut must not leave a committed effect: {cut_entry}"
    );
    assert_eq!(cut_entry["state"], "indeterminate", "{cut_entry}");
    let cut_record = persistence
        .managed_effect_get(&ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: new_session.clone(),
                run_id: new_run.clone(),
            },
            call_id: CUT_CALL_ID.into(),
        })
        .unwrap()
        .expect("durable intent record for the cut read");
    assert!(
        cut_record.prepared.is_none(),
        "AfterIntent precedes native view construction"
    );
    assert!(
        cut_record.outcome.is_none(),
        "the cut must not publish an outcome"
    );
    assert_eq!(cut_record.state, ManagedPublicationStatus::Indeterminate);

    let restored_after = state_store
        .binding(&new_run)
        .unwrap()
        .expect("the restored binding must survive the cut");
    assert_eq!(
        restored_after.binding.object_id, checkpoint_root,
        "the cut must not replace the restored root"
    );
    assert_eq!(
        restored_after.binding.revision, restored_revision,
        "the cut must not advance the restored root revision"
    );
    assert_eq!(restored_after.binding.checkpoint_id, checkpoint_id);
    assert_eq!(
        restored_after.payload.to_json(),
        json!({"s2": S2_VALUE}),
        "the cut must not rewrite the restored document"
    );
    assert_eq!(
        state_store
            .object_payload(&checkpoint_root)
            .unwrap()
            .to_json(),
        json!({"s2": S2_VALUE}),
        "the checkpointed immutable root still holds the captured value"
    );
    let restored_head_after = persistence
        .managed_workspace_head(&restored_identity)
        .unwrap();
    assert_eq!(
        (
            restored_head_after.store_id.as_str(),
            restored_head_after.branch_id.as_str(),
            restored_head_after.epoch,
            restored_head_after.head_object_id.as_str(),
            restored_head_after.head_version
        ),
        (
            restored_head_before.store_id.as_str(),
            restored_head_before.branch_id.as_str(),
            restored_head_before.epoch,
            restored_head_before.head_object_id.as_str(),
            restored_head_before.head_version
        ),
        "the cut must not commit on the restored branch"
    );

    http.close().await;
    shutdown_when_idle(&state).await;
}

// STATEFUL-CUT-FOLLOWUP-625: after an AfterIntent cut on a restored S2 read,
// a later run admitted on the exact restored branch must read back the same
// checkpoint immutable root. Single combination proof: the cut assertions and
// a real follow-up on the same branch, same checkpoint, same root. No second
// restore, no new branch, no rewritten history.
#[tokio::test(flavor = "multi_thread")]
async fn s2_stateful_cut_then_followup_reads_same_checkpoint_root() {
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rustscript_agent::{
        AgentGatewayConfig, AgentGatewayState,
        config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
        effects::{
            ManagedEffectFault, ManagedEffectGetRequest, ManagedOwnerScope,
            ManagedPublicationStatus, ResourceQuota,
        },
        plugins::{
            InstallAuthorization, PackageStore, PluginStateStore, PublisherKey,
            trusted_tool_package_root,
        },
    };

    const CALLER_ID: &str = "org.rustscript.tools.s2cutfocaller";
    const CALLEE_ID: &str = "org.rustscript.tools.s2cutfocallee";
    const SEED_CALL: &str = "s2-cutfo-seed";
    const CUT_CALL_ID: &str = "s2-cutfo-read";
    const FOLLOW_CALL_ID: &str = "s2-cutfo-followup";
    const S2_VALUE: &str = "s2-state-1";

    const CALLER_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"},offset:{type:"integer",minimum:1},limit:{type:"integer",minimum:1}},required:["path"],additionalProperties:false}"#;
    const CALLEE_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false}"#;

    const S2C_CALLER_SOURCE: &str = r#"fn s2c_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s2c_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}
fn s2c_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s2c_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let prepare: map = s2c_map(context, "prepare");
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if s2c_string(prepared, "kind", "") == "replay" => {
        s2c_map(prepared, "result")
    } else => {
        if s2c_bool(prepared, "ok", false) == false => {
            prepared
        } else => {
            let token: string = s2c_string(prepared, "execution_token", "");
            let arguments: map = s2c_map(context, "arguments");
            let path: string = s2c_string(arguments, "path", "");
            let meta: map = cap::fs_metadata(token, path);
            if s2c_bool(meta, "ok", false) == false => {
                meta
            } else => {
                let caller_len: int = s2c_int(meta, "len", 0);
                let canonical: string = json::encode(arguments);
                let child: map = agent_runtime::invoke_pinned_plugin_child({ canonical_arguments: canonical });
                if s2c_bool(child, "ok", false) == false => {
                    let failed: map = { ok: false, content: "", data: {}, error: { code: s2c_string(child, "code", "child_failed"), message: s2c_string(child, "message", "child failed") }, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, failed)
                } else => {
                    let result: map = { ok: true, content: "s2ccaller:" + s2c_string(child, "canonical_result", ""), data: { caller_len: caller_len }, error: null, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, result)
                }
            }
        }
    }
}
"#;

    // The seed run writes the state value; every later run on a restored
    // binding only reads the captured document back, so a write on the
    // restored branch would be a replaced root, not a read.
    const S2C_CALLEE_SOURCE: &str = r#"fn s2c_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s2c_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s2c_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let current: map = state::read();
    if s2c_bool(current, "ok", false) == false => {
        current
    } else => {
        let revision: int = s2c_int(current, "revision", 0);
        let prior: string = s2c_string(current, "document", "");
        let expected: string = json::encode({ s2: "s2-state-1" });
        if prior == expected => {
            { ok: true, content: "s2-restored:" + prior, data: { same: true }, error: null, truncated: false, artifacts: [] }
        } else => {
            let written: map = state::write(revision, expected);
            if s2c_bool(written, "ok", false) == false => {
                written
            } else => {
                { ok: true, content: "s2-wrote:" + expected, data: { same: true }, error: null, truncated: false, artifacts: [] }
            }
        }
    }
}
"#;

    fn s2c_catalog(tool: &str, schema: &str) -> String {
        format!(
            "pub fn managed_authority_catalog(context: map) -> map {{\n    {{\n        declarations: [{{ tool_name: \"{tool}\", operation: \"workspace_read\" }}],\n        descriptors: [{{\n            name: \"{tool}\",\n            description: \"Read bounded text from a workspace file\",\n            toolset: \"coding\",\n            risk_class: \"read\",\n            schema: {schema}\n        }}]\n    }}\n}}\n"
        )
    }

    let caller_manifest = format!(
        "format: rustscript.plugin/v1\nid: {CALLER_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: child\n    id: {CALLEE_ID}\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated:\n        - dependency: child\n          entry: run\n          allow:\n            - kind: workspace.fs.read\n              scope: bound_workspace\n              recovery: none\n            - kind: workspace.fs.write\n              scope: bound_workspace\n              recovery: none\n"
    );
    let callee_manifest = format!(
        "format: rustscript.plugin/v1\nid: {CALLEE_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\n  - workspace.write\nstate:\n  scope: run\n  schema: 1\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
    );

    let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("t16-s2cutfo-{}", uuid::Uuid::new_v4().simple()));
    let _ = std::fs::remove_dir_all(&root);
    let workspace = root.join("workspace");
    let home = root.join("workspace-home");
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(workspace.join("note.txt"), b"s2-cutfo-note").unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home, &source] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let token = uuid::Uuid::new_v4().to_string();
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.run_timeout = Duration::from_secs(900);
    let db = root.join("gateway.sqlite");
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    let store = PackageStore::open(trusted_tool_package_root(&db)).unwrap();
    for (dir, manifest, run_source, catalog) in [
        (
            "package-s2cutfocaller",
            caller_manifest.as_str(),
            S2C_CALLER_SOURCE,
            s2c_catalog("read_file", CALLER_SCHEMA),
        ),
        (
            "package-s2cutfocallee",
            callee_manifest.as_str(),
            S2C_CALLEE_SOURCE,
            s2c_catalog("read_file", CALLEE_SCHEMA),
        ),
    ] {
        let package = source.join(dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
        std::fs::write(package.join("run.rss"), run_source).unwrap();
        std::fs::write(package.join("catalog.rss"), catalog).unwrap();
        let payload = store.signature_payload(&package).unwrap();
        std::fs::write(
            package.join("signature.ed25519"),
            pair.sign(&payload).as_ref(),
        )
        .unwrap();
        store.install(&package, &auth).unwrap();
    }
    let http = Http::bind(state.clone()).await;
    let hidden = [workspace.as_path(), source.as_path()];
    let (graph, generation) = activate(&http, &token, &config, &db, CALLER_ID).await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();

    // S1: seed one stateful child value.
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": SEED_CALL, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    provider.push_ok(stop_turn("s2-cutfo-seeded"));
    state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "seed one stateful child value"}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph);
    assert_eq!(admitted["activation_generation"], generation);
    assert_closed(&admitted, &token, &hidden);
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&state, &run_id).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    let projection = projected_run(&http, &token, &session_id, &run_id).await;
    assert!(
        event_names(&state, &run_id)
            .iter()
            .any(|name| name == "run.completed"),
        "the seed run must complete: {:?} projection: {}",
        state.service().run_events(&run_id),
        projection
    );
    assert!(
        projection.contains("s2-wrote:") && projection.contains(S2_VALUE),
        "the seed run must write the state value: {projection}"
    );

    // S2: checkpoint the stateful value.
    let persistence = state.persistence().unwrap();
    let record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.clone(),
                run_id: run_id.clone(),
            },
            call_id: SEED_CALL.into(),
        })
        .unwrap()
        .expect("the seed parent effect row must exist");
    let (status, effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_id}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    let receipt = effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == SEED_CALL)
        .expect("seed parent effect receipt")
        .clone();
    let workspace_id = receipt["workspace_id"].as_str().unwrap().to_string();
    let source_branch = receipt["branch_id"].as_str().unwrap().to_string();
    let epoch = receipt["epoch"].as_u64().unwrap();

    let (status, checkpoint) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_id,
                "workspace_id": workspace_id,
                "source_branch_id": source_branch,
                "expected_epoch": epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &checkpoint));
    let coverage = &checkpoint["checkpoint"]["plugin_state"];
    assert_eq!(
        coverage["kind"], "stateful",
        "the cut needs a real stateful checkpoint: {coverage}"
    );
    assert_eq!(coverage["package_id"], CALLEE_ID);
    let roots = coverage["roots"].as_array().unwrap();
    assert_eq!(
        roots.len(),
        1,
        "exactly one run-scoped callee root: {coverage}"
    );
    assert!(
        roots[0]["revision"].as_u64().unwrap() >= 1,
        "the admitted checkpoint must capture a written revision: {}",
        roots[0]
    );
    let checkpoint_root = roots[0]["immutable_root_id"].as_str().unwrap().to_string();
    assert!(!checkpoint_root.is_empty());
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_closed(&checkpoint, &token, &hidden);

    let head = persistence
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    let expected_source = json!({
        "store_id": head.store_id,
        "workspace_id": head.workspace_id,
        "branch_id": head.branch_id,
        "epoch": head.epoch,
        "head_object_id": head.head_object_id,
        "head_version": head.head_version
    });

    let state_store = PluginStateStore::open(Arc::clone(&persistence));

    // S3: restore onto a fresh branch, then cut the first read AfterIntent.
    // The fault is armed only after the restore admission already returned
    // and the restored binding exists — never before the checkpoint restore.
    // This is the single fault injection of this test.
    let (provider, entered, release) =
        pausing_tool_provider(CUT_CALL_ID, "read_file", json!({"path": "note.txt"}));
    state.service().inject_provider_host(provider);
    let (status, restored) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/restore"),
            json!({
                "workspace_id": workspace_id,
                "source_branch_id": source_branch,
                "checkpoint_id": checkpoint_id,
                "expected_source": expected_source,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "input": {"text": "read the checkpointed callee value"},
                "cancel_active_source": true,
                "graph_selection": "checkpoint_exact"
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &restored));
    assert_eq!(restored["disposition"], "restored_and_admitted");
    assert_eq!(restored["graph"]["graph_id"], graph);
    let new_branch = restored["new_branch"]["branch_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        new_branch, source_branch,
        "restore must land on a new branch"
    );
    let new_run = restored["new_run_id"].as_str().unwrap().to_string();
    let new_session = restored["new_session_id"].as_str().unwrap().to_string();
    assert_ne!(new_run, run_id);
    assert_closed(&restored, &token, &hidden);

    let restored_snapshot = state_store
        .binding(&new_run)
        .unwrap()
        .expect("the restored run must carry the callee run binding");
    assert_eq!(restored_snapshot.binding.plugin_id, CALLEE_ID);
    assert_eq!(
        restored_snapshot.binding.object_id, checkpoint_root,
        "the restored binding must reference the checkpointed immutable root"
    );
    assert_eq!(restored_snapshot.binding.checkpoint_id, checkpoint_id);
    assert_eq!(restored_snapshot.payload.to_json(), json!({"s2": S2_VALUE}));
    let restored_revision = restored_snapshot.binding.revision;

    let mut restored_identity = record.identity.workspace.clone();
    restored_identity.branch_id = new_branch.clone();
    let restored_head_before = persistence
        .managed_workspace_head(&restored_identity)
        .unwrap();

    entered
        .recv_timeout(Duration::from_secs(60))
        .expect("the restored run must reach its first model turn before the read starts");
    state
        .service()
        .inject_managed_effect_fault(ManagedEffectFault::AfterIntent)
        .unwrap();
    release.send(()).unwrap();

    wait_until(|| {
        event_names(&state, &new_run).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    let cut_events = state.service().run_events(&new_run);
    let cut_names = event_names(&state, &new_run);
    assert_eq!(
        cut_names
            .iter()
            .filter(|name| {
                *name == "run.completed" || *name == "run.failed" || *name == "run.cancelled"
            })
            .collect::<Vec<_>>(),
        vec!["run.failed"],
        "the cut restore run must only fail, never complete: {cut_events:?}"
    );
    assert!(
        cut_events.iter().any(|event| {
            event["event"] == "tool.started" && event["data"]["tool_call_id"] == CUT_CALL_ID
        }),
        "AfterIntent still leaves the started read intent: {cut_events:?}"
    );
    assert!(
        !cut_events
            .iter()
            .any(|event| { event["event"] == "tool.completed" || event["event"] == "tool.failed" }),
        "the cut is not a recorded tool terminal: {cut_events:?}"
    );
    assert!(
        !state
            .service()
            .session_messages(&new_session)
            .iter()
            .any(|message| message["tool_call_id"] == CUT_CALL_ID),
        "the cut restore read must not publish a tool result"
    );
    let cut_projection = projected_run(&http, &token, &new_session, &new_run).await;
    assert!(
        !cut_projection.contains("s2-restored:") && !cut_projection.contains(S2_VALUE),
        "the cut must not publish the restored bytes: {cut_projection}"
    );
    let cut_sse = http.typed_sse(&token, &new_run).await;
    assert_typed_terminal(&cut_sse, "run.failed");

    let (status, cut_effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{new_run}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &cut_effects));
    let cut_entry = cut_effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == CUT_CALL_ID)
        .expect("the cut read leaves a durable intent")
        .clone();
    assert_ne!(
        cut_entry["state"], "committed",
        "the cut must not leave a committed effect: {cut_entry}"
    );
    assert_eq!(cut_entry["state"], "indeterminate", "{cut_entry}");
    let cut_record = persistence
        .managed_effect_get(&ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: new_session.clone(),
                run_id: new_run.clone(),
            },
            call_id: CUT_CALL_ID.into(),
        })
        .unwrap()
        .expect("durable intent record for the cut read");
    assert!(
        cut_record.prepared.is_none(),
        "AfterIntent precedes native view construction"
    );
    assert!(
        cut_record.outcome.is_none(),
        "the cut must not publish an outcome"
    );
    assert_eq!(cut_record.state, ManagedPublicationStatus::Indeterminate);

    let restored_after = state_store
        .binding(&new_run)
        .unwrap()
        .expect("the restored binding must survive the cut");
    assert_eq!(
        restored_after.binding.object_id, checkpoint_root,
        "the cut must not replace the restored root"
    );
    assert_eq!(
        restored_after.binding.revision, restored_revision,
        "the cut must not advance the restored root revision"
    );
    assert_eq!(restored_after.binding.checkpoint_id, checkpoint_id);
    assert_eq!(
        restored_after.payload.to_json(),
        json!({"s2": S2_VALUE}),
        "the cut must not rewrite the restored document"
    );
    assert_eq!(
        state_store
            .object_payload(&checkpoint_root)
            .unwrap()
            .to_json(),
        json!({"s2": S2_VALUE}),
        "the checkpointed immutable root still holds the captured value"
    );
    let restored_head_after = persistence
        .managed_workspace_head(&restored_identity)
        .unwrap();
    assert_eq!(
        (
            restored_head_after.store_id.as_str(),
            restored_head_after.branch_id.as_str(),
            restored_head_after.epoch,
            restored_head_after.head_object_id.as_str(),
            restored_head_after.head_version
        ),
        (
            restored_head_before.store_id.as_str(),
            restored_head_before.branch_id.as_str(),
            restored_head_before.epoch,
            restored_head_before.head_object_id.as_str(),
            restored_head_before.head_version
        ),
        "the cut must not commit on the restored branch"
    );

    // S4: after the cut run terminates, admit a new run on the exact restored
    // branch. No new branch, no second restore, no second fault injection.
    let follow_provider = Arc::new(ScriptedProvider::new());
    follow_provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": FOLLOW_CALL_ID, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    follow_provider.push_ok(stop_turn("s2-cutfo-followup-done"));
    state.service().inject_provider_host(follow_provider);
    let (status, follow) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": new_session,
                "input": "read back the captured callee value on the restored branch",
                "workspace_branch": new_branch
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &follow));
    assert_eq!(follow["graph_id"], graph);
    assert_eq!(follow["activation_generation"], generation);
    assert_eq!(
        follow["workspace_branch"], new_branch,
        "the follow-up run must stay on the exact restored branch"
    );
    assert_closed(&follow, &token, &hidden);
    let follow_id = follow["run_id"].as_str().unwrap().to_string();
    assert_ne!(follow_id, new_run);
    wait_until(|| {
        event_names(&state, &follow_id).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    assert!(
        event_names(&state, &follow_id)
            .iter()
            .any(|name| name == "run.completed"),
        "the follow-up run must complete: {:?}",
        state.service().run_events(&follow_id)
    );
    let follow_sse = http.typed_sse(&token, &follow_id).await;
    assert_typed_terminal(&follow_sse, "run.completed");
    let follow_projection = projected_run(&http, &token, &new_session, &follow_id).await;
    assert!(
        follow_projection.contains("s2-restored:") && follow_projection.contains(S2_VALUE),
        "the follow-up run must read the captured root: {follow_projection}"
    );
    assert!(
        !follow_projection.contains("s2-wrote:"),
        "the follow-up run must not rewrite the captured bytes: {follow_projection}"
    );
    let (status, follow_effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{follow_id}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &follow_effects));
    let follow_entry = follow_effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == FOLLOW_CALL_ID)
        .expect("follow-up parent effect receipt")
        .clone();
    assert_eq!(follow_entry["state"], "read_only", "{follow_entry}");
    assert_eq!(follow_entry["branch_id"], new_branch);
    assert_closed(&follow_effects, &token, &hidden);
    let follow_snapshot = state_store
        .binding(&follow_id)
        .unwrap()
        .expect("the follow-up run must carry the callee run binding");
    assert_eq!(follow_snapshot.binding.plugin_id, CALLEE_ID);
    assert_eq!(
        follow_snapshot.binding.object_id, checkpoint_root,
        "the follow-up binding must reference the checkpointed immutable root"
    );
    assert_eq!(
        follow_snapshot.binding.revision, restored_revision,
        "the follow-up run must not advance the restored root revision"
    );
    assert_eq!(follow_snapshot.binding.checkpoint_id, checkpoint_id);
    assert_eq!(follow_snapshot.payload.to_json(), json!({"s2": S2_VALUE}));
    let (status, follow_messages) = http
        .request(
            "GET",
            &format!("/api/sessions/{new_session}/messages"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &follow_messages));
    let follow_block = typed_tool_block(
        follow_messages["data"]
            .as_array()
            .expect("follow-up messages"),
        FOLLOW_CALL_ID,
    )
    .expect("typed follow-up read result");
    assert_eq!(follow_block["tool_call_id"], FOLLOW_CALL_ID);
    assert_eq!(follow_block["is_error"], false);
    assert!(
        follow_block["content"].as_str().unwrap().contains(S2_VALUE),
        "the follow-up HTTP message must carry the captured value: {follow_block}"
    );
    assert!(
        !follow_block["content"]
            .as_str()
            .unwrap()
            .contains("s2-wrote:"),
        "the follow-up message must not carry a write marker: {follow_block}"
    );
    assert_closed(&follow_messages, &token, &hidden);
    let follow_pin = pin_for_run(&config, &db, &follow_id);
    assert_eq!(follow_pin["graph_id"], graph);
    assert_eq!(follow_pin["generation"], generation);

    // S5: the cut's historical record must stay indeterminate; the successful
    // follow-up must not rewrite it, restore again, or move branches.
    let (status, cut_effects_after) = http
        .request(
            "GET",
            &format!("/v1/runs/{new_run}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &cut_effects_after));
    let cut_entry_after = cut_effects_after["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == CUT_CALL_ID)
        .expect("the cut intent must still be recorded")
        .clone();
    assert_eq!(
        cut_entry_after["state"], "indeterminate",
        "the follow-up must not rewrite the cut intent: {cut_entry_after}"
    );
    let cut_record_after = persistence
        .managed_effect_get(&ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: new_session.clone(),
                run_id: new_run.clone(),
            },
            call_id: CUT_CALL_ID.into(),
        })
        .unwrap()
        .expect("durable intent record for the cut read must survive the follow-up");
    assert!(cut_record_after.prepared.is_none());
    assert!(cut_record_after.outcome.is_none());
    assert_eq!(
        cut_record_after.state,
        ManagedPublicationStatus::Indeterminate
    );
    let restored_final = state_store
        .binding(&new_run)
        .unwrap()
        .expect("the cut run binding must survive the follow-up");
    assert_eq!(
        restored_final.binding.object_id, checkpoint_root,
        "the follow-up must not replace the cut run root"
    );
    assert_eq!(restored_final.binding.checkpoint_id, checkpoint_id);

    http.close().await;
    shutdown_when_idle(&state).await;
}

// STATEFUL-RESTORE-FOLLOWUP: after an admitted S2 checkpoint restore, a later
// run admitted on the restored branch must read the captured root. Existing
// protocol fields only: no new schema field, no new effect kind, no new
// route. A fresh write of the same bytes (s2-wrote:) is a failure, not a
// pass; the follow-up binding object_id must equal the checkpoint immutable
// root.
#[tokio::test(flavor = "multi_thread")]
async fn s2_restored_branch_followup_run_reads_captured_root() {
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rustscript_agent::{
        AgentGatewayConfig, AgentGatewayState,
        config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
        effects::ResourceQuota,
        plugins::{InstallAuthorization, PackageStore, PublisherKey, trusted_tool_package_root},
    };

    const CALLER_ID: &str = "org.rustscript.tools.s2restfocaller";
    const CALLEE_ID: &str = "org.rustscript.tools.s2restfocallee";
    const CALL_ID: &str = "s2-followup-call";
    const S2_VALUE: &str = "s2-state-1";

    const CALLER_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"},offset:{type:"integer",minimum:1},limit:{type:"integer",minimum:1}},required:["path"],additionalProperties:false}"#;
    const CALLEE_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false}"#;

    const S2_CALLER_SOURCE: &str = r#"fn s2f_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s2f_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}
fn s2f_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s2f_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let prepare: map = s2f_map(context, "prepare");
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if s2f_string(prepared, "kind", "") == "replay" => {
        s2f_map(prepared, "result")
    } else => {
        if s2f_bool(prepared, "ok", false) == false => {
            prepared
        } else => {
            let token: string = s2f_string(prepared, "execution_token", "");
            let arguments: map = s2f_map(context, "arguments");
            let path: string = s2f_string(arguments, "path", "");
            let meta: map = cap::fs_metadata(token, path);
            if s2f_bool(meta, "ok", false) == false => {
                meta
            } else => {
                let caller_len: int = s2f_int(meta, "len", 0);
                let canonical: string = json::encode(arguments);
                let child: map = agent_runtime::invoke_pinned_plugin_child({ canonical_arguments: canonical });
                if s2f_bool(child, "ok", false) == false => {
                    let failed: map = { ok: false, content: "", data: {}, error: { code: s2f_string(child, "code", "child_failed"), message: s2f_string(child, "message", "child failed") }, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, failed)
                } else => {
                    let result: map = { ok: true, content: "s2caller:" + s2f_string(child, "canonical_result", ""), data: { caller_len: caller_len }, error: null, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, result)
                }
            }
        }
    }
}
"#;

    // The first run seeds the callee root; every later run on a restored
    // binding only reads the captured document back and proves it equals the
    // seeded value.
    const S2_CALLEE_SOURCE: &str = r#"fn s2f_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s2f_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s2f_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let current: map = state::read();
    if s2f_bool(current, "ok", false) == false => {
        current
    } else => {
        let revision: int = s2f_int(current, "revision", 0);
        let prior: string = s2f_string(current, "document", "");
        let expected: string = json::encode({ s2: "s2-state-1" });
        if prior == expected => {
            { ok: true, content: "s2-restored:" + prior, data: { same: true }, error: null, truncated: false, artifacts: [] }
        } else => {
            let written: map = state::write(revision, expected);
            if s2f_bool(written, "ok", false) == false => {
                written
            } else => {
                { ok: true, content: "s2-wrote:" + expected, data: { same: true }, error: null, truncated: false, artifacts: [] }
            }
        }
    }
}
"#;

    fn s2_catalog(tool: &str, schema: &str) -> String {
        format!(
            "pub fn managed_authority_catalog(context: map) -> map {{\n    {{\n        declarations: [{{ tool_name: \"{tool}\", operation: \"workspace_read\" }}],\n        descriptors: [{{\n            name: \"{tool}\",\n            description: \"Read bounded text from a workspace file\",\n            toolset: \"coding\",\n            risk_class: \"read\",\n            schema: {schema}\n        }}]\n    }}\n}}\n"
        )
    }

    let caller_manifest = format!(
        "format: rustscript.plugin/v1\nid: {CALLER_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: child\n    id: {CALLEE_ID}\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated:\n        - dependency: child\n          entry: run\n          allow:\n            - kind: workspace.fs.read\n              scope: bound_workspace\n              recovery: none\n            - kind: workspace.fs.write\n              scope: bound_workspace\n              recovery: none\n"
    );
    let callee_manifest = format!(
        "format: rustscript.plugin/v1\nid: {CALLEE_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\n  - workspace.write\nstate:\n  scope: run\n  schema: 1\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
    );

    let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("t16-s2restfo-{}", uuid::Uuid::new_v4().simple()));
    let _ = std::fs::remove_dir_all(&root);
    let workspace = root.join("workspace");
    let home = root.join("workspace-home");
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(workspace.join("note.txt"), b"s2-note").unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home, &source] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let token = uuid::Uuid::new_v4().to_string();
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.run_timeout = Duration::from_secs(900);
    let db = root.join("gateway.sqlite");
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    let store = PackageStore::open(trusted_tool_package_root(&db)).unwrap();
    for (dir, manifest, run_source, catalog) in [
        (
            "package-s2restfocaller",
            caller_manifest.as_str(),
            S2_CALLER_SOURCE,
            s2_catalog("read_file", CALLER_SCHEMA),
        ),
        (
            "package-s2restfocallee",
            callee_manifest.as_str(),
            S2_CALLEE_SOURCE,
            s2_catalog("read_file", CALLEE_SCHEMA),
        ),
    ] {
        let package = source.join(dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
        std::fs::write(package.join("run.rss"), run_source).unwrap();
        std::fs::write(package.join("catalog.rss"), catalog).unwrap();
        let payload = store.signature_payload(&package).unwrap();
        std::fs::write(
            package.join("signature.ed25519"),
            pair.sign(&payload).as_ref(),
        )
        .unwrap();
        store.install(&package, &auth).unwrap();
    }
    let http = Http::bind(state.clone()).await;
    let hidden = [workspace.as_path(), source.as_path()];
    let (graph, generation) = activate(&http, &token, &config, &db, CALLER_ID).await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();

    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": CALL_ID, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    provider.push_ok(stop_turn("s2-done"));
    state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "seed the stateful child value"}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    assert_eq!(admitted["graph_id"], graph);
    assert_eq!(admitted["activation_generation"], generation);
    assert_closed(&admitted, &token, &hidden);
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&state, &run_id).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    let projection = projected_run(&http, &token, &session_id, &run_id).await;
    assert!(
        event_names(&state, &run_id)
            .iter()
            .any(|name| name == "run.completed"),
        "the S2 run must complete: {:?} projection: {}",
        state.service().run_events(&run_id),
        projection
    );
    assert!(
        projection.contains("s2-wrote:") && projection.contains(S2_VALUE),
        "the first run must write the state value: {projection}"
    );

    let persistence = state.persistence().unwrap();
    let record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.clone(),
                run_id: run_id.clone(),
            },
            call_id: CALL_ID.into(),
        })
        .unwrap()
        .expect("the single parent effect row must exist");
    let (status, effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_id}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects));
    let receipt = effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == CALL_ID)
        .expect("parent effect receipt")
        .clone();
    let workspace_id = receipt["workspace_id"].as_str().unwrap().to_string();
    let source_branch = receipt["branch_id"].as_str().unwrap().to_string();
    let epoch = receipt["epoch"].as_u64().unwrap();

    let (status, checkpoint) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            json!({
                "source_run_id": run_id,
                "workspace_id": workspace_id,
                "source_branch_id": source_branch,
                "expected_epoch": epoch,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &checkpoint));
    assert_eq!(checkpoint["checkpoint"]["graph"]["graph_id"], graph);
    let coverage = &checkpoint["checkpoint"]["plugin_state"];
    assert_eq!(
        coverage["kind"], "stateful",
        "the admitted S2 graph checkpoints as a stateful graph: {coverage}"
    );
    let roots = coverage["roots"].as_array().unwrap();
    assert_eq!(
        roots.len(),
        1,
        "exactly one run-scoped callee root: {coverage}"
    );
    let checkpoint_root = roots[0]["immutable_root_id"].as_str().unwrap().to_string();
    assert!(!checkpoint_root.is_empty());
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_closed(&checkpoint, &token, &hidden);

    let head = persistence
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    let expected_source = json!({
        "store_id": head.store_id,
        "workspace_id": head.workspace_id,
        "branch_id": head.branch_id,
        "epoch": head.epoch,
        "head_object_id": head.head_object_id,
        "head_version": head.head_version
    });

    let restored_provider = Arc::new(ScriptedProvider::new());
    restored_provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": "read-restored", "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    restored_provider.push_ok(stop_turn("s2-restored-done"));
    state.service().inject_provider_host(restored_provider);
    let (status, restored) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/restore"),
            json!({
                "workspace_id": workspace_id,
                "source_branch_id": source_branch,
                "checkpoint_id": checkpoint_id,
                "expected_source": expected_source,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "input": {"text": "read the checkpointed callee value"},
                "cancel_active_source": true,
                "graph_selection": "checkpoint_exact"
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &restored));
    assert_eq!(restored["disposition"], "restored_and_admitted");
    assert_eq!(restored["graph"]["graph_id"], graph);
    let restored_branch = restored["new_branch"]["branch_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        restored_branch, source_branch,
        "restore must land on a new branch"
    );
    let new_run = restored["new_run_id"].as_str().unwrap().to_string();
    let new_session = restored["new_session_id"].as_str().unwrap().to_string();
    assert_closed(&restored, &token, &hidden);
    wait_until(|| {
        event_names(&state, &new_run).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    assert!(
        event_names(&state, &new_run)
            .iter()
            .any(|name| name == "run.completed"),
        "the restored run must complete: {:?}",
        state.service().run_events(&new_run)
    );
    let restored_projection = projected_run(&http, &token, &new_session, &new_run).await;
    assert!(
        restored_projection.contains("s2-restored:") && restored_projection.contains(S2_VALUE),
        "the restored run must read the same value back: {restored_projection}"
    );
    assert!(
        !restored_projection.contains("s2-wrote:"),
        "the restored run must read the captured root, not write a new value: {restored_projection}"
    );

    // Follow-up run on the restored branch: it must resolve the restore
    // lineage to the same checkpoint and read the captured immutable root.
    // Rewriting the same bytes into a fresh root is a failure, not a pass.
    let follow_provider = Arc::new(ScriptedProvider::new());
    follow_provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": "read-followup", "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    follow_provider.push_ok(stop_turn("s2-followup-done"));
    state.service().inject_provider_host(follow_provider);
    let (status, follow) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": new_session,
                "input": "read back the captured callee value on the restored branch",
                "workspace_branch": restored_branch
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &follow));
    assert_eq!(follow["graph_id"], graph);
    assert_eq!(follow["activation_generation"], generation);
    assert_eq!(follow["workspace_branch"], restored_branch);
    let follow_id = follow["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&state, &follow_id).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    assert!(
        event_names(&state, &follow_id)
            .iter()
            .any(|name| name == "run.completed"),
        "the follow-up run must complete: {:?}",
        state.service().run_events(&follow_id)
    );
    let follow_projection = projected_run(&http, &token, &new_session, &follow_id).await;
    assert!(
        follow_projection.contains("s2-restored:") && follow_projection.contains(S2_VALUE),
        "the follow-up run must read the captured root: {follow_projection}"
    );
    assert!(
        !follow_projection.contains("s2-wrote:"),
        "the follow-up run must not rewrite the captured bytes: {follow_projection}"
    );
    let state_store = rustscript_agent::plugins::PluginStateStore::open(Arc::clone(&persistence));
    let snapshot = state_store
        .binding(&follow_id)
        .unwrap()
        .expect("the follow-up run must carry the callee run binding");
    assert_eq!(snapshot.binding.plugin_id, CALLEE_ID);
    assert_eq!(
        snapshot.binding.object_id, checkpoint_root,
        "the follow-up binding must reference the checkpointed immutable root"
    );
    assert_eq!(snapshot.payload.to_json(), json!({"s2": S2_VALUE}));

    http.close().await;
    shutdown_when_idle(&state).await;
}

// T16 stateful HTTP chain over real sockets: graph A is the admitted
// stateless caller plus one run-scoped stateful child. A run on A writes one
// stateful value and checkpoints it; activating graph B leaves A's pinned
// runs fixed while a new run uses B; restoring the checkpoint onto a new
// branch reads the captured root back (rewriting the same bytes is a failure,
// not a pass); rolling back the default graph advances generation and the
// next admission uses the rolled-back graph. Graph pin, effects, and messages
// observed over HTTP agree with the durable records. No new schema field,
// effect kind, or route.
#[tokio::test(flavor = "multi_thread")]
async fn s2_stateful_http_chain_hot_cut_restore_reads_captured_value_and_rollback_advances_generation()
 {
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rustscript_agent::{
        AgentGatewayConfig, AgentGatewayState,
        config::{ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig},
        effects::ResourceQuota,
        plugins::{InstallAuthorization, PackageStore, PublisherKey, trusted_tool_package_root},
    };

    const CALLER_A_ID: &str = "org.rustscript.tools.s2chainacaller";
    const CALLEE_A_ID: &str = "org.rustscript.tools.s2chainacallee";
    const CALLER_B_ID: &str = "org.rustscript.tools.s2chainbcaller";
    const CALLEE_B_ID: &str = "org.rustscript.tools.s2chainbcallee";
    const CALL_A_ID: &str = "s2-chain-a-call";
    const CALL_B_ID: &str = "s2-chain-b-call";
    const CALL_CONT_ID: &str = "s2-chain-a-continuation-call";
    const CALL_CONT2_ID: &str = "s2-chain-a-continuation-call-2";
    const CALL_RESTORE_ID: &str = "s2-chain-restore-call";
    const CALL_ROLL_ID: &str = "s2-chain-roll-call";
    const S2A_VALUE: &str = "s2-chain-a";
    const S2B_VALUE: &str = "s2-chain-b";

    const CALLER_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"},offset:{type:"integer",minimum:1},limit:{type:"integer",minimum:1}},required:["path"],additionalProperties:false}"#;
    const CALLEE_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false}"#;

    const CALLER_A_SOURCE: &str = r#"fn c7a_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn c7a_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}
fn c7a_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn c7a_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let prepare: map = c7a_map(context, "prepare");
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if c7a_string(prepared, "kind", "") == "replay" => {
        c7a_map(prepared, "result")
    } else => {
        if c7a_bool(prepared, "ok", false) == false => {
            prepared
        } else => {
            let token: string = c7a_string(prepared, "execution_token", "");
            let arguments: map = c7a_map(context, "arguments");
            let path: string = c7a_string(arguments, "path", "");
            let meta: map = cap::fs_metadata(token, path);
            if c7a_bool(meta, "ok", false) == false => {
                meta
            } else => {
                let caller_len: int = c7a_int(meta, "len", 0);
                let canonical: string = json::encode(arguments);
                let child: map = agent_runtime::invoke_pinned_plugin_child({ canonical_arguments: canonical });
                if c7a_bool(child, "ok", false) == false => {
                    let failed: map = { ok: false, content: "", data: {}, error: { code: c7a_string(child, "code", "child_failed"), message: c7a_string(child, "message", "child failed") }, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, failed)
                } else => {
                    let result: map = { ok: true, content: "s2achain:" + c7a_string(child, "canonical_result", ""), data: { caller_len: caller_len }, error: null, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, result)
                }
            }
        }
    }
}
"#;

    const CALLER_B_SOURCE: &str = r#"fn c7b_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn c7b_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}
fn c7b_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn c7b_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let prepare: map = c7b_map(context, "prepare");
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if c7b_string(prepared, "kind", "") == "replay" => {
        c7b_map(prepared, "result")
    } else => {
        if c7b_bool(prepared, "ok", false) == false => {
            prepared
        } else => {
            let token: string = c7b_string(prepared, "execution_token", "");
            let arguments: map = c7b_map(context, "arguments");
            let path: string = c7b_string(arguments, "path", "");
            let meta: map = cap::fs_metadata(token, path);
            if c7b_bool(meta, "ok", false) == false => {
                meta
            } else => {
                let caller_len: int = c7b_int(meta, "len", 0);
                let canonical: string = json::encode(arguments);
                let child: map = agent_runtime::invoke_pinned_plugin_child({ canonical_arguments: canonical });
                if c7b_bool(child, "ok", false) == false => {
                    let failed: map = { ok: false, content: "", data: {}, error: { code: c7b_string(child, "code", "child_failed"), message: c7b_string(child, "message", "child failed") }, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, failed)
                } else => {
                    let result: map = { ok: true, content: "s2bchain:" + c7b_string(child, "canonical_result", ""), data: { caller_len: caller_len }, error: null, truncated: false, artifacts: [] };
                    agent_runtime::tool_commit(token, result)
                }
            }
        }
    }
}
"#;

    // The first run on a fresh root writes the seeded value; every later run
    // on a restored binding only reads the captured document back. A rewrite
    // of the same bytes on the restored branch would surface as a write
    // marker and fail the read-back assertions below.
    const CALLEE_A_SOURCE: &str = r#"fn s7a_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s7a_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s7a_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let current: map = state::read();
    if s7a_bool(current, "ok", false) == false => {
        current
    } else => {
        let revision: int = s7a_int(current, "revision", 0);
        let prior: string = s7a_string(current, "document", "");
        let expected: string = json::encode({ s2: "s2-chain-a" });
        if prior == expected => {
            { ok: true, content: "s2a-restored:" + prior, data: { same: true }, error: null, truncated: false, artifacts: [] }
        } else => {
            let written: map = state::write(revision, expected);
            if s7a_bool(written, "ok", false) == false => {
                written
            } else => {
                { ok: true, content: "s2a-wrote:" + expected, data: { same: true }, error: null, truncated: false, artifacts: [] }
            }
        }
    }
}
"#;

    const CALLEE_B_SOURCE: &str = r#"fn s7b_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn s7b_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn s7b_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    let current: map = state::read();
    if s7b_bool(current, "ok", false) == false => {
        current
    } else => {
        let revision: int = s7b_int(current, "revision", 0);
        let prior: string = s7b_string(current, "document", "");
        let expected: string = json::encode({ s2: "s2-chain-b" });
        if prior == expected => {
            { ok: true, content: "s2b-restored:" + prior, data: { same: true }, error: null, truncated: false, artifacts: [] }
        } else => {
            let written: map = state::write(revision, expected);
            if s7b_bool(written, "ok", false) == false => {
                written
            } else => {
                { ok: true, content: "s2b-wrote:" + expected, data: { same: true }, error: null, truncated: false, artifacts: [] }
            }
        }
    }
}
"#;

    fn chain_catalog(tool: &str, schema: &str) -> String {
        format!(
            "pub fn managed_authority_catalog(context: map) -> map {{\n    {{\n        declarations: [{{ tool_name: \"{tool}\", operation: \"workspace_read\" }}],\n        descriptors: [{{\n            name: \"{tool}\",\n            description: \"Read bounded text from a workspace file\",\n            toolset: \"coding\",\n            risk_class: \"read\",\n            schema: {schema}\n        }}]\n    }}\n}}\n"
        )
    }

    fn chain_caller_manifest(caller: &str, callee: &str) -> String {
        format!(
            "format: rustscript.plugin/v1\nid: {caller}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: child\n    id: {callee}\n    version: \"1.0.0\"\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated:\n        - dependency: child\n          entry: run\n          allow:\n            - kind: workspace.fs.read\n              scope: bound_workspace\n              recovery: none\n            - kind: workspace.fs.write\n              scope: bound_workspace\n              recovery: none\n"
        )
    }

    fn chain_callee_manifest(callee: &str) -> String {
        format!(
            "format: rustscript.plugin/v1\nid: {callee}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\n  - workspace.write\nstate:\n  scope: run\n  schema: 1\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n        - kind: workspace.fs.write\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
        )
    }

    let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("t16-s2chain-{}", uuid::Uuid::new_v4().simple()));
    let _ = std::fs::remove_dir_all(&root);
    let workspace = root.join("workspace");
    let home = root.join("workspace-home");
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(workspace.join("note.txt"), b"s2-chain-note").unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    lifecycle: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home, &source] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let token = uuid::Uuid::new_v4().to_string();
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = InstallAuthorization {
        admin: true,
        accepted_publishers: vec![PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    let mut config = AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy {
                create_checkpoint: true,
                restore: true,
                branch: true,
                publish: false,
            },
        }),
        ..AgentGatewayConfig::default()
    };
    config.approvals.write = "allow".into();
    config.run_timeout = Duration::from_secs(900);
    let db = root.join("gateway.sqlite");
    let state = AgentGatewayState::with_sqlite_path(config.clone(), &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    let store = PackageStore::open(trusted_tool_package_root(&db)).unwrap();
    let caller_a_manifest = chain_caller_manifest(CALLER_A_ID, CALLEE_A_ID);
    let caller_b_manifest = chain_caller_manifest(CALLER_B_ID, CALLEE_B_ID);
    let callee_a_manifest = chain_callee_manifest(CALLEE_A_ID);
    let callee_b_manifest = chain_callee_manifest(CALLEE_B_ID);
    let catalog_caller = chain_catalog("read_file", CALLER_SCHEMA);
    let catalog_callee = chain_catalog("read_file", CALLEE_SCHEMA);
    for (dir, manifest, run_source, catalog) in [
        (
            "package-chain-a-caller",
            caller_a_manifest.as_str(),
            CALLER_A_SOURCE,
            catalog_caller.as_str(),
        ),
        (
            "package-chain-a-callee",
            callee_a_manifest.as_str(),
            CALLEE_A_SOURCE,
            catalog_callee.as_str(),
        ),
        (
            "package-chain-b-caller",
            caller_b_manifest.as_str(),
            CALLER_B_SOURCE,
            catalog_caller.as_str(),
        ),
        (
            "package-chain-b-callee",
            callee_b_manifest.as_str(),
            CALLEE_B_SOURCE,
            catalog_callee.as_str(),
        ),
    ] {
        let package = source.join(dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("manifest.yaml"), manifest).unwrap();
        std::fs::write(package.join("run.rss"), run_source).unwrap();
        std::fs::write(package.join("catalog.rss"), catalog).unwrap();
        let payload = store.signature_payload(&package).unwrap();
        std::fs::write(
            package.join("signature.ed25519"),
            pair.sign(&payload).as_ref(),
        )
        .unwrap();
        store.install(&package, &auth).unwrap();
    }
    let http = Http::bind(state.clone()).await;
    let hidden = [workspace.as_path(), source.as_path()];

    // S1: admit graph A and pin it over HTTP.
    let (graph_a, generation_a) = activate(&http, &token, &config, &db, CALLER_A_ID).await;
    let (status, graph_view) = http
        .request(
            "GET",
            &format!("/v1/plugin-graphs/{graph_a}"),
            json!({}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &graph_view));
    assert_eq!(graph_view["graph_id"], graph_a);
    assert_closed(&graph_view, &token, &hidden);

    // S2: a run on A writes the stateful value. HTTP admission starts at the
    // real socket routes; request JSON grants nothing.
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let provider_a = Arc::new(ScriptedProvider::new());
    provider_a.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": CALL_A_ID, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    provider_a.push_ok(stop_turn("s2-chain-a-done"));
    state.service().inject_provider_host(provider_a);
    let idem_a = uuid::Uuid::new_v4().to_string();
    let run_body_a = json!({"session_id": session_id, "input": "write the stateful chain value"});
    let (status, admitted_a) = http
        .request(
            "POST",
            "/v1/runs",
            run_body_a.clone(),
            Some(&token),
            Some(&idem_a),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted_a));
    assert_eq!(admitted_a["graph_id"], graph_a);
    assert_eq!(admitted_a["activation_generation"], generation_a);
    assert_eq!(admitted_a["publication"], json!("not_published"));
    assert_closed(&admitted_a, &token, &hidden);
    let run_a = admitted_a["run_id"].as_str().unwrap().to_string();
    let branch_a = admitted_a["workspace_branch"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&state, &run_a).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    assert!(
        event_names(&state, &run_a)
            .iter()
            .any(|name| name == "run.completed"),
        "the graph-A run must complete: {:?}",
        state.service().run_events(&run_a)
    );
    let projection_a = projected_run(&http, &token, &session_id, &run_a).await;
    assert!(
        projection_a.contains("s2a-wrote:") && projection_a.contains(S2A_VALUE),
        "the first run must write the stateful value: {projection_a}"
    );
    let (status, effects_a) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_a}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects_a));
    let receipt_a = effects_a["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == CALL_A_ID)
        .expect("graph-A parent effect receipt")
        .clone();
    assert_eq!(receipt_a["state"], "read_only");
    assert_eq!(receipt_a["branch_id"], branch_a);
    assert_closed(&effects_a, &token, &hidden);
    let persistence = state.persistence().unwrap();
    let record_a = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.clone(),
                run_id: run_a.clone(),
            },
            call_id: CALL_A_ID.into(),
        })
        .unwrap()
        .expect("durable graph-A parent effect must exist");
    assert_eq!(record_a.identity.tool_name, "read_file");
    assert_eq!(
        record_a.state,
        rustscript_agent::effects::ManagedPublicationStatus::ReadOnly
    );
    assert_eq!(
        receipt_a["effect_id"].as_str().unwrap(),
        record_a.effect_id,
        "HTTP effects and the durable record agree on the receipt"
    );
    let workspace_id = receipt_a["workspace_id"].as_str().unwrap().to_string();
    let epoch_a = receipt_a["epoch"].as_u64().unwrap();

    // S3: checkpoint the stateful value. The checkpoint pins graph A and
    // covers exactly the callee run root.
    let checkpoint_body = json!({
        "source_run_id": run_a,
        "workspace_id": workspace_id,
        "source_branch_id": branch_a,
        "expected_epoch": epoch_a,
        "request_id": uuid::Uuid::new_v4().to_string(),
        "mode": "at_closed_batch"
    });
    let (status, checkpoint) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            checkpoint_body.clone(),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &checkpoint));
    assert_eq!(checkpoint["replayed"], false);
    assert_eq!(checkpoint["checkpoint"]["graph"]["graph_id"], graph_a);
    assert_eq!(
        checkpoint["checkpoint"]["graph"]["captured_activation_generation"],
        generation_a
    );
    let coverage = &checkpoint["checkpoint"]["plugin_state"];
    assert_eq!(
        coverage["kind"], "stateful",
        "the admitted chain checkpoints as a stateful graph: {coverage}"
    );
    assert_eq!(
        coverage["package_id"], CALLEE_A_ID,
        "the covered state owner is the locked callee: {coverage}"
    );
    let roots = coverage["roots"].as_array().unwrap();
    assert_eq!(
        roots.len(),
        1,
        "exactly one run-scoped callee root: {coverage}"
    );
    assert_eq!(roots[0]["owner_kind"], "run");
    assert_eq!(roots[0]["package_id"], CALLEE_A_ID);
    assert!(
        roots[0]["revision"].as_u64().unwrap() >= 1,
        "a written root always has a revision: {}",
        roots[0]
    );
    let checkpoint_root = roots[0]["immutable_root_id"].as_str().unwrap().to_string();
    assert!(!checkpoint_root.is_empty());
    let checkpoint_id = checkpoint["checkpoint"]["checkpoint_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_closed(&checkpoint, &token, &hidden);
    let (status, replay) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/checkpoints"),
            checkpoint_body,
            Some(&token),
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
                "expected_epoch": epoch_a,
                "request_id": uuid::Uuid::new_v4().to_string(),
                "mode": "at_closed_batch"
            }),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &foreign));
    assert_eq!(foreign["error"]["code"], "managed_checkpoint_conflict");

    // S4: an in-flight graph-A run crosses the hot cut and really executes
    // its pinned stateful child after B activates. The completed seed run
    // above (run_a) stays the checkpoint source; this second run (run_cont)
    // is the continuation proof, not the source.
    let inner_cont = ScriptedProvider::new();
    inner_cont.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": CALL_CONT_ID, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    inner_cont.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": CALL_CONT2_ID, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    inner_cont.push_ok(stop_turn("s2-chain-a-continued-done"));
    let gate_cont = Arc::new(SecondBusinessGate::new(inner_cont));
    state.service().inject_provider_host(gate_cont.clone());
    let (status, admitted_cont) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "continue the stateful chain value"}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted_cont));
    assert_eq!(admitted_cont["graph_id"], graph_a);
    assert_eq!(admitted_cont["activation_generation"], generation_a);
    assert_eq!(admitted_cont["publication"], json!("not_published"));
    assert_closed(&admitted_cont, &token, &hidden);
    let run_cont = admitted_cont["run_id"].as_str().unwrap().to_string();
    let branch_cont = admitted_cont["workspace_branch"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        run_cont, run_a,
        "continuation run must differ from the checkpoint source run"
    );
    wait_until(|| gate_cont.holding()).await;
    assert!(
        gate_cont.holding(),
        "the continuation run must be in flight before B activates"
    );

    // S4b: activating graph B must not change A's pinned graph. The seed
    // idempotent reread below only preserves the completed admission; it is
    // not continuation evidence — run_cont above is.
    let (graph_b, generation_b) = activate(&http, &token, &config, &db, CALLER_B_ID).await;
    assert_ne!(graph_b, graph_a);
    assert!(generation_b > generation_a);
    let (status, reread_a) = http
        .request(
            "POST",
            "/v1/runs",
            run_body_a.clone(),
            Some(&token),
            Some(&idem_a),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &reread_a));
    assert_eq!(reread_a["run_id"], run_a);
    assert_eq!(reread_a["graph_id"], graph_a);
    assert_eq!(reread_a["activation_generation"], generation_a);
    let pinned_a = pin_for_run(&config, &db, &run_a);
    assert_eq!(pinned_a["graph_id"], graph_a);
    assert_eq!(pinned_a["generation"], generation_a);
    let (status, graph_still_a) = http
        .request(
            "GET",
            &format!("/v1/plugin-graphs/{graph_a}"),
            json!({}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &graph_still_a));
    assert_eq!(graph_still_a["graph_id"], graph_a);
    assert!(
        gate_cont.holding(),
        "the continuation run must still be held across B activation"
    );
    // S4c: release the gate; the in-flight A run really executes its pinned
    // stateful child after the cut.
    gate_cont.release();
    wait_until(|| {
        event_names(&state, &run_cont).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    assert!(
        event_names(&state, &run_cont)
            .iter()
            .any(|name| name == "run.completed"),
        "the in-flight graph-A run must complete after B activates: {:?}",
        state.service().run_events(&run_cont)
    );
    let projection_cont = projected_run(&http, &token, &session_id, &run_cont).await;
    assert!(
        projection_cont.contains(S2A_VALUE),
        "the continued run must carry the graph-A value: {projection_cont}"
    );
    assert!(
        !projection_cont.contains(S2B_VALUE),
        "the continued run must not carry the graph-B value: {projection_cont}"
    );
    let (status, effects_cont) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_cont}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &effects_cont));
    let first_cont = effects_cont["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == CALL_CONT_ID)
        .expect("pre-cut stateful child receipt")
        .clone();
    assert_eq!(first_cont["state"], "read_only");
    assert_eq!(first_cont["branch_id"], branch_cont);
    let second_cont = effects_cont["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == CALL_CONT2_ID)
        .expect("post-cut stateful child must have executed")
        .clone();
    assert_eq!(second_cont["state"], "read_only");
    assert_eq!(second_cont["branch_id"], branch_cont);
    assert_closed(&effects_cont, &token, &hidden);
    let record_cont2 = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: session_id.clone(),
                run_id: run_cont.clone(),
            },
            call_id: CALL_CONT2_ID.into(),
        })
        .unwrap()
        .expect("durable post-cut child effect must exist");
    assert_eq!(record_cont2.identity.tool_name, "read_file");
    assert_eq!(
        record_cont2.state,
        rustscript_agent::effects::ManagedPublicationStatus::ReadOnly
    );
    assert_eq!(
        second_cont["effect_id"].as_str().unwrap(),
        record_cont2.effect_id,
        "HTTP effects and the durable record agree on the post-cut receipt"
    );
    let (status, messages_cont) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &messages_cont));
    for call in [CALL_CONT_ID, CALL_CONT2_ID] {
        let block = typed_tool_block(
            messages_cont["data"]
                .as_array()
                .expect("continuation messages"),
            call,
        )
        .unwrap_or_else(|| panic!("typed continuation result missing for {call}"));
        assert_eq!(block["tool_call_id"], call);
        assert_eq!(block["is_error"], false);
        assert!(
            block["content"].as_str().unwrap().contains(S2A_VALUE),
            "the continuation call {call} must carry the graph-A value: {block}"
        );
        assert!(
            !block["content"].as_str().unwrap().contains(S2B_VALUE),
            "the continuation call {call} must not carry the graph-B value: {block}"
        );
    }
    assert_closed(&messages_cont, &token, &hidden);
    let pinned_cont = pin_for_run(&config, &db, &run_cont);
    assert_eq!(pinned_cont["graph_id"], graph_a);
    assert_eq!(pinned_cont["generation"], generation_a);
    let events_cont = http.typed_sse(&token, &run_cont).await;
    assert_typed_terminal(&events_cont, "run.completed");

    // S5: a new run uses B and writes B's own stateful value.
    let provider_b = Arc::new(ScriptedProvider::new());
    provider_b.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": CALL_B_ID, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    provider_b.push_ok(stop_turn("s2-chain-b-done"));
    state.service().inject_provider_host(provider_b);
    let (status, admitted_b) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write the second graph value"}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted_b));
    assert_eq!(admitted_b["graph_id"], graph_b);
    assert_eq!(admitted_b["activation_generation"], generation_b);
    let run_b = admitted_b["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&state, &run_b).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    assert!(
        event_names(&state, &run_b)
            .iter()
            .any(|name| name == "run.completed"),
        "the graph-B run must complete: {:?}",
        state.service().run_events(&run_b)
    );
    let projection_b = projected_run(&http, &token, &session_id, &run_b).await;
    assert!(
        projection_b.contains("s2b-wrote:") && projection_b.contains(S2B_VALUE),
        "the new run must execute graph B: {projection_b}"
    );
    assert!(
        !projection_b.contains(S2A_VALUE),
        "the graph-B run must not carry the graph-A value: {projection_b}"
    );
    let pinned_b = pin_for_run(&config, &db, &run_b);
    assert_eq!(pinned_b["graph_id"], graph_b);
    assert_eq!(pinned_b["generation"], generation_b);
    let (status, before_restore) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &before_restore));
    let session_before_restore = before_restore["data"].clone();
    assert_closed(&before_restore, &token, &hidden);

    // S6: restoring the checkpoint opens a new branch whose run reads the
    // captured value back instead of rewriting the same bytes.
    let head = persistence
        .managed_workspace_head(&record_a.identity.workspace)
        .unwrap();
    let restored_provider = Arc::new(ScriptedProvider::new());
    restored_provider.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": CALL_RESTORE_ID, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    restored_provider.push_ok(stop_turn("s2-chain-restored-done"));
    state.service().inject_provider_host(restored_provider);
    let restore_body = json!({
        "workspace_id": workspace_id,
        "source_branch_id": branch_a,
        "checkpoint_id": checkpoint_id,
        "expected_source": {
            "store_id": head.store_id,
            "workspace_id": head.workspace_id,
            "branch_id": head.branch_id,
            "epoch": head.epoch,
            "head_object_id": head.head_object_id,
            "head_version": head.head_version
        },
        "request_id": uuid::Uuid::new_v4().to_string(),
        "input": {"text": "read the captured chain value"},
        "cancel_active_source": true,
        "graph_selection": "checkpoint_exact"
    });
    let (status, restored) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/restore"),
            restore_body.clone(),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &restored));
    assert_eq!(restored["disposition"], "restored_and_admitted");
    assert_eq!(restored["graph"]["graph_id"], graph_a);
    assert_ne!(
        restored["new_branch"]["branch_id"], branch_a,
        "restore must land on a new branch"
    );
    let new_run = restored["new_run_id"].as_str().unwrap().to_string();
    let new_session = restored["new_session_id"].as_str().unwrap().to_string();
    assert_ne!(new_run, run_a);
    assert_closed(&restored, &token, &hidden);
    let (status, replayed_restore) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/restore"),
            restore_body,
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &replayed_restore));
    assert_eq!(replayed_restore["replayed"], true);
    assert_eq!(replayed_restore["new_run_id"], new_run);
    let (status, old_again) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &old_again));
    assert_eq!(old_again["data"], session_before_restore);
    wait_until(|| {
        event_names(&state, &new_run).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    assert!(
        event_names(&state, &new_run)
            .iter()
            .any(|name| name == "run.completed"),
        "the restored run must complete: {:?}",
        state.service().run_events(&new_run)
    );
    let restored_projection = projected_run(&http, &token, &new_session, &new_run).await;
    assert!(
        restored_projection.contains("s2a-restored:") && restored_projection.contains(S2A_VALUE),
        "the restored run must read the captured value back: {restored_projection}"
    );
    assert!(
        !restored_projection.contains("s2a-wrote:"),
        "the restored run must read the captured root, not rewrite the same bytes: {restored_projection}"
    );
    assert!(
        !restored_projection.contains(S2B_VALUE),
        "the restored run must execute the checkpoint graph, not the active graph: {restored_projection}"
    );
    let state_store = rustscript_agent::plugins::PluginStateStore::open(Arc::clone(&persistence));
    let snapshot = state_store
        .binding(&new_run)
        .unwrap()
        .expect("the restored run must carry the callee run binding");
    assert_eq!(snapshot.binding.plugin_id, CALLEE_A_ID);
    assert_eq!(
        snapshot.binding.object_id, checkpoint_root,
        "the restored binding must reference the checkpointed immutable root"
    );
    assert_eq!(snapshot.payload.to_json(), json!({"s2": S2A_VALUE}));
    let restored_pin = pin_for_run(&config, &db, &new_run);
    assert_eq!(restored_pin["graph_id"], graph_a);
    assert_eq!(
        restored_pin["generation"], generation_a,
        "restored run must pin the checkpoint-captured generation, not the active graph"
    );
    let (status, restored_effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{new_run}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &restored_effects));
    let restore_entry = restored_effects["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["call_id"] == CALL_RESTORE_ID)
        .expect("restored parent effect receipt")
        .clone();
    assert_eq!(restore_entry["state"], "read_only");
    assert_eq!(
        restore_entry["branch_id"],
        restored["new_branch"]["branch_id"]
    );
    let restore_record = persistence
        .managed_effect_get(&rustscript_agent::effects::ManagedEffectGetRequest {
            owner: rustscript_agent::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: new_session.clone(),
                run_id: new_run.clone(),
            },
            call_id: CALL_RESTORE_ID.into(),
        })
        .unwrap()
        .expect("durable restored parent effect must exist");
    assert_eq!(
        restore_record.state,
        rustscript_agent::effects::ManagedPublicationStatus::ReadOnly
    );
    assert_eq!(
        restore_entry["effect_id"].as_str().unwrap(),
        restore_record.effect_id,
        "HTTP effects and the durable record agree on the restored receipt"
    );
    let (status, restored_messages) = http
        .request(
            "GET",
            &format!("/api/sessions/{new_session}/messages"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &restored_messages));
    let restore_block = typed_tool_block(
        restored_messages["data"]
            .as_array()
            .expect("restored messages"),
        CALL_RESTORE_ID,
    )
    .expect("typed restored read result");
    assert_eq!(restore_block["tool_call_id"], CALL_RESTORE_ID);
    assert_eq!(restore_block["is_error"], false);
    assert!(
        restore_block["content"]
            .as_str()
            .unwrap()
            .contains(S2A_VALUE),
        "the HTTP message must carry the captured value: {restore_block}"
    );
    assert_closed(&restored_messages, &token, &hidden);

    // S7: rolling back the default graph advances generation; the next
    // admission uses the rolled-back graph.
    let (status, rolled) = http
        .request(
            "POST",
            &format!("/v1/plugin-activations/owner-space.{generation_a}/rollback"),
            json!({"admin": true, "graph_id": graph_b}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &rolled));
    let generation_roll = rolled["generation"].as_u64().unwrap();
    assert!(generation_roll > generation_b);
    assert_eq!(rolled["graph_id"], graph_a);
    let provider_roll = Arc::new(ScriptedProvider::new());
    provider_roll.push_ok(json!({
        "text": "",
        "tool_calls": [{"id": CALL_ROLL_ID, "name": "read_file", "arguments": {"path": "note.txt"}}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "reasoning": "",
        "stop_reason": "tool_calls"
    }));
    provider_roll.push_ok(stop_turn("s2-chain-roll-done"));
    state.service().inject_provider_host(provider_roll);
    let (status, admitted_roll) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write after rollback"}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted_roll));
    assert_eq!(admitted_roll["graph_id"], graph_a);
    assert_eq!(admitted_roll["activation_generation"], generation_roll);
    let run_roll = admitted_roll["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&state, &run_roll).iter().any(|name| {
            matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )
        })
    })
    .await;
    assert!(
        event_names(&state, &run_roll)
            .iter()
            .any(|name| name == "run.completed"),
        "the post-rollback run must complete: {:?}",
        state.service().run_events(&run_roll)
    );
    let projection_roll = projected_run(&http, &token, &session_id, &run_roll).await;
    assert!(
        projection_roll.contains("s2a-wrote:") && projection_roll.contains(S2A_VALUE),
        "the post-rollback run must use the rolled-back graph: {projection_roll}"
    );
    let pinned_roll = pin_for_run(&config, &db, &run_roll);
    assert_eq!(pinned_roll["graph_id"], graph_a);
    assert_eq!(pinned_roll["generation"], generation_roll);

    // S8: HTTP queries of the graph pin, effects, and existing messages agree
    // with the durable records; the pre-restore history is untouched.
    let (status, final_effects) = http
        .request(
            "GET",
            &format!("/v1/runs/{run_a}/effects?limit=128"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &final_effects));
    assert_eq!(
        final_effects["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["call_id"] == CALL_A_ID)
            .unwrap()["effect_id"],
        receipt_a["effect_id"]
    );
    let (status, final_messages) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &final_messages));
    let prefix = &final_messages["data"].as_array().unwrap()
        [..session_before_restore.as_array().unwrap().len()];
    assert_eq!(Value::Array(prefix.to_vec()), session_before_restore);
    let seed_block = typed_tool_block(final_messages["data"].as_array().unwrap(), CALL_A_ID)
        .expect("typed seed result still present");
    assert_eq!(seed_block["is_error"], false);
    let (status, graph_b_view) = http
        .request(
            "GET",
            &format!("/v1/plugin-graphs/{graph_b}"),
            json!({}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &graph_b_view));
    assert_eq!(graph_b_view["graph_id"], graph_b);
    assert_closed(&final_messages, &token, &hidden);

    http.close().await;
    shutdown_when_idle(&state).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn required_publication_commits_before_typed_run_completed() {
    let cycle = Cycle::open_required(&format!("t16-required-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call(
        "write-required",
        "write_file",
        "required-out.txt",
    ));
    provider.push_ok(stop_turn("required-done"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write the required marker"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let branch = admitted["workspace_branch"]
        .as_str()
        .expect("managed branch")
        .to_string();
    let epoch = admitted["epoch"].as_u64().expect("managed epoch");
    assert_eq!(
        admitted["publication"],
        json!("not_published"),
        "admission projects the real pre-completion state"
    );

    // Real socket SSE replay: workspace.published must immediately precede
    // run.completed, and exactly one terminal event may exist.
    let events = tokio::time::timeout(
        Duration::from_secs(10),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "SSE never terminated; parked={}; events={:?}",
            cycle.state.service().pending_terminal_count(),
            event_names(&cycle.state, &run_id)
        )
    });
    assert_typed_terminal(&events, "run.completed");
    let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
    let published = names
        .iter()
        .position(|name| *name == "workspace.published")
        .expect("required completion emits workspace.published");
    assert_eq!(
        published + 1,
        names.len() - 1,
        "workspace.published must immediately precede run.completed: {names:?}"
    );
    let raw = http.raw_sse(&cycle.token, &run_id).await;
    let published_event = raw
        .iter()
        .find(|value| value["event"] == "workspace.published")
        .expect("durable workspace.published payload");
    let completed = raw
        .iter()
        .find(|value| value["event"] == "run.completed")
        .expect("durable run.completed payload");
    let publication = &completed["publication"];
    assert_eq!(publication["status"], "committed");
    assert_eq!(publication["workspace_id"], published_event["workspace_id"]);
    assert_eq!(publication["branch_id"], json!(branch));
    assert_eq!(publication["epoch"], json!(epoch));
    assert_eq!(
        publication["head_object_id"],
        published_event["head_object_id"]
    );
    assert_eq!(publication["head_version"], published_event["head_version"]);
    let request_id = publication["request_id"]
        .as_str()
        .expect("frozen request identity")
        .to_string();
    assert_eq!(published_event["request_id"], json!(request_id));
    assert!(
        completed["seq"].as_u64().unwrap() > published_event["seq"].as_u64().unwrap(),
        "run.completed follows workspace.published in seq order"
    );

    // Durable readback of the committed pointer in a later read.
    let workspace_id = publication["workspace_id"]
        .as_str()
        .expect("workspace identity")
        .to_string();
    let persistence = cycle.state.persistence().expect("persistence");
    let pointer = persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("pointer read")
        .expect("required completion committed a pointer");
    assert_eq!(pointer.branch_id, branch);
    assert_eq!(pointer.epoch, epoch);
    assert_eq!(
        pointer.head_object_id,
        publication["head_object_id"].as_str().unwrap()
    );
    assert_eq!(
        pointer.head_version,
        publication["head_version"].as_u64().unwrap()
    );
    assert_eq!(pointer.request_id, request_id);
    assert_eq!(pointer.revision, 1, "first publication revision");

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
    assert!(
        messages["data"]
            .as_array()
            .expect("session messages")
            .iter()
            .any(|message| message["run_id"] == json!(run_id)
                && message["content"].to_string().contains("required-done")),
        "the committed assistant message is readable: {messages}"
    );

    // The next admission on this branch projects the real committed state.
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("required-second"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, second) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "second run"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &second));
    assert_eq!(second["publication"], json!("committed"));
    assert_eq!(
        second["workspace_branch"],
        json!(branch),
        "the next admission continues the same published branch"
    );
    assert_closed(&admitted, &cycle.token, &hidden);
    assert_closed(&second, &cycle.token, &hidden);

    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn forged_publication_json_is_refused_before_enqueue() {
    let cycle = Cycle::open_required(&format!("t16-forged-{}", uuid::Uuid::new_v4().simple()));
    let persistence = cycle.state.persistence().expect("persistence");
    // Public run_terminal with non-empty publication data: refused before enqueue.
    let error = persistence
        .run_terminal(&json!({
            "run_id": "run-forged",
            "to_status": "completed",
            "publication_json": "{\"status\":\"committed\"}"
        }))
        .expect_err("public run_terminal must refuse publication data");
    assert_eq!(error.code, "managed_publication_authority_required");
    // Crafted payload keys do not construct the private permit either.
    let error = persistence
        .run_terminal(&json!({
            "run_id": "run-forged",
            "to_status": "completed",
            "publication": {"status": "committed"},
            "publication_json": "{\"request_id\":\"forged\"}"
        }))
        .expect_err("crafted publication keys must not grant access");
    assert_eq!(error.code, "managed_publication_authority_required");
    shutdown_when_idle(&cycle.state).await;
}

/// T9-1: a real authenticated socket admission whose otherwise-valid body
/// carries forged publication/run/graph/capability fields is accepted, but the
/// payload cannot select Required completion, a Native permit, a pointer or a
/// workspace.published event. The trusted host policy is Staged with ordinary
/// publication capability enabled, so a legitimate capability denial cannot be
/// mistaken for the forged-input refusal.
#[tokio::test(flavor = "multi_thread")]
async fn forged_run_request_fields_cannot_select_publication_or_native_permit() {
    let cycle = Cycle::open_staged_with_publish(&format!(
        "t16-forged-request-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("write-forged", "write_file", "forged-out.txt"));
    provider.push_ok(stop_turn("forged-done"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let forged_run_id = uuid::Uuid::new_v4().to_string();
    let forged_publication = json!({
        "status": "committed",
        "request_id": uuid::Uuid::new_v4().to_string(),
        "workspace_id": "forged-workspace",
        "branch_id": "forged-branch",
        "head_object_id": "forged-head",
        "head_version": 99
    });
    let body = json!({
        "session_id": session_id,
        "input": "write the staged marker",
        "extra": {
            "publication": forged_publication.clone(),
            "run_id": forged_run_id.clone(),
            "graph_ref_id": "forged-graph-ref",
            "private_finalize": true,
            "publication_capability": "native-finalize"
        },
        "publication": forged_publication,
        "run_id": forged_run_id.clone(),
        "graph_ref_id": "forged-graph-ref",
        "publication_json": "{\"status\":\"committed\"}"
    });
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            body,
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(
        status,
        202,
        "an otherwise valid request with forged fields is admitted: {}",
        explain(status, &admitted)
    );
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    assert_ne!(
        run_id, forged_run_id,
        "the request cannot select its run id"
    );
    assert_eq!(
        admitted["graph_id"],
        json!(graph),
        "the request cannot select a graph ref"
    );
    assert_ne!(admitted["graph_id"], json!("forged-graph-ref"));
    assert_eq!(
        admitted["publication"],
        json!("not_published"),
        "the forged publication document cannot select a completion policy"
    );
    assert_closed(&admitted, &cycle.token, &hidden);

    let events = tokio::time::timeout(
        Duration::from_secs(10),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .expect("forged-input run terminates");
    assert_typed_terminal(&events, "run.completed");
    let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
    assert!(
        !names.contains(&"workspace.published"),
        "forged publication data must not emit a service-owned publication event: {names:?}"
    );
    let raw = http.raw_sse(&cycle.token, &run_id).await;
    let completed = raw
        .iter()
        .find(|value| value["event"] == "run.completed")
        .expect("durable run.completed payload");
    assert_eq!(completed["publication"]["status"], "staged");
    assert!(
        completed["publication"].get("request_id").is_none(),
        "a staged terminal carries no forged publication request identity: {}",
        completed["publication"]
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
    let write = effects["entries"]
        .as_array()
        .expect("effect entries")
        .iter()
        .find(|entry| entry["call_id"] == "write-forged")
        .expect("the legitimate write receipt")
        .clone();
    assert_eq!(write["state"], "committed", "the legitimate effect is kept");
    let workspace_id = write["workspace_id"]
        .as_str()
        .expect("workspace identity")
        .to_string();
    let pointer = cycle
        .state
        .persistence()
        .expect("persistence")
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("pointer read");
    assert!(
        pointer.is_none(),
        "forged request data must not create a publication pointer: {pointer:?}"
    );

    let (status, forged_lookup) = http
        .request(
            "GET",
            &format!("/v1/runs/{forged_run_id}/events"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 404, "{}", explain(status, &forged_lookup));
    assert_eq!(forged_lookup["error"]["code"], "run_not_found");
    assert_closed(&forged_lookup, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// T9-2: a real compiled and admitted agent guest emits one canonical allowed
/// event and then attempts the service-owned `workspace.published` type. The
/// existing `validate_script_event` drops the forged event, the run fails with
/// the typed schema code, and no publication event or pointer is created. The
/// allowed-event positive proves the same guest event surface was live.
#[tokio::test(flavor = "multi_thread")]
async fn guest_stream_emit_cannot_publish_service_owned_event() {
    let source = r#"
use stream;
pub fn run(context: map) -> map {
    stream::emit({"type": "model.delta", "delta": "allowed-guest-event"});
    stream::emit({
        "type": "workspace.published",
        "workspace_id": "forged-workspace",
        "branch_id": "forged-branch",
        "head_object_id": "forged-head",
        "head_version": 99
    });
    { kind: "run.completed", answer: "guest-events-done" }
}
"#;
    let cycle = Cycle::open_guest_source(
        &format!("t16-guest-event-{}", uuid::Uuid::new_v4().simple()),
        source,
    );
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "emit a forged event"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let events = tokio::time::timeout(
        Duration::from_secs(10),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .expect("guest event run terminates");
    assert_typed_terminal(&events, "run.failed");
    let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
    assert!(
        names.contains(&"model.delta"),
        "the canonical allowed event must be delivered by the same guest surface: {names:?}"
    );
    assert!(
        !names.contains(&"workspace.published"),
        "the service-owned event must never be delivered: {names:?}"
    );
    let raw = http.raw_sse(&cycle.token, &run_id).await;
    let failed = raw
        .iter()
        .find(|value| value["event"] == "run.failed")
        .expect("durable schema-violation terminal");
    assert_eq!(failed["error_code"], "invalid_event_schema");
    assert!(
        !cycle
            .state
            .service()
            .run_events(&run_id)
            .iter()
            .any(|event| event["event"] == "workspace.published"),
        "the durable event log contains no forged publication event"
    );
    assert_closed(failed, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// T9-3: a real compiled and admitted guest calls the existing
/// `agent::approval_storage` surface with the otherwise valid `finalize`
/// operation. The fixed invalid-operation branch refuses it, the existing
/// list surface stays available, and no approval receipt or publication
/// state changes. No finalize descriptor or bridge is added.
#[tokio::test(flavor = "multi_thread")]
async fn guest_approval_storage_finalize_is_refused_without_changes() {
    let source = r#"
pub fn run(context: map) -> map {
    let run_id: string = context["run_id"];
    let session_id: string = context["session_id"];
    let finalize: map = agent::approval_storage("finalize", {
        run_id: run_id.copy(),
        session_id: session_id.copy(),
        approval_id: "forged-approval",
        decision: "approved",
        request_id: "forged-request"
    });
    let listed: map = agent::approval_storage("list", {
        run_id: run_id.copy(),
        session_id: session_id.copy()
    });
    let finalize_error: map = finalize["error"];
    let finalize_code: string = finalize_error["code"];
    let list_ok: bool = listed["ok"];
    let mut list_flag: string = "0";
    if list_ok == true {
        list_flag = "1";
    }
    { kind: "run.completed", answer: "finalize=" + finalize_code + ";list_ok=" + list_flag }
}
"#;
    let cycle = Cycle::open_guest_source(
        &format!("t16-guest-approval-{}", uuid::Uuid::new_v4().simple()),
        source,
    );
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "attempt approval finalize"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let events = tokio::time::timeout(
        Duration::from_secs(10),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .expect("guest approval run terminates");
    assert_typed_terminal(&events, "run.completed");
    let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
    assert!(
        !names.contains(&"workspace.published"),
        "an invalid approval operation must not publish: {names:?}"
    );
    let raw = http.raw_sse(&cycle.token, &run_id).await;
    let completed = raw
        .iter()
        .find(|value| value["event"] == "run.completed")
        .expect("durable run.completed payload");
    assert_eq!(
        completed["publication"]["status"], "staged",
        "the invalid operation cannot turn the completion into a publication"
    );
    assert!(completed["publication"].get("request_id").is_none());

    let messages = projected_run(&http, &cycle.token, &session_id, &run_id).await;
    assert!(
        messages.contains("finalize=approval_operation_invalid;list_ok=1"),
        "the guest observed the fixed invalid-operation refusal and a live list surface: {messages}"
    );
    let persistence = cycle.state.persistence().expect("persistence");
    let approvals = persistence
        .approval_list(&run_id, &session_id)
        .expect("approval receipt read");
    assert!(
        approvals["rows"]
            .as_array()
            .expect("approval rows")
            .is_empty(),
        "the invalid finalize operation creates no approval receipt: {approvals}"
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
    assert!(
        effects["entries"]
            .as_array()
            .expect("effect entries")
            .is_empty(),
        "the invalid approval operation creates no effect receipt: {effects}"
    );
    assert_closed(completed, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn staged_policy_completes_with_staged_branch_and_pointer_unchanged() {
    let cycle = Cycle::open(&format!("t16-staged-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("write-staged", "write_file", "staged-out.txt"));
    provider.push_ok(stop_turn("staged-done"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write the staged marker"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let branch = admitted["workspace_branch"]
        .as_str()
        .expect("managed branch")
        .to_string();
    let epoch = admitted["epoch"].as_u64().expect("managed epoch");
    assert_eq!(admitted["publication"], json!("not_published"));

    let events = tokio::time::timeout(
        Duration::from_secs(10),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "SSE never terminated; parked={}; events={:?}",
            cycle.state.service().pending_terminal_count(),
            event_names(&cycle.state, &run_id)
        )
    });
    assert_typed_terminal(&events, "run.completed");
    let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
    assert!(
        !names.contains(&"workspace.published"),
        "staged completion must not publish a workspace pointer: {names:?}"
    );
    let raw = http.raw_sse(&cycle.token, &run_id).await;
    let completed = raw
        .iter()
        .find(|value| value["event"] == "run.completed")
        .expect("durable run.completed payload");
    let publication = &completed["publication"];
    assert_eq!(publication["status"], "staged");
    assert_eq!(publication["branch_id"], json!(branch));
    assert_eq!(publication["epoch"], json!(epoch));
    assert!(
        publication.get("request_id").is_none(),
        "a staged terminal claims no publication request identity: {publication}"
    );

    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// S-1: a proven publication absence may not release the settlement owner or
/// clear the pending entry before the single failed bookkeeping terminal is
/// durable. The first bookkeeping submit is injected to fail before any row is
/// written; the run row must stay `running` with a reachable owner and pending
/// entry, then the existing janitor retry must land exactly one failed terminal
/// with no publication write.
#[tokio::test(flavor = "multi_thread")]
async fn publication_absence_keeps_owner_until_bookkeeping_terminal() {
    let cycle = Cycle::open_required(&format!("t16-absence-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    // Both one-shot Native faults are bound to the exact ops they name:
    // the claimed finalize is queued and skipped (durable absence, submitted
    // unknown), and the first proven-absence bookkeeping submit fails before
    // the worker executes it.
    persistence.inject_drop_finalize_without_apply();
    persistence.inject_fail_publication_absence_bookkeeping();
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("write-absence", "write_file", "absence-out.txt"));
    provider.push_ok(stop_turn("absence-done"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write the absence marker"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();

    // The finalize send was queued and skipped: the completion is submitted
    // unknown and parked.
    let pending_deadline = std::time::Instant::now() + Duration::from_secs(15);
    while cycle.state.service().pending_terminal_count() == 0 {
        assert!(
            std::time::Instant::now() < pending_deadline,
            "completion never parked; events={:?} pending={} run={:?}",
            event_names(&cycle.state, &run_id),
            cycle.state.service().pending_terminal_count(),
            persistence.run_get(&run_id).ok(),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // The write receipt committed before completion carries the real managed
    // workspace identity used for the pointer read below.
    let entries = run_effect_entries(&http, &cycle.token, &run_id).await;
    let workspace_id = entries
        .iter()
        .find(|entry| entry["call_id"] == "write-absence")
        .and_then(|entry| entry["workspace_id"].as_str())
        .expect("committed write receipt workspace identity")
        .to_string();
    // The first janitor settlement sees the exact completed absence and then
    // the injected bookkeeping submit failure is consumed by that exact write.
    wait_until(|| !persistence.publication_absence_bookkeeping_armed()).await;

    // S-1 negative control: the durable run is still running and the pending
    // entry plus Native owner are still reachable. No publication exists.
    let run = persistence.run_get(&run_id).expect("typed run read");
    let rows =
        rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(&run).expect("typed run rows");
    let row = rows.first().expect("one run row");
    assert_eq!(
        row.get(3).and_then(Value::as_str),
        Some("running"),
        "the failed bookkeeping submit wrote no row"
    );
    assert_eq!(
        cycle.state.service().pending_terminal_count(),
        1,
        "the pending entry must survive the failed bookkeeping submit"
    );
    assert!(
        !event_names(&cycle.state, &run_id)
            .iter()
            .any(|name| name == "run.failed" || name == "run.completed"),
        "no terminal may be fabricated before its durable row exists"
    );
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "a skipped finalize wrote no publication pointer"
    );

    // The existing janitor retry now lands exactly one failed bookkeeping
    // terminal and only then disposes the owner and clears the pending entry.
    wait_for(
        || cycle.state.service().pending_terminal_count() == 0,
        Duration::from_secs(40),
    )
    .await;
    let run = persistence.run_get(&run_id).expect("typed run read");
    let rows =
        rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(&run).expect("typed run rows");
    let row = rows.first().expect("one run row");
    assert_eq!(row.get(3).and_then(Value::as_str), Some("failed"));
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "absence must never create a publication"
    );
    let events = http.typed_sse(&cycle.token, &run_id).await;
    assert_typed_terminal(&events, "run.failed");
    assert!(
        !events
            .iter()
            .any(|event| event.name == "workspace.published"),
        "no publication event may exist for a proven absence: {events:?}"
    );
    let raw = http.raw_sse(&cycle.token, &run_id).await;
    let failed = raw
        .iter()
        .find(|value| value["event"] == "run.failed")
        .expect("durable failed bookkeeping payload");
    assert_eq!(failed["error_code"], "managed_publication_conflict");
    assert_eq!(failed["publication"]["status"], "not_published");
    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// 640 exact-one-zero-row: the required-publication transaction writes its
/// terminal events and assistant message first, then the necessary run status
/// write matches zero rows and its immediate cardinality guard rolls the whole
/// transaction back. Pointer, receipt, run status, messages and events must all
/// stay at their pre-completion values; the run fails without a publication.
#[tokio::test(flavor = "multi_thread")]
async fn required_completion_zero_row_rolls_back_entire_transaction() {
    let cycle = Cycle::open_required(&format!("t16-zero-row-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    // One-shot Native fault: the next claimed publication run status write
    // matches zero rows. Every other request stays uninjected.
    persistence.inject_finalize_zero_row();
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("write-zero", "write_file", "zero-row-out.txt"));
    provider.push_ok(stop_turn("zero-row-done"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write the zero row marker"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();

    wait_until(|| {
        event_names(&cycle.state, &run_id)
            .iter()
            .any(|name| name == "run.failed")
    })
    .await;
    let entries = run_effect_entries(&http, &cycle.token, &run_id).await;
    let workspace_id = entries
        .iter()
        .find(|entry| entry["call_id"] == "write-zero")
        .and_then(|entry| entry["workspace_id"].as_str())
        .expect("committed write receipt workspace identity")
        .to_string();
    // The transaction rolled back as a whole: no publication pointer exists.
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "the zero-row guard must roll the pointer insert back"
    );
    let run = persistence.run_get(&run_id).expect("typed run read");
    let rows =
        rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(&run).expect("typed run rows");
    let row = rows.first().expect("one run row");
    assert_eq!(
        row.get(3).and_then(Value::as_str),
        Some("failed"),
        "the durable run keeps the pre-publication failed terminal only"
    );
    // The rolled-back assistant message is absent from the session projection.
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
    assert!(
        !messages["data"]
            .as_array()
            .expect("session messages")
            .iter()
            .any(|message| message["run_id"] == json!(run_id)
                && message["id"]
                    .as_str()
                    .is_some_and(|id| id.ends_with(":finalize:message"))),
        "the transaction's finalize message insert must roll back: {messages}"
    );
    let events = http.typed_sse(&cycle.token, &run_id).await;
    assert_typed_terminal(&events, "run.failed");
    assert!(
        !events
            .iter()
            .any(|event| event.name == "workspace.published" || event.name == "run.completed"),
        "a rolled-back publication leaves no domain events: {events:?}"
    );
    let raw = http.raw_sse(&cycle.token, &run_id).await;
    let failed = raw
        .iter()
        .find(|value| value["event"] == "run.failed")
        .expect("durable failed terminal payload");
    assert_eq!(failed["error_code"], "managed_publication_conflict");
    assert_eq!(failed["publication"]["status"], "not_published");
    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// N4 pause visibility: the claimed publication completion pauses after the
/// frozen head/revision read and before the claimed terminal. While paused
/// outside commit_gate, no run terminal, no workspace.published and no durable
/// pointer may exist; releasing the pause completes exactly one publication.
#[tokio::test(flavor = "multi_thread")]
async fn required_completion_pause_is_visible_and_outside_commit_gate() {
    let cycle = Cycle::open_required(&format!("t16-pause-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("write-pause", "write_file", "pause-out.txt"));
    provider.push_ok(stop_turn("pause-done"));
    // Hold the second business response so the test can arm the one-shot
    // publication pause for this exact admitted run before completion starts.
    let gate = Arc::new(SecondBusinessGate::new(provider));
    cycle.state.service().inject_provider_host(gate.clone());
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write the pause marker"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| gate.holding()).await;
    let state = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let entered = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let hook_state = std::sync::Arc::clone(&state);
    let hook_entered = std::sync::Arc::clone(&entered);
    persistence.arm_managed_publication_precommit_pause(&run_id, move || {
        let (flag, cv) = &*hook_entered;
        *flag.lock().expect("pause entered flag") = true;
        cv.notify_all();
        let (flag, cv) = &*hook_state;
        let mut released = flag.lock().expect("pause release flag");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !*released {
            let now = std::time::Instant::now();
            assert!(now < deadline, "pause was never released");
            let (guard, _) = cv
                .wait_timeout(released, deadline.saturating_duration_since(now))
                .expect("pause wait");
            released = guard;
        }
    });
    gate.release();
    // Wait until the real completion reached the pause (the hook is called
    // outside commit_gate after the frozen head/revision read).
    let pause_deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let (flag, _) = &*entered;
        if *flag.lock().expect("pause entered flag") {
            break;
        }
        assert!(
            std::time::Instant::now() < pause_deadline,
            "pause not reached"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // While paused: no terminal, no publication event, no pointer, no pending
    // owner yet. The publication decision is not visible before its commit.
    let names = event_names(&cycle.state, &run_id);
    assert!(
        !names
            .iter()
            .any(|name| name == "run.completed" || name == "workspace.published"),
        "the paused completion must not expose a terminal or publication: {names:?}"
    );
    let entries = run_effect_entries(&http, &cycle.token, &run_id).await;
    let workspace_id = entries
        .iter()
        .find(|entry| entry["call_id"] == "write-pause")
        .and_then(|entry| entry["workspace_id"].as_str())
        .expect("committed write receipt workspace identity")
        .to_string();
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "a paused completion must not have written the pointer"
    );
    assert_eq!(cycle.state.service().pending_terminal_count(), 0);
    // Release and finish the exact same completion.
    {
        let (flag, cv) = &*state;
        *flag.lock().expect("pause release flag") = true;
        cv.notify_all();
    }
    let events = tokio::time::timeout(
        Duration::from_secs(15),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .expect("released completion terminates");
    assert_typed_terminal(&events, "run.completed");
    let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
    let published = names
        .iter()
        .position(|name| *name == "workspace.published")
        .expect("workspace.published after release");
    assert_eq!(published + 1, names.len() - 1);
    let pointer = persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("pointer read")
        .expect("released completion publishes");
    assert_eq!(pointer.revision, 1);
    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// N1/N6: a real second branch publishes through the authorized management
/// API while the first run's completion is paused after it froze the workspace
/// pointer revision. Releasing the first completion must hit the real
/// workspace-scoped pointer CAS conflict: B's exact pointer/receipt survive,
/// A's private committed branch stays, and a reopen keeps the durable failure.
#[tokio::test(flavor = "multi_thread")]
async fn second_branch_publication_while_first_completion_paused_conflicts() {
    let cycle =
        Cycle::open_required_with_publish(&format!("t16-cas-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");

    // A first, independent run publishes the workspace root branch and gives
    // the durable pointer revision and branch source CAS.
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("root-done"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, root_admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "root run"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &root_admitted));
    assert_closed(&root_admitted, &cycle.token, &hidden);
    let root_run = root_admitted["run_id"].as_str().unwrap().to_string();
    let events = tokio::time::timeout(
        Duration::from_secs(20),
        http.typed_sse(&cycle.token, &root_run),
    )
    .await
    .expect("root run terminates");
    assert_typed_terminal(&events, "run.completed");
    let raw = http.raw_sse(&cycle.token, &root_run).await;
    let root_publication = raw
        .iter()
        .find(|value| value["event"] == "run.completed")
        .and_then(|value| value.get("publication"))
        .expect("root publication document")
        .clone();
    let workspace_id = root_publication["workspace_id"]
        .as_str()
        .expect("root workspace id")
        .to_string();
    let root_branch = root_publication["branch_id"]
        .as_str()
        .expect("root branch id")
        .to_string();
    let root_epoch = root_publication["epoch"].as_u64().expect("root epoch");
    let root_head = root_publication["head_object_id"]
        .as_str()
        .expect("root head object")
        .to_string();
    let root_version = root_publication["head_version"]
        .as_u64()
        .expect("root head version");
    let root_pointer = persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("root pointer read")
        .expect("root publication pointer");
    assert_eq!(root_pointer.revision, 1);
    assert_eq!(root_pointer.branch_id, root_branch);

    // Two real branches from the exact published root head. Both are created
    // through the authorized typed branch API before A's completion starts.
    let mut branches = Vec::new();
    for tag in ["a", "b"] {
        let (status, branch) = http
            .request(
                "POST",
                &format!("/v1/workspaces/{workspace_id}/branches"),
                json!({
                    "workspace_id": workspace_id,
                    "source_branch_id": root_branch,
                    "expected_source": {
                        "store_id": root_pointer.store_id,
                        "workspace_id": workspace_id,
                        "branch_id": root_branch,
                        "epoch": root_epoch,
                        "head_object_id": root_head,
                        "head_version": root_version,
                    },
                    "request_id": uuid::Uuid::new_v4().to_string(),
                }),
                Some(&cycle.token),
                None,
            )
            .await;
        assert_eq!(status, 201, "branch {tag}: {}", explain(status, &branch));
        assert_eq!(branch["replayed"], false, "{tag}: {branch}");
        branches.push(branch["branch"].clone());
    }
    let branch_a = branches[0]["branch_id"].as_str().unwrap().to_string();
    let branch_b = branches[1]["branch_id"].as_str().unwrap().to_string();
    assert_ne!(branch_a, branch_b);

    // A writes on branch A and pauses at the exact precommit publication
    // window after freezing the initial pointer revision.
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("write-cas", "write_file", "cas-out.txt"));
    provider.push_ok(stop_turn("cas-a-final"));
    let gate = Arc::new(SecondBusinessGate::new(provider));
    cycle.state.service().inject_provider_host(gate.clone());
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "write on branch a",
                "workspace_branch": branch_a,
            }),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_a = admitted["run_id"].as_str().unwrap().to_string();
    assert_eq!(admitted["workspace_branch"], json!(branch_a));
    wait_until(|| gate.holding()).await;
    let entered = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let entered_hook = Arc::clone(&entered);
    let release_hook = Arc::clone(&release);
    persistence.arm_managed_publication_precommit_pause(&run_a, move || {
        let (flag, cv) = &*entered_hook;
        *flag.lock().expect("pause entered") = true;
        cv.notify_all();
        let (flag, cv) = &*release_hook;
        let mut released = flag.lock().expect("pause release");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !*released {
            let now = std::time::Instant::now();
            assert!(now < deadline, "CAS pause was never released");
            let (guard, _) = cv
                .wait_timeout(released, deadline.saturating_duration_since(now))
                .expect("CAS pause wait");
            released = guard;
        }
    });
    gate.release();
    let pause_deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let (flag, _) = &*entered;
        if *flag.lock().expect("pause entered") {
            break;
        }
        assert!(
            std::time::Instant::now() < pause_deadline,
            "CAS pause not reached"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // B publishes at its real head through the same authorized management API.
    // This advances the workspace pointer while A's frozen expectation is still
    // revision 1.
    let request_b = uuid::Uuid::new_v4().to_string();
    let (status, published) = http
        .request(
            "POST",
            &format!("/v1/workspaces/{workspace_id}/publish"),
            json!({
                "workspace_id": workspace_id,
                "branch_id": branch_b,
                "expected_head": {
                    "workspace_id": workspace_id,
                    "branch_id": branch_b,
                    "epoch": branches[1]["epoch"],
                    "head_object_id": branches[1]["head_object_id"],
                    "head_version": branches[1]["head_version"],
                    "store_id": branches[1]["store_id"],
                    "schema_version": 1,
                    "process_lineage_tainted": false,
                },
                "request_id": request_b,
            }),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(
        status,
        200,
        "branch B publish: {}",
        explain(status, &published)
    );
    assert_eq!(published["status"], "committed");
    let pointer_b = persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("B pointer read")
        .expect("B publication pointer");
    assert_eq!(pointer_b.branch_id, branch_b);
    assert_eq!(pointer_b.request_id, request_b);
    assert_eq!(pointer_b.revision, 2, "B advanced the workspace pointer");

    {
        let (flag, cv) = &*release;
        *flag.lock().expect("pause release") = true;
        cv.notify_all();
    }
    let events = tokio::time::timeout(
        Duration::from_secs(20),
        http.typed_sse(&cycle.token, &run_a),
    )
    .await
    .expect("CAS conflict terminates");
    assert_typed_terminal(&events, "run.failed");
    assert!(
        !events
            .iter()
            .any(|event| event.name == "workspace.published" || event.name == "run.completed"),
        "a stale pointer revision must not publish: {events:?}"
    );
    let failed = http
        .raw_sse(&cycle.token, &run_a)
        .await
        .into_iter()
        .find(|value| value["event"] == "run.failed")
        .expect("durable CAS failure payload");
    assert_eq!(failed["error_code"], "managed_publication_conflict");
    assert_eq!(
        failed["publication"]["status"], "not_published",
        "the stale-revision CAS aborted the transaction, so the ordered absence is typed not_published: {failed}"
    );
    assert_eq!(
        failed["error_message"], "required publication absence proven after the original deadline",
        "the CAS failure is settled from a durable absence, not a timeout: {failed}"
    );

    // B's pointer and receipt fields are untouched by A's failed completion.
    let pointer_after = persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("post-CAS pointer read")
        .expect("B pointer survives");
    assert_eq!(pointer_after.branch_id, branch_b);
    assert_eq!(pointer_after.epoch, branches[1]["epoch"].as_u64().unwrap());
    assert_eq!(
        pointer_after.head_object_id,
        branches[1]["head_object_id"].as_str().unwrap()
    );
    assert_eq!(
        pointer_after.head_version,
        branches[1]["head_version"].as_u64().unwrap()
    );
    assert_eq!(pointer_after.request_id, request_b);
    assert_eq!(pointer_after.revision, 2);

    // A's own branch receipt, precompletion messages and effect receipt stay;
    // only the uncommitted publication message may be absent.
    let entries = run_effect_entries(&http, &cycle.token, &run_a).await;
    let entry = entries
        .iter()
        .find(|entry| entry["call_id"] == "write-cas")
        .expect("A private branch write receipt survives");
    assert_eq!(entry["branch_id"], json!(branch_a));
    assert_eq!(entry["workspace_id"], json!(workspace_id));
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
    assert!(
        messages["data"]
            .as_array()
            .expect("session messages")
            .iter()
            .any(|message| message["run_id"] == json!(run_a)
                && message.to_string().contains("write-cas")),
        "the provider/tool message history stays readable"
    );
    assert!(
        !messages["data"]
            .as_array()
            .expect("session messages")
            .iter()
            .any(|message| message["run_id"] == json!(run_a)
                && message["id"]
                    .as_str()
                    .is_some_and(|id| id.ends_with(":finalize:message"))),
        "the uncommitted publication message is not inserted"
    );
    let run = persistence.run_get(&run_a).expect("A typed run read");
    let rows =
        rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(&run).expect("A typed run rows");
    let row = rows.first().expect("one run row");
    assert_eq!(row.get(3).and_then(Value::as_str), Some("failed"));

    // Reopen the existing durable root: the CAS failure and B's publication
    // pointer are still the durable truth.
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
    let reopened = cycle.reopen();
    let reopened_persistence = reopened.state.persistence().expect("reopened persistence");
    let reopened_pointer = reopened_persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("reopened pointer read")
        .expect("B pointer after reopen");
    assert_eq!(reopened_pointer.branch_id, branch_b);
    assert_eq!(reopened_pointer.request_id, request_b);
    assert_eq!(reopened_pointer.revision, 2);
    let reopened_run = reopened_persistence
        .run_get(&run_a)
        .expect("reopened run read");
    let reopened_rows = rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(&reopened_run)
        .expect("reopened run rows");
    let reopened_row = reopened_rows.first().expect("one reopened run row");
    assert_eq!(
        reopened_row.get(3).and_then(Value::as_str),
        Some("failed"),
        "the durable CAS failure survives reopen"
    );
    shutdown_when_idle(&reopened.state).await;
}

/// T2 same store: the genuine installed/captured graph is revoked through the
/// same registered control store object while the run is paused at precommit.
/// Its durable tombstone precedes the release and the run must not publish.
#[tokio::test(flavor = "multi_thread")]
async fn same_store_graph_revoke_at_precommit_blocks_publication() {
    let cycle = Cycle::open_required_with_library(&format!(
        "t16-graph-revoke-same-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_package(&http, &cycle.token, LIBRARY_LEAF_DIR).await;
    install_package(&http, &cycle.token, LIBRARY_TOOL_DIR).await;
    let (graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        LIBRARY_TOOL_ID,
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    std::fs::write(cycle.workspace.join("note.txt"), b"hello").unwrap();
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("read-revoke-same", "read_file", "note.txt"));
    provider.push_ok(stop_turn("same-store-final"));
    let gate = Arc::new(SecondBusinessGate::new(provider));
    cycle.state.service().inject_provider_host(gate.clone());
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "read before same-store revoke"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| gate.holding()).await;
    let entered = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let entered_hook = Arc::clone(&entered);
    let release_hook = Arc::clone(&release);
    persistence.arm_managed_publication_precommit_pause(&run_id, move || {
        let (flag, cv) = &*entered_hook;
        *flag.lock().expect("pause entered") = true;
        cv.notify_all();
        let (flag, cv) = &*release_hook;
        let mut released = flag.lock().expect("pause release");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !*released {
            let now = std::time::Instant::now();
            assert!(now < deadline, "same-store pause was never released");
            let (guard, _) = cv
                .wait_timeout(released, deadline.saturating_duration_since(now))
                .expect("same-store pause wait");
            released = guard;
        }
    });
    gate.release();
    let pause_deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let (flag, _) = &*entered;
        if *flag.lock().expect("pause entered") {
            break;
        }
        assert!(
            std::time::Instant::now() < pause_deadline,
            "pause not reached"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Same persistence object, same registered control store; the real
    // installed package store resolves the captured graph.
    let control = rustscript_agent::plugins::PluginControlStore::new(&persistence);
    assert_eq!(
        control.graph_revocation(&graph).expect("pre-revoke lookup"),
        None
    );
    let revocation = control
        .revoke_graph(
            &cycle
                .state
                .service()
                .managed_tool_store_for_test()
                .expect("trusted package store"),
            &graph,
        )
        .expect("durable same-store graph revoke");
    assert_eq!(revocation.graph_id, graph);
    assert!(
        control
            .graph_revocation(&graph)
            .expect("durable revocation read")
            .is_some(),
        "the revoke is durably observable before A is released"
    );

    {
        let (flag, cv) = &*release;
        *flag.lock().expect("pause release") = true;
        cv.notify_all();
    }
    let events = tokio::time::timeout(
        Duration::from_secs(25),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .expect("revoked run terminates");
    let terminal = events
        .iter()
        .find(|event| event.terminal)
        .expect("one terminal")
        .name
        .clone();
    assert_eq!(
        terminal, "run.cancelled",
        "the same-store listener cancels the run instead of completing it"
    );
    assert!(
        !events
            .iter()
            .any(|event| event.name == "workspace.published" || event.name == "run.completed"),
        "same-store revoke must not publish: {events:?}"
    );
    let entries = run_effect_entries(&http, &cycle.token, &run_id).await;
    let workspace_id = entries
        .iter()
        .find(|entry| entry["call_id"] == "read-revoke-same")
        .and_then(|entry| entry["workspace_id"].as_str())
        .expect("committed write receipt workspace identity")
        .to_string();
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "revoked graph must not write a publication pointer"
    );
    let run = persistence.run_get(&run_id).expect("typed run read");
    let rows =
        rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(&run).expect("typed run rows");
    let row = rows.first().expect("one run row");
    let status_after = row.get(3).and_then(Value::as_str);
    assert_eq!(
        status_after,
        Some("cancelled"),
        "the durable same-store revoked run is cancelled"
    );
    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// T2 second store: the same backing persistence is opened through the
/// supported typed constructor as a second store object without the first
/// store's in-memory revocation listener. The durable precommit guard alone
/// must defeat the paused publication after the real revoke acknowledgement.
#[tokio::test(flavor = "multi_thread")]
async fn second_store_graph_revoke_at_precommit_uses_durable_guard() {
    let cycle = Cycle::open_required_with_library(&format!(
        "t16-graph-revoke-second-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_package(&http, &cycle.token, LIBRARY_LEAF_DIR).await;
    install_package(&http, &cycle.token, LIBRARY_TOOL_DIR).await;
    let (graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        LIBRARY_TOOL_ID,
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    std::fs::write(cycle.workspace.join("note.txt"), b"hello").unwrap();
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("read-revoke-second", "read_file", "note.txt"));
    provider.push_ok(stop_turn("second-store-final"));
    let gate = Arc::new(SecondBusinessGate::new(provider));
    cycle.state.service().inject_provider_host(gate.clone());
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "read before second-store revoke"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| gate.holding()).await;
    let entered = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let entered_hook = Arc::clone(&entered);
    let release_hook = Arc::clone(&release);
    persistence.arm_managed_publication_precommit_pause(&run_id, move || {
        let (flag, cv) = &*entered_hook;
        *flag.lock().expect("pause entered") = true;
        cv.notify_all();
        let (flag, cv) = &*release_hook;
        let mut released = flag.lock().expect("pause release");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !*released {
            let now = std::time::Instant::now();
            assert!(now < deadline, "second-store pause was never released");
            let (guard, _) = cv
                .wait_timeout(released, deadline.saturating_duration_since(now))
                .expect("second-store pause wait");
            released = guard;
        }
    });
    gate.release();
    let pause_deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let (flag, _) = &*entered;
        if *flag.lock().expect("pause entered") {
            break;
        }
        assert!(
            std::time::Instant::now() < pause_deadline,
            "pause not reached"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Supported typed second open of the same file, not a manual SQLite
    // connection. This object is intentionally not the registered store and
    // therefore cannot deliver the in-memory revoke notice.
    let second = rustscript_agent::GatewayPersistence::open(&cycle.config, &cycle.db)
        .expect("second typed persistence");
    let second_control = rustscript_agent::plugins::PluginControlStore::new(&second);
    assert_eq!(
        second_control
            .graph_revocation(&graph)
            .expect("second-store pre-revoke lookup"),
        None
    );
    let revocation = second_control
        .revoke_graph(
            &cycle
                .state
                .service()
                .managed_tool_store_for_test()
                .expect("trusted package store"),
            &graph,
        )
        .expect("durable second-store graph revoke");
    assert_eq!(revocation.graph_id, graph);
    assert!(
        second_control
            .graph_revocation(&graph)
            .expect("second-store durable read")
            .is_some(),
        "the durable revoke is observable through the second store before release"
    );
    assert!(
        !event_names(&cycle.state, &run_id)
            .iter()
            .any(|name| name == "run.failed" || name == "run.cancelled"),
        "the second store must not deliver the first store's in-memory cancellation"
    );

    {
        let (flag, cv) = &*release;
        *flag.lock().expect("pause release") = true;
        cv.notify_all();
    }
    let events = tokio::time::timeout(
        Duration::from_secs(25),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .expect("durable-guard run terminates");
    let terminal = events
        .iter()
        .find(|event| event.terminal)
        .expect("one terminal")
        .name
        .clone();
    assert_eq!(
        terminal, "run.failed",
        "the second-store durable guard fails the run without an in-memory notice"
    );
    assert!(
        !events
            .iter()
            .any(|event| event.name == "workspace.published" || event.name == "run.completed"),
        "the durable graph tombstone must not publish: {events:?}"
    );
    let entries = run_effect_entries(&http, &cycle.token, &run_id).await;
    let workspace_id = entries
        .iter()
        .find(|entry| entry["call_id"] == "read-revoke-second")
        .and_then(|entry| entry["workspace_id"].as_str())
        .expect("committed read receipt workspace identity")
        .to_string();
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "the second-store durable guard must not write a publication pointer"
    );
    let run = persistence.run_get(&run_id).expect("typed run read");
    let rows =
        rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(&run).expect("typed run rows");
    let row = rows.first().expect("one run row");
    let status_after = row.get(3).and_then(Value::as_str);
    assert_eq!(
        status_after,
        Some("failed"),
        "the durable second-store revoked run is failed"
    );
    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// T3: a real publication receipt and pointer are durable before the same
/// installed graph is revoked. Revocation must not roll back published history;
/// a later admission pinning the old graph is refused.
#[tokio::test(flavor = "multi_thread")]
async fn publish_then_graph_revoke_keeps_receipt_and_denies_old_pin() {
    let cycle = Cycle::open_required_with_library(&format!(
        "t16-publish-revoke-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_package(&http, &cycle.token, LIBRARY_LEAF_DIR).await;
    install_package(&http, &cycle.token, LIBRARY_TOOL_DIR).await;
    let (graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        LIBRARY_TOOL_ID,
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("publish-before-revoke"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "publish before revoke"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let events = tokio::time::timeout(
        Duration::from_secs(25),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .expect("published run terminates");
    assert_typed_terminal(&events, "run.completed");
    let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
    assert!(
        names.contains(&"workspace.published"),
        "required completion published first: {names:?}"
    );
    let raw = http.raw_sse(&cycle.token, &run_id).await;
    let completed = raw
        .iter()
        .find(|value| value["event"] == "run.completed")
        .expect("durable completion payload");
    let publication = completed["publication"].clone();
    assert_eq!(publication["status"], "committed");
    let workspace_id = publication["workspace_id"]
        .as_str()
        .expect("publication workspace id")
        .to_string();
    let request_id = publication["request_id"]
        .as_str()
        .expect("publication request id")
        .to_string();
    let pointer_before = persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("pre-revoke pointer read")
        .expect("published pointer");
    assert_eq!(pointer_before.request_id, request_id);
    assert_eq!(pointer_before.revision, 1);
    assert_eq!(
        pointer_before.head_object_id,
        publication["head_object_id"].as_str().unwrap()
    );
    assert_eq!(
        pointer_before.head_version,
        publication["head_version"].as_u64().unwrap()
    );
    let run_before = persistence.run_get(&run_id).expect("pre-revoke run read");
    let rows = rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(&run_before)
        .expect("pre-revoke run rows");
    let row = rows.first().expect("one pre-revoke run row");
    assert_eq!(row.get(3).and_then(Value::as_str), Some("completed"));

    // Revoke the same genuine installed graph after the publication is durable.
    let control = rustscript_agent::plugins::PluginControlStore::new(&persistence);
    let revocation = control
        .revoke_graph(
            &cycle
                .state
                .service()
                .managed_tool_store_for_test()
                .expect("trusted package store"),
            &graph,
        )
        .expect("post-publication graph revoke");
    assert_eq!(revocation.graph_id, graph);
    assert!(
        control
            .graph_revocation(&graph)
            .expect("post-publication revocation read")
            .is_some()
    );

    // Nothing rolls back: the pointer, receipt identity and completed run stay.
    let pointer_after = persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("post-revoke pointer read")
        .expect("published pointer survives revocation");
    assert_eq!(pointer_after.request_id, request_id);
    assert_eq!(pointer_after.branch_id, pointer_before.branch_id);
    assert_eq!(pointer_after.epoch, pointer_before.epoch);
    assert_eq!(pointer_after.head_object_id, pointer_before.head_object_id);
    assert_eq!(pointer_after.head_version, pointer_before.head_version);
    assert_eq!(pointer_after.revision, 1, "no revision rollback");
    let run_after = persistence.run_get(&run_id).expect("post-revoke run read");
    let rows = rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(&run_after)
        .expect("post-revoke run rows");
    let row = rows.first().expect("one post-revoke run row");
    assert_eq!(row.get(3).and_then(Value::as_str), Some("completed"));
    let replay = http.raw_sse(&cycle.token, &run_id).await;
    let completed_after = replay
        .iter()
        .find(|value| value["event"] == "run.completed")
        .expect("completed terminal remains readable");
    assert_eq!(completed_after["publication"], publication);

    // A later admission that pins this old graph is denied before execution.
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("must-not-run"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, denied) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "old pin after revoke",
                "graph_id": graph,
            }),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 409, "{}", explain(status, &denied));
    assert_eq!(denied["error"]["code"], "plugin_graph_revoked");
    assert!(
        denied.get("run_id").is_none(),
        "a revoked old pin creates no run: {denied}"
    );
    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// Registration-branch foreign contrast: a real branch is created in another
/// workspace through the same persistent domain and a valid owner identity, then
/// selected from the original workspace through the current `workspace_branch`
/// admission. The branch origin must be genuinely foreign, while the original
/// workspace's own branch admission stays positive.
#[tokio::test(flavor = "multi_thread")]
async fn admission_rejects_a_real_foreign_workspace_branch() {
    let cycle = Cycle::open_required_with_library(&format!(
        "t16-branch-foreign-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let http = Http::bind(cycle.state.clone()).await;
    install_package(&http, &cycle.token, LIBRARY_LEAF_DIR).await;
    install_package(&http, &cycle.token, LIBRARY_TOOL_DIR).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        LIBRARY_TOOL_ID,
    )
    .await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_a = session["session"]["id"].as_str().unwrap().to_string();
    http.close().await;
    shutdown_when_idle(&cycle.state).await;

    // Open the second real workspace on the same database and home with the
    // same configured bearer and package policy.
    let Cycle {
        root: _root,
        workspace,
        second_workspace,
        home,
        source,
        db,
        token,
        config,
        auth,
        state,
    } = cycle;
    drop(state);
    let mut b_config = config.clone();
    b_config
        .managed_workspace
        .as_mut()
        .expect("managed workspace")
        .source_root = second_workspace.clone();
    let b_state = rustscript_agent::AgentGatewayState::with_sqlite_path(b_config, &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth.clone(), source.clone(), "owner-space")
        .unwrap();
    let b_http = Http::bind(b_state.clone()).await;
    let (status, session_b) = b_http
        .request("POST", "/api/sessions", json!({}), Some(&token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session_b));
    let session_b = session_b["session"]["id"].as_str().unwrap().to_string();
    let (status, bound) = b_http
        .request(
            "POST",
            &format!("/v1/sessions/{session_b}/workspace"),
            json!({"workspace": second_workspace.display().to_string()}),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &bound));
    let (status, view) = b_http
        .request(
            "GET",
            &format!("/api/sessions/{session_b}"),
            json!(null),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &view));
    assert_eq!(
        view["session"]["workspace"]["canonical_path"],
        json!(
            second_workspace
                .canonicalize()
                .unwrap()
                .display()
                .to_string()
        ),
        "the second session is really bound to the second workspace: {view}"
    );
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("workspace-b-done"));
    b_state.service().inject_provider_host(Arc::new(provider));
    let (status, admitted_b) = b_http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_b, "input": "create workspace b branch"}),
            Some(&token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted_b));
    let run_b = admitted_b["run_id"].as_str().unwrap().to_string();
    let branch_b = admitted_b["workspace_branch"]
        .as_str()
        .expect("workspace B active branch")
        .to_string();
    let events = tokio::time::timeout(Duration::from_secs(20), b_http.typed_sse(&token, &run_b))
        .await
        .expect("workspace B run terminates");
    assert_typed_terminal(&events, "run.completed");
    let raw_b = b_http.raw_sse(&token, &run_b).await;
    let publication_b = raw_b
        .iter()
        .find(|value| value["event"] == "run.completed")
        .and_then(|value| value.get("publication"))
        .expect("workspace B publication");
    let workspace_b_id = publication_b["workspace_id"]
        .as_str()
        .expect("workspace B id")
        .to_string();
    assert_eq!(publication_b["branch_id"], json!(branch_b));
    b_http.close().await;
    shutdown_when_idle(&b_state).await;
    drop(b_state);

    // Reopen the original workspace on the same durable root and bearer.
    let a_state = rustscript_agent::AgentGatewayState::with_sqlite_path(config, &db)
        .unwrap()
        .with_workspace_home(&home)
        .with_plugin_control(auth, source.clone(), "owner-space")
        .unwrap();
    let a_http = Http::bind(a_state.clone()).await;
    // The original workspace's registration/root branch admission stays
    // positive before the foreign probe.
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("workspace-a-root"));
    a_state.service().inject_provider_host(Arc::new(provider));
    let (status, positive) = a_http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_a, "input": "workspace A root stays positive"}),
            Some(&token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &positive));
    let run_a = positive["run_id"].as_str().unwrap().to_string();
    let events = tokio::time::timeout(Duration::from_secs(20), a_http.typed_sse(&token, &run_a))
        .await
        .expect("workspace A positive run terminates");
    assert_typed_terminal(&events, "run.completed");
    let raw_a = a_http.raw_sse(&token, &run_a).await;
    let workspace_a_id = raw_a
        .iter()
        .find(|value| value["event"] == "run.completed")
        .and_then(|value| value.get("publication"))
        .and_then(|publication| publication.get("workspace_id"))
        .and_then(Value::as_str)
        .expect("workspace A id")
        .to_string();
    assert_ne!(workspace_a_id, workspace_b_id);

    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("foreign-must-not-run"));
    a_state.service().inject_provider_host(Arc::new(provider));
    let (status, foreign) = a_http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_a,
                "input": "select workspace B branch from workspace A",
                "workspace_branch": branch_b,
            }),
            Some(&token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 403, "{}", explain(status, &foreign));
    assert_eq!(foreign["error"]["code"], "managed_authority_required");
    assert!(
        foreign.get("run_id").is_none(),
        "a foreign branch creates no run: {foreign}"
    );
    assert!(
        !foreign.to_string().contains(&branch_b),
        "the refusal must not echo the foreign branch identity"
    );
    assert_closed(&positive, &token, &[workspace.as_path()]);
    a_http.close().await;
    shutdown_when_idle(&a_state).await;
}

/// T1: the exact captured `WorkspaceAuthority` is revoked after guest
/// quiescence and before the completion writer permit is minted, through its
/// existing Native revoke method. The revalidation must refuse the permit:
/// no publication pointer, no workspace.published, the original admission clock
/// and the retained branch owner stay unchanged, and the run fails closed.
#[tokio::test(flavor = "multi_thread")]
async fn workspace_authority_revoke_between_quiescence_and_mint_refuses_publication() {
    let cycle = Cycle::open_required(&format!(
        "t16-workspace-revoke-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("write-t1", "write_file", "t1-out.txt"));
    provider.push_ok(stop_turn("t1-must-not-publish"));
    let gate = Arc::new(SecondBusinessGate::new(provider));
    cycle.state.service().inject_provider_host(gate.clone());
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write the t1 marker"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| gate.holding()).await;
    let pre_revoke = cycle
        .state
        .service()
        .managed_run_authority_state(&run_id)
        .expect("captured run authority");
    assert!(
        !pre_revoke.0,
        "the admitted authority must not be revoked before the explicit hook: {pre_revoke:?}"
    );

    let before_deadline = cycle
        .state
        .service()
        .managed_run_deadline_instant(&run_id)
        .expect("the admitted run's original clock");

    type RevokeObservation =
        Arc<std::sync::Mutex<Option<(Option<std::time::Instant>, Option<String>, bool)>>>;
    let observed: RevokeObservation = Arc::new(std::sync::Mutex::new(None));
    let hook_observed = Arc::clone(&observed);
    let hook_service = cycle.state.service();
    let hook_run = run_id.clone();
    let hook_before_deadline = before_deadline;
    cycle
        .state
        .persistence()
        .expect("persistence")
        .arm_managed_completion_quiescence_pause(&run_id, move || {
            let revoked = hook_service.revoke_managed_run_workspace_authority(&hook_run);
            let deadline = hook_service.managed_run_deadline_instant(&hook_run);
            let owner = hook_service.managed_run_completion_owner(&hook_run);
            assert_eq!(
                deadline,
                Some(hook_before_deadline),
                "the revoke must not replace the original admission clock"
            );
            assert_eq!(
                owner.as_deref(),
                Some(hook_run.as_str()),
                "the revoke must not mint or replace the branch completion owner"
            );
            *hook_observed.lock().expect("revoke observation") = Some((deadline, owner, revoked));
        });
    gate.release();
    let events = tokio::time::timeout(
        Duration::from_secs(25),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .expect("revoked completion terminates");
    assert_typed_terminal(&events, "run.failed");
    assert!(
        !events
            .iter()
            .any(|event| event.name == "workspace.published" || event.name == "run.completed"),
        "a revoked workspace authority must not publish: {events:?}"
    );
    let (deadline, owner, revoked) = observed
        .lock()
        .expect("revoke observation")
        .clone()
        .expect("the quiescence hook really ran");
    assert!(
        revoked,
        "the exact captured authority must refuse its own check"
    );
    assert_eq!(deadline, Some(before_deadline));
    assert_eq!(owner, Some(run_id.clone()));
    assert_eq!(
        cycle.state.service().managed_run_completion_owner(&run_id),
        Some(run_id.clone()),
        "the failed permit keeps the original branch owner"
    );

    let entries = run_effect_entries(&http, &cycle.token, &run_id).await;
    let entry = entries
        .iter()
        .find(|entry| entry["call_id"] == "write-t1")
        .expect("the committed write receipt survives the refused completion");
    let workspace_id = entry["workspace_id"]
        .as_str()
        .expect("committed write receipt workspace identity")
        .to_string();
    assert_eq!(
        cycle
            .state
            .persistence()
            .expect("persistence")
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "a revoked workspace authority must not write a publication pointer"
    );
    let run = cycle
        .state
        .persistence()
        .expect("persistence")
        .run_get(&run_id)
        .expect("typed run read");
    let rows =
        rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(&run).expect("typed run rows");
    let row = rows.first().expect("one run row");
    assert_eq!(row.get(3).and_then(Value::as_str), Some("failed"));
    let raw = http.raw_sse(&cycle.token, &run_id).await;
    let failed = raw
        .iter()
        .find(|value| value["event"] == "run.failed")
        .expect("durable failed terminal payload");
    assert_eq!(failed["error_code"], "managed_publication_conflict");
    assert_eq!(failed["publication"]["status"], "conflict");
    // The prior provider turn, messages and write receipt stay intact; only the
    // uncommitted final assistant is absent.
    let names = event_names(&cycle.state, &run_id);
    assert!(
        names.iter().any(|name| name == "model.completed"),
        "{names:?}"
    );
    assert!(names.iter().any(|name| name.contains("tool")), "{names:?}");
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
    assert!(
        messages["data"]
            .as_array()
            .expect("session messages")
            .iter()
            .any(|message| message["run_id"] == json!(run_id)
                && message.to_string().contains("write-t1")),
        "the committed tool-call message stays readable"
    );
    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// D7 real producer projection: the existing Telegram session producer creates
/// the live synthetic telegram-addressed session, then the same exact id is
/// admitted under the gateway workspace principal. This reaches the real
/// managed admission/publication path rather than an arbitrary missing-memory
/// row, with a normal gateway session as the projection control.
#[tokio::test(flavor = "multi_thread")]
async fn live_telegram_addressed_session_reaches_managed_admission() {
    let cycle =
        Cycle::open_required_with_library(&format!("t16-d7-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_package(&http, &cycle.token, LIBRARY_LEAF_DIR).await;
    install_package(&http, &cycle.token, LIBRARY_TOOL_DIR).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        LIBRARY_TOOL_ID,
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    let session_id = cycle
        .state
        .ensure_telegram_session_for_test("synthetic-account", 424242, Some(7), "77")
        .await
        .expect("the existing telegram producer creates a live session");
    let (status, view) = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &view));
    assert_eq!(
        view["session"]["source"], "telegram",
        "the live projection carries the real telegram address producer value: {view}"
    );

    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("telegram-live-done"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "live telegram addressed admission",
            }),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(
        status, 202,
        "the live telegram-addressed session reaches managed admission: {admitted}"
    );
    let run_id = admitted["run_id"]
        .as_str()
        .expect("admitted run")
        .to_string();
    let events = tokio::time::timeout(
        Duration::from_secs(25),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .expect("telegram-addressed run terminates");
    assert_typed_terminal(&events, "run.completed");
    let raw = http.raw_sse(&cycle.token, &run_id).await;
    let completed = raw
        .iter()
        .find(|value| value["event"] == "run.completed")
        .expect("durable completion payload");
    let publication = &completed["publication"];
    let branch = publication["branch_id"]
        .as_str()
        .expect("publication branch")
        .to_string();
    let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
    assert!(
        names.contains(&"workspace.published"),
        "the legitimate admission publishes under the gateway principal: {names:?}"
    );
    assert_eq!(publication["status"], "committed");
    assert_eq!(publication["branch_id"], json!(branch));
    let workspace_id = publication["workspace_id"]
        .as_str()
        .expect("publication workspace")
        .to_string();
    let pointer = persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("pointer read")
        .expect("legitimate publication pointer");
    assert_eq!(publication["request_id"], json!(pointer.request_id));
    assert_eq!(pointer.branch_id, branch);
    assert_eq!(pointer.revision, 1);

    // Projection control: a normal gateway session on the same service still
    // admits and publishes, so the telegram producer path is not misclassified
    // by a broken gateway projection.
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("gateway-control-done"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, gateway_session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &gateway_session));
    let gateway_session = gateway_session["session"]["id"]
        .as_str()
        .expect("gateway session")
        .to_string();
    let (status, control) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": gateway_session, "input": "gateway projection control"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &control));
    let control_run = control["run_id"].as_str().expect("control run").to_string();
    let control_events = tokio::time::timeout(
        Duration::from_secs(25),
        http.typed_sse(&cycle.token, &control_run),
    )
    .await
    .expect("gateway control terminates");
    assert_typed_terminal(&control_events, "run.completed");
    let control_pointer = persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("control pointer read")
        .expect("control publication pointer");
    assert_eq!(control_pointer.revision, 2);
    assert_ne!(control_pointer.request_id, pointer.request_id);
    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// Registration/root branch identity: explicit `workspace_branch` selection of
/// the workspace's own registration branch is an authorized local/root choice,
/// while an active branch id that is not part of this workspace stays refused.
#[tokio::test(flavor = "multi_thread")]
async fn explicit_registration_branch_is_authorized_and_unknown_branch_stays_refused() {
    let cycle = Cycle::open_required(&format!(
        "t16-branch-origin-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("branch-origin-first"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, first) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "first registration run"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &first));
    let branch = first["workspace_branch"]
        .as_str()
        .expect("managed registration branch")
        .to_string();
    let first_run = first["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&cycle.state, &first_run)
            .iter()
            .any(|name| name == "run.completed")
    })
    .await;

    // Explicit selection of the registration/root branch is authorized.
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("branch-origin-second"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, second) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "explicit registration branch run",
                "workspace_branch": branch,
            }),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &second));
    assert_eq!(second["workspace_branch"], json!(branch));
    let second_run = second["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        event_names(&cycle.state, &second_run)
            .iter()
            .any(|name| name == "run.completed" || name == "run.cancelled" || name == "run.failed")
    })
    .await;

    // An unknown branch id never becomes a local root.
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("branch-origin-third"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, unknown) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "unknown branch run",
                "workspace_branch": "br-00000000000000000000000000000000",
            }),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_ne!(status, 202, "{}", explain(status, &unknown));
    assert_eq!(
        unknown["error"]["code"], "managed_branch_missing",
        "an unknown branch stays fail-closed: {unknown}"
    );
    assert_closed(&first, &cycle.token, &hidden);
    assert_closed(&second, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// T6: a successful finalize send whose acknowledgement is lost stays
/// submitted-unknown; the same-worker ordered settlement finds the exact
/// receipt, applies the frozen request (one revision advance) and never re-sends
/// or mints a second publication identity.
#[tokio::test(flavor = "multi_thread")]
async fn lost_finalize_ack_settles_exact_receipt_without_resend() {
    let cycle = Cycle::open_required(&format!("t16-ack-loss-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    persistence.inject_drop_finalize_ack();
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("write-ack", "write_file", "ack-out.txt"));
    provider.push_ok(stop_turn("ack-done"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write the ack marker"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    // The outermost send succeeded, so one terminal is registered as pending
    // and later settled from the ordered FIFO receipt.
    let events = tokio::time::timeout(
        Duration::from_secs(20),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .expect("settled completion terminates");
    assert_typed_terminal(&events, "run.completed");
    let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
    let published = names
        .iter()
        .position(|name| *name == "workspace.published")
        .expect("workspace.published after an acknowledged-loss settlement");
    assert_eq!(published + 1, names.len() - 1);
    assert_eq!(
        names
            .iter()
            .filter(|name| **name == "workspace.published")
            .count(),
        1,
        "the settlement must not send a second publication event: {names:?}"
    );
    let raw = http.raw_sse(&cycle.token, &run_id).await;
    let completion = raw
        .iter()
        .find(|value| value["event"] == "run.completed")
        .expect("durable completion payload");
    let request_id = completion["publication"]["request_id"]
        .as_str()
        .expect("frozen request identity")
        .to_string();
    assert_eq!(completion["publication"]["status"], "committed");
    let entries = run_effect_entries(&http, &cycle.token, &run_id).await;
    let workspace_id = entries
        .iter()
        .find(|entry| entry["call_id"] == "write-ack")
        .and_then(|entry| entry["workspace_id"].as_str())
        .expect("committed write receipt workspace identity")
        .to_string();
    let pointer = persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("pointer read")
        .expect("settled receipt publishes a pointer");
    assert_eq!(pointer.request_id, request_id);
    assert_eq!(pointer.revision, 1, "one revision advance only");
    assert_eq!(cycle.state.service().pending_terminal_count(), 0);
    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// T8: a parked settlement reply is delivered past the existing five-second
/// metadata budget while the sole storage worker stays free. The timeout keeps
/// the pending owner reachable; the later ordered absence then lands exactly one
/// failed bookkeeping terminal and never a publication.
#[tokio::test(flavor = "multi_thread")]
async fn deferred_settlement_reply_times_out_with_owner_retained_and_worker_free() {
    let cycle = Cycle::open_required(&format!(
        "t16-settle-timeout-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    persistence.inject_drop_finalize_without_apply();
    persistence.inject_defer_finalize_settle_reply();
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("write-settle", "write_file", "settle-out.txt"));
    provider.push_ok(stop_turn("settle-done"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write the settle marker"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| cycle.state.service().pending_terminal_count() > 0).await;
    // The retention window opens at the first observable pending owner, before
    // the HTTP read below. That parked entry is what must survive the original
    // five-second budget; the later read only proves the worker is free.
    let retained_since = std::time::Instant::now();
    // The deferred settlement reply is held past its budget. The single storage
    // worker has already executed the read-only snapshot and is free: an
    // ordinary typed effects read must return promptly inside the same window.
    let read_started = std::time::Instant::now();
    let entries = run_effect_entries(&http, &cycle.token, &run_id).await;
    assert!(
        read_started.elapsed() < Duration::from_secs(4),
        "the deferred reply must not hold the sole storage worker"
    );
    let workspace_id = entries
        .iter()
        .find(|entry| entry["call_id"] == "write-settle")
        .and_then(|entry| entry["workspace_id"].as_str())
        .expect("committed write receipt workspace identity")
        .to_string();
    // The five-second metadata budget elapses while the pending entry and the
    // Native owner stay reachable; the timeout itself fabricates no terminal.
    let clear_deadline = retained_since + Duration::from_secs(40);
    while cycle.state.service().pending_terminal_count() > 0 {
        assert!(
            std::time::Instant::now() < clear_deadline,
            "pending owner was never settled after the timeout"
        );
        assert!(
            !event_names(&cycle.state, &run_id)
                .iter()
                .any(|name| name == "run.failed" || name == "run.completed"),
            "the timeout itself must not fabricate a terminal"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        retained_since.elapsed() >= Duration::from_millis(4_900),
        "the pending owner must survive the original five-second budget: {:?}",
        retained_since.elapsed()
    );
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "absence must not publish"
    );
    let events = http.typed_sse(&cycle.token, &run_id).await;
    assert_typed_terminal(&events, "run.failed");
    assert!(
        !events
            .iter()
            .any(|event| event.name == "workspace.published" || event.name == "run.completed"),
        "the timeout/absence path publishes nothing: {events:?}"
    );
    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// N2: the accepted G3 AfterIntent producer leaves a real durable
/// `intent`/indeterminate managed effect on the admitted branch after the
/// owning run fails without any tool terminal. A later Required run is really
/// admitted on that branch, but its finalize transaction must be refused by the
/// exact unresolved-effect guard: no pointer, no publication event, no
/// finalize message, no run completion, and the original effect identity and
/// branch root stay auditable.
#[tokio::test(flavor = "multi_thread")]
async fn required_completion_refuses_branch_with_real_indeterminate_intent() {
    let cycle = Cycle::open_required(&format!("t16-pending-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");

    // Real Native producer: the formal signed file tool creates its durable
    // intent, then the injected Native cut traps the call before any view, IO,
    // receipt or tool terminal exists.
    cycle
        .state
        .service()
        .inject_managed_effect_fault(rustscript_agent::effects::ManagedEffectFault::AfterIntent)
        .expect("arm the Native AfterIntent cut");
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("pending-write", "write_file", "pending-out.txt"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "write the pending marker"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let branch = admitted["workspace_branch"]
        .as_str()
        .expect("managed branch")
        .to_string();
    let epoch = admitted["epoch"].as_u64().expect("managed epoch");

    let events = tokio::time::timeout(
        Duration::from_secs(20),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the cut run never terminated; events={:?}",
            event_names(&cycle.state, &run_id)
        )
    });
    assert_typed_terminal(&events, "run.failed");
    let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
    assert!(
        !names.contains(&"tool.completed"),
        "the injected Native cut leaves no tool terminal: {names:?}"
    );
    assert!(
        !names.contains(&"workspace.published"),
        "the cut publishes nothing: {names:?}"
    );

    // Read the exact durable effect the accepted producer left behind.
    let cut_entries = run_effect_entries(&http, &cycle.token, &run_id).await;
    let cut_effect = cut_entries
        .iter()
        .find(|entry| entry["call_id"] == "pending-write")
        .expect("the durable cut intent is readable")
        .clone();
    assert_eq!(
        cut_effect["state"], "indeterminate",
        "the cut leaves a real indeterminate managed effect: {cut_effect}"
    );
    assert_eq!(cut_effect["branch_id"], json!(branch));
    assert_eq!(cut_effect["epoch"], json!(epoch));
    let effect_id = cut_effect["effect_id"]
        .as_str()
        .expect("effect identity")
        .to_string();
    let workspace_id = cut_effect["workspace_id"]
        .as_str()
        .expect("workspace identity")
        .to_string();
    assert!(
        !cycle.workspace.join("pending-out.txt").exists(),
        "the cut performed no workspace IO"
    );
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "the cut never published"
    );

    // A second Required run proceeds on the same admitted branch with a
    // legitimate, tool-free turn. The unresolved branch effect is the only
    // reason publication can be refused.
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("pending-second"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, second) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "publish over the pending branch",
                "workspace_branch": branch,
            }),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(
        status,
        202,
        "the second run is really admitted: {}",
        explain(status, &second)
    );
    assert_eq!(second["publication"], json!("not_published"));
    let second_run = second["run_id"].as_str().unwrap().to_string();
    let second_events = tokio::time::timeout(
        Duration::from_secs(20),
        http.typed_sse(&cycle.token, &second_run),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the refused publication never terminated; events={:?}",
            event_names(&cycle.state, &second_run)
        )
    });
    assert_typed_terminal(&second_events, "run.failed");
    let second_names: Vec<&str> = second_events
        .iter()
        .map(|event| event.name.as_str())
        .collect();
    assert!(
        !second_names
            .iter()
            .any(|name| *name == "workspace.published" || *name == "run.completed"),
        "an unresolved branch effect must not publish: {second_names:?}"
    );
    let failed = http
        .raw_sse(&cycle.token, &second_run)
        .await
        .into_iter()
        .find(|value| value["event"] == "run.failed")
        .expect("durable refusal payload");
    assert_eq!(failed["error_code"], "managed_publication_conflict");
    assert!(
        matches!(
            failed["publication"]["status"].as_str(),
            Some("conflict" | "not_published")
        ),
        "the refusal carries an ordered non-publication: {failed}"
    );

    // The pre-completion refusal wrote nothing: pointer, durable effect and
    // the original failed run stay exactly as they were.
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("post-refusal pointer read"),
        None,
        "a refused Required completion must not publish a pointer"
    );
    let after_entries = run_effect_entries(&http, &cycle.token, &run_id).await;
    let after_effect = after_entries
        .iter()
        .find(|entry| entry["call_id"] == "pending-write")
        .expect("the original effect is still reachable");
    assert_eq!(after_effect["effect_id"], json!(effect_id));
    assert_eq!(after_effect["state"], "indeterminate");
    let first = persistence
        .run_get(&run_id)
        .expect("original typed run read");
    let first_rows = rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(&first)
        .expect("original run rows");
    assert_eq!(
        first_rows
            .first()
            .and_then(|row| row.get(3))
            .and_then(Value::as_str),
        Some("failed")
    );
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
    assert!(
        !messages["data"]
            .as_array()
            .expect("session messages")
            .iter()
            .any(|message| message["run_id"] == json!(second_run)
                && message["id"]
                    .as_str()
                    .is_some_and(|id| id.ends_with(":finalize:message"))),
        "the rolled-back transaction inserted no publication message"
    );
    assert_closed(&admitted, &cycle.token, &hidden);
    assert_closed(&second, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// Real authorized read followed by a deterministic business barrier: the run
/// stays admissible/live and never owns a branch writer.
struct LiveReaderProvider {
    turn: std::sync::atomic::AtomicUsize,
    entered: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl rustscript_agent::AgentProviderHost for LiveReaderProvider {
    fn call(&self, _request: &Value, cancellation: &rustscript_agent::RunCancellation) -> Value {
        let turn = self.turn.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if turn == 1 {
            return json!({
                "ok": true,
                "response": tool_call("live-read", "read_file", "note.txt"),
                "error": {}
            });
        }
        let (flag, cv) = &*self.entered;
        *flag.lock().expect("live reader entered") = true;
        cv.notify_all();
        let (flag, cv) = &*self.release;
        let mut released = flag.lock().expect("live reader release");
        let deadline = std::time::Instant::now() + Duration::from_secs(90);
        while !*released && std::time::Instant::now() < deadline {
            if cancellation.requested().is_some() || cancellation.deadline_passed() {
                break;
            }
            let now = std::time::Instant::now();
            let (guard, _) = cv
                .wait_timeout(released, deadline.saturating_duration_since(now))
                .expect("live reader wait");
            released = guard;
        }
        json!({"ok": true, "response": stop_turn("live-done"), "error": {}})
    }
}

/// N3: two genuinely admitted runs share one branch. The first run has already
/// performed its authorized read and is held live at a real provider barrier
/// while the second Required run completes. The second completion is refused by
/// the transaction's other-active-run guard (no pointer, no publication event),
/// and the first run continues under its original clock/permit and publishes
/// its own pointer afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn required_completion_with_live_sibling_run_conflicts_without_pointer() {
    let cycle = Cycle::open_required(&format!("t16-busy-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    std::fs::write(cycle.workspace.join("note.txt"), b"live-reader-note").unwrap();
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();

    // Run A: real authorized read, then a real barrier after its result.
    let entered = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let live = Arc::new(LiveReaderProvider {
        turn: std::sync::atomic::AtomicUsize::new(0),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    });
    cycle.state.service().inject_provider_host(live);
    let (status, live_admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "live reader run"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &live_admitted));
    let live_run = live_admitted["run_id"].as_str().unwrap().to_string();
    let branch = live_admitted["workspace_branch"]
        .as_str()
        .expect("managed branch")
        .to_string();
    let epoch = live_admitted["epoch"].as_u64().expect("managed epoch");
    wait_until(|| {
        let (flag, _) = &*entered;
        *flag.lock().expect("live entered flag")
    })
    .await;
    assert!(
        event_names(&cycle.state, &live_run)
            .iter()
            .any(|name| name == "tool.completed"),
        "the live run completed its authorized read: {:?}",
        event_names(&cycle.state, &live_run)
    );
    assert!(
        !event_names(&cycle.state, &live_run)
            .iter()
            .any(|name| matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )),
        "the live run is still running at its barrier"
    );

    // Run B: the second genuinely admitted run reaches Required completion.
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("busy-done"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, busy_admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "busy completion run",
                "workspace_branch": branch,
            }),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(
        status,
        202,
        "the second run is really admitted: {}",
        explain(status, &busy_admitted)
    );
    assert_eq!(busy_admitted["workspace_branch"], json!(branch));
    let busy_run = busy_admitted["run_id"].as_str().unwrap().to_string();
    let busy_events = tokio::time::timeout(
        Duration::from_secs(30),
        http.typed_sse(&cycle.token, &busy_run),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the busy completion never terminated; live={:?} busy={:?}",
            event_names(&cycle.state, &live_run),
            event_names(&cycle.state, &busy_run)
        )
    });
    assert_typed_terminal(&busy_events, "run.failed");
    let busy_names: Vec<&str> = busy_events
        .iter()
        .map(|event| event.name.as_str())
        .collect();
    assert!(
        !busy_names
            .iter()
            .any(|name| *name == "workspace.published" || *name == "run.completed"),
        "a completion beside a live sibling must not publish: {busy_names:?}"
    );
    let failed = http
        .raw_sse(&cycle.token, &busy_run)
        .await
        .into_iter()
        .find(|value| value["event"] == "run.failed")
        .expect("durable busy refusal");
    assert_eq!(failed["error_code"], "managed_publication_conflict");
    assert!(
        matches!(
            failed["publication"]["status"].as_str(),
            Some("conflict" | "not_published")
        ),
        "no publication identity from the refused completion: {failed}"
    );
    // No pointer exists while the refused completion and the live run coexist.
    let live_effect = run_effect_entries(&http, &cycle.token, &live_run)
        .await
        .into_iter()
        .find(|entry| entry["call_id"] == "live-read")
        .expect("the authorized read is auditable");
    let workspace = live_effect["workspace_id"]
        .as_str()
        .expect("workspace identity")
        .to_string();
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace, "gateway")
            .expect("pre-pointer read"),
        None,
        "the refused completion created no pointer"
    );
    assert!(
        !event_names(&cycle.state, &live_run)
            .iter()
            .any(|name| matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "run.cancelled"
            )),
        "the live run's owner/clock were not disturbed by the sibling refusal"
    );

    // Release the original run: it continues under its admitted permit and
    // publishes its own pointer through the same Required completion.
    {
        let (flag, cv) = &*release;
        *flag.lock().expect("live release flag") = true;
        cv.notify_all();
    }
    let live_events = tokio::time::timeout(
        Duration::from_secs(60),
        http.typed_sse(&cycle.token, &live_run),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the live run never finished; events={:?}",
            event_names(&cycle.state, &live_run)
        )
    });
    assert_typed_terminal(&live_events, "run.completed");
    let live_raw = http.raw_sse(&cycle.token, &live_run).await;
    let completed = live_raw
        .iter()
        .find(|value| value["event"] == "run.completed")
        .expect("live completed payload");
    assert_eq!(completed["publication"]["status"], "committed");
    assert_eq!(completed["publication"]["branch_id"], json!(branch));
    assert_eq!(completed["publication"]["epoch"], json!(epoch));
    let published = live_raw
        .iter()
        .find(|value| value["event"] == "workspace.published")
        .expect("live publication event");
    assert_eq!(
        completed["publication"]["request_id"], published["request_id"],
        "the live run's own frozen request identity published"
    );
    let pointer = persistence
        .managed_workspace_publication(&workspace, "gateway")
        .expect("live pointer read")
        .expect("the live run's completion published");
    assert_eq!(pointer.branch_id, branch);
    assert_eq!(pointer.epoch, epoch);
    assert_eq!(pointer.revision, 1);
    assert_eq!(
        pointer.request_id,
        completed["publication"]["request_id"].as_str().unwrap()
    );
    assert_eq!(
        pointer.head_object_id,
        completed["publication"]["head_object_id"].as_str().unwrap()
    );
    assert_closed(&live_admitted, &cycle.token, &hidden);
    assert_closed(&busy_admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// Managed Required workspace with the shipped stateless embedded tool host:
/// the same production `terminal`/`process` leaves, no activated plugin graph
/// pin requirement. Used for the real process-group positive control.
struct PlainProcessRun {
    root: std::path::PathBuf,
    workspace: std::path::PathBuf,
    home: std::path::PathBuf,
    source: std::path::PathBuf,
    token: String,
    session_id: String,
    state: rustscript_agent::AgentGatewayState,
    http: Http,
}

async fn open_plain_required_process(label: &str) -> PlainProcessRun {
    use rustscript_agent::config::{
        ManagedMaintenancePolicy, ManagedRetentionLimits, ManagedWorkspaceConfig,
    };
    use rustscript_agent::effects::ResourceQuota;
    let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap()).join(
        format!("t16-plain-{label}-{}", uuid::Uuid::new_v4().simple()),
    );
    let _ = std::fs::remove_dir_all(&root);
    let workspace = root.join("workspace");
    let home = root.join("workspace-home");
    let source = root.join("controlled-source");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    let yaml = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\napprovals:\n  read: allow\n  write: allow\n  process: allow\n",
        workspace.display(),
        workspace.display()
    );
    std::fs::write(home.join("config.yaml"), yaml).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &workspace, &home, &source] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            home.join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let token = uuid::Uuid::new_v4().to_string();
    let mut config = rustscript_agent::AgentGatewayConfig {
        bearer_token: Some(token.clone()),
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace.clone(),
            quota: ResourceQuota::new(1000, 1_048_576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: ManagedMaintenancePolicy::default(),
        }),
        managed_completion_policy: rustscript_agent::config::ManagedCompletionPolicy::Required,
        run_timeout: Duration::from_secs(900),
        ..rustscript_agent::AgentGatewayConfig::default()
    };
    config.approvals.read = "allow".into();
    config.approvals.write = "allow".into();
    config.approvals.process = "allow".into();
    let db = root.join("gateway.sqlite");
    let state = rustscript_agent::AgentGatewayState::with_sqlite_path(config, &db)
        .unwrap()
        .with_workspace_home(&home);
    let http = Http::bind(state.clone()).await;
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    PlainProcessRun {
        root,
        workspace,
        home,
        source,
        token,
        session_id,
        state,
        http,
    }
}

/// Collect the real process handles the provider turn can see in its request
/// context (the committed spawn tool result carries `data.process_id`).
fn request_process_ids(value: &Value) -> Vec<String> {
    fn walk(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(fields) => {
                for (key, field) in fields {
                    if key == "process_id"
                        && let Value::String(id) = field
                        && !id.is_empty()
                        && !out.iter().any(|seen| seen == id)
                    {
                        out.push(id.clone());
                    }
                    walk(field, out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, &mut out);
    out
}

/// Scan `/proc` for children of this test process by the unique marker this
/// fixture passes in argv. Only cmdline matches of that marker are read.
fn marker_pids(marker: &str) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids = Vec::new();
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        if String::from_utf8_lossy(&cmdline).contains(marker) {
            pids.push(pid);
        }
    }
    pids
}

/// One business gate shared by the provider mode and the waiting test thread:
/// the flag is set under its own mutex and the condition variable wakes the
/// waiter. Both ends must hold the same pair.
type GatePair = Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>;

/// Real background producer with a deterministic business barrier. Every mode
/// first spawns the real `terminal background=true` tool, then issues one real
/// `process` poll so the live/terminal status is a typed tool result, and only
/// then enters the business barrier.
struct ProcessLifecycleProvider {
    turns: std::sync::Mutex<usize>,
    barrier: Option<Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>>,
    release: Option<Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>>,
    script: &'static str,
    timeout_ms: u64,
    close_and_wait: bool,
    close_after_poll: bool,
    wait_fault_barrier: bool,
}

impl ProcessLifecycleProvider {
    fn close_and_wait() -> Self {
        Self {
            turns: std::sync::Mutex::new(0),
            barrier: None,
            release: None,
            script: "printf 't16-group-ready'",
            timeout_ms: 4000,
            close_and_wait: true,
            close_after_poll: false,
            wait_fault_barrier: false,
        }
    }
    /// Spawn + close + a barrier immediately before the terminal wait, so the
    /// caller can arm the real Native CommitAfterDecision cut for that commit.
    fn fault_wait() -> (Self, GatePair, GatePair) {
        let entered = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        (
            Self {
                turns: std::sync::Mutex::new(0),
                barrier: Some(Arc::clone(&entered)),
                release: Some(Arc::clone(&release)),
                script: "printf 't16-group-ready'; sleep 1",
                timeout_ms: 4000,
                close_and_wait: true,
                close_after_poll: false,
                wait_fault_barrier: true,
            },
            entered,
            release,
        )
    }
    fn barrier(script: &'static str, timeout_ms: u64) -> (Self, GatePair, GatePair) {
        let entered = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        (
            Self {
                turns: std::sync::Mutex::new(0),
                barrier: Some(Arc::clone(&entered)),
                release: Some(Arc::clone(&release)),
                script,
                timeout_ms,
                close_and_wait: false,
                close_after_poll: false,
                wait_fault_barrier: false,
            },
            entered,
            release,
        )
    }
    /// Spawn + real typed poll + stdin close + a business barrier before the
    /// terminal step. The child exits on its own and the close joins the owned
    /// stdin worker, so the branch still holds an Open group whose table is
    /// genuinely quiescent without a prior `process wait` retiring its writer.
    fn open_proof_after_poll(script: &'static str, timeout_ms: u64) -> (Self, GatePair, GatePair) {
        let entered = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        (
            Self {
                turns: std::sync::Mutex::new(0),
                barrier: Some(Arc::clone(&entered)),
                release: Some(Arc::clone(&release)),
                script,
                timeout_ms,
                close_and_wait: false,
                close_after_poll: true,
                wait_fault_barrier: false,
            },
            entered,
            release,
        )
    }
    fn reply(call: Value) -> Value {
        json!({
            "ok": true,
            "response": {
                "text": "", "tool_calls": [call],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                "reasoning": "", "stop_reason": "tool_calls"
            },
            "error": {}
        })
    }
}

impl rustscript_agent::AgentProviderHost for ProcessLifecycleProvider {
    fn call(&self, request: &Value, cancellation: &rustscript_agent::RunCancellation) -> Value {
        let mut turns = self.turns.lock().expect("process provider turns");
        *turns += 1;
        let turn = *turns;
        let ids = request_process_ids(request);
        let first = ids.first().cloned().unwrap_or_default();
        match turn {
            1 => Self::reply(json!({
                "id": "process-spawn",
                "name": "terminal",
                "arguments": {
                    "argv": ["/bin/sh", "-c", self.script],
                    "background": true,
                    "timeout_ms": self.timeout_ms
                }
            })),
            2 if self.close_and_wait => Self::reply(json!({
                "id": "process-close",
                "name": "process",
                "arguments": {"action": "close", "process_id": first}
            })),
            3 if self.close_and_wait => {
                let body = || {
                    Self::reply(json!({
                        "id": "process-wait",
                        "name": "process",
                        "arguments": {"action": "wait", "process_id": first, "timeout_ms": 10000}
                    }))
                };
                if self.wait_fault_barrier
                    && let (Some(entered), Some(release)) = (&self.barrier, &self.release)
                {
                    let (flag, cv) = &**entered;
                    *flag.lock().expect("wait fault barrier entered") = true;
                    cv.notify_all();
                    let (flag, cv) = &**release;
                    let mut released = flag.lock().expect("wait fault barrier release");
                    let deadline = std::time::Instant::now() + Duration::from_secs(60);
                    while !*released && std::time::Instant::now() < deadline {
                        if cancellation.requested().is_some() || cancellation.deadline_passed() {
                            break;
                        }
                        let now = std::time::Instant::now();
                        let (guard, _) = cv
                            .wait_timeout(released, deadline.saturating_duration_since(now))
                            .expect("wait fault barrier wait");
                        released = guard;
                    }
                }
                body()
            }
            2 if !self.close_and_wait => Self::reply(json!({
                "id": "process-poll",
                "name": "process",
                "arguments": {"action": "poll", "process_id": first}
            })),
            3 if self.close_after_poll => Self::reply(json!({
                "id": "process-close",
                "name": "process",
                "arguments": {"action": "close", "process_id": first}
            })),
            4 if self.close_after_poll => {
                if let (Some(entered), Some(release)) = (&self.barrier, &self.release) {
                    let (flag, cv) = &**entered;
                    *flag.lock().expect("process barrier entered") = true;
                    cv.notify_all();
                    let (flag, cv) = &**release;
                    let mut released = flag.lock().expect("process barrier release");
                    let deadline = std::time::Instant::now() + Duration::from_secs(60);
                    while !*released && std::time::Instant::now() < deadline {
                        if cancellation.requested().is_some() || cancellation.deadline_passed() {
                            break;
                        }
                        let now = std::time::Instant::now();
                        let (guard, _) = cv
                            .wait_timeout(released, deadline.saturating_duration_since(now))
                            .expect("process barrier wait");
                        released = guard;
                    }
                }
                json!({
                    "ok": true,
                    "response": stop_turn("process-barrier-stop"),
                    "error": {}
                })
            }
            3 => {
                if let (Some(entered), Some(release)) = (&self.barrier, &self.release) {
                    let (flag, cv) = &**entered;
                    *flag.lock().expect("process barrier entered") = true;
                    cv.notify_all();
                    let (flag, cv) = &**release;
                    let mut released = flag.lock().expect("process barrier release");
                    let deadline = std::time::Instant::now() + Duration::from_secs(60);
                    while !*released && std::time::Instant::now() < deadline {
                        if cancellation.requested().is_some() || cancellation.deadline_passed() {
                            break;
                        }
                        let now = std::time::Instant::now();
                        let (guard, _) = cv
                            .wait_timeout(released, deadline.saturating_duration_since(now))
                            .expect("process barrier wait");
                        released = guard;
                    }
                }
                json!({
                    "ok": true,
                    "response": stop_turn("process-barrier-stop"),
                    "error": {}
                })
            }
            _ => json!({
                "ok": true,
                "response": stop_turn("process-finished"),
                "error": {}
            }),
        }
    }
}

fn proc_stat_state(pid: u32) -> Option<String> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = raw.rsplit_once(") ")?.1;
    rest.split_whitespace().next().map(str::to_string)
}

/// T4 quiescence-positive / publication-negative control: a real
/// `terminal background=true` producer installs the run group root; the run
/// closes stdin and reaps its child before the terminal step, so the branch
/// gate's quiescence proof passes (not `busy`). The accepted durable T10
/// process-lineage predicate then refuses the Required publication with
/// `managed_process_lineage_unsupported`: no pointer, no workspace.published,
/// no run.completed, while the committed spawn/control receipts and the fully
/// reaped group remain auditable.
#[tokio::test(flavor = "multi_thread")]
async fn required_process_quiescent_group_is_refused_by_lineage_predicate() {
    let PlainProcessRun {
        root: _root,
        workspace,
        home: _home,
        source,
        token,
        session_id,
        state,
        http,
    } = open_plain_required_process("proc-ok").await;
    let hidden = [workspace.as_path(), source.as_path()];
    let persistence = state.persistence().expect("persistence");
    let provider = Arc::new(ProcessLifecycleProvider::close_and_wait());
    state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "own one background group"}),
            Some(&token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let branch = admitted["workspace_branch"]
        .as_str()
        .expect("managed branch")
        .to_string();
    let epoch = admitted["epoch"].as_u64().expect("managed epoch");
    let progress = std::time::Instant::now() + Duration::from_secs(30);
    while event_names(&state, &run_id)
        .iter()
        .filter(|name| *name == "tool.completed")
        .count()
        < 3
    {
        assert!(
            std::time::Instant::now() < progress,
            "the process run never reached its group controls: {:?}",
            state.service().run_events(&run_id)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let events = tokio::time::timeout(Duration::from_secs(30), http.typed_sse(&token, &run_id))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the closed/reaped group run never terminated; events={:?}",
                state.service().run_events(&run_id)
            )
        });
    let raw = http.raw_sse(&token, &run_id).await;
    assert_typed_terminal(&events, "run.failed");
    assert!(
        !events
            .iter()
            .any(|event| event.name == "workspace.published" || event.name == "run.completed"),
        "a refused process completion publishes nothing: {events:?}"
    );
    let failed = raw
        .iter()
        .find(|value| value["event"] == "run.failed")
        .expect("durable refusal payload");
    assert_eq!(
        failed["error_code"], "managed_process_lineage_unsupported",
        "the group was quiescent, so the refusal is the accepted T10 lineage predicate: {failed}"
    );
    assert_eq!(failed["publication"]["status"], "conflict");
    let entries = run_effect_entries(&http, &token, &run_id).await;
    let spawn = entries
        .iter()
        .find(|entry| entry["call_id"] == "process-spawn")
        .expect("spawn effect");
    assert_eq!(
        spawn["state"], "read_only",
        "the background spawn is an ordered read-only effect"
    );
    let close = entries
        .iter()
        .find(|entry| entry["call_id"] == "process-close")
        .expect("stdin close effect");
    assert_eq!(
        close["state"], "read_only",
        "stdin close is an ordered read-only control effect"
    );
    let wait = entries
        .iter()
        .find(|entry| entry["call_id"] == "process-wait")
        .expect("group wait effect");
    assert_eq!(
        wait["state"], "committed",
        "the terminal wait is the one group TreeWrite publication"
    );
    assert!(
        spawn["decided_at_ms"].as_u64().unwrap() < close["decided_at_ms"].as_u64().unwrap()
            && close["decided_at_ms"].as_u64().unwrap() < wait["decided_at_ms"].as_u64().unwrap(),
        "spawn -> close -> wait committed in order"
    );
    let workspace_id = spawn["workspace_id"]
        .as_str()
        .expect("workspace")
        .to_string();
    assert_eq!(spawn["branch_id"], json!(branch));
    assert_eq!(spawn["epoch"], json!(epoch));
    assert_eq!(wait["workspace_id"], json!(workspace_id));
    assert_eq!(wait["branch_id"], json!(branch));
    assert_eq!(wait["epoch"], json!(epoch));
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "the lineage predicate left the pointer untouched"
    );
    // The producer's own group is fully gone and no OS child leaked.
    assert!(
        marker_pids("t16-group-ready").is_empty(),
        "no produced child may survive the quiescent group completion"
    );
    assert_closed(&admitted, &token, &hidden);
    http.close().await;
    shutdown_when_idle(&state).await;
}

/// T4 quiescence-positive control without a prior `process wait`: a real
/// background group's child exits on its own, the run closes stdin (joining the
/// owned stdin worker) but never waits, so the branch writer is still Open when
/// the Required completion runs. The completion must obtain the whole-table
/// proof from the Open arm (harvest + drain join + stdin zero), mint its
/// reservation and only then hit the accepted T10 lineage refusal: the failure
/// is `managed_process_lineage_unsupported`, not the self-refusing `busy` of a
/// callback that cleanup cannot satisfy, and the pointer stays untouched.
#[tokio::test(flavor = "multi_thread")]
async fn required_process_open_group_proof_reaches_lineage_refusal() {
    let cycle = Cycle::open_required_process(&format!(
        "t16-proc-open-proof-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.embedding.tools",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (provider, entered, release) =
        ProcessLifecycleProvider::open_proof_after_poll("printf 't16-open-proof'", 4000);
    let provider = Arc::new(provider);
    cycle.state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "prove the open group"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let branch = admitted["workspace_branch"]
        .as_str()
        .expect("managed branch")
        .to_string();
    let epoch = admitted["epoch"].as_u64().expect("managed epoch");
    wait_until(|| {
        let (flag, _) = &*entered;
        *flag.lock().expect("open proof barrier")
    })
    .await;
    assert!(
        cycle
            .state
            .service()
            .session_messages(&session_id)
            .iter()
            .any(|message| message["run_id"] == json!(run_id)
                && message.to_string().contains("\"status\":\"exited\"")),
        "the real typed poll reports the child exited before the barrier: {:?}",
        cycle
            .state
            .service()
            .session_messages(&session_id)
            .iter()
            .filter(|message| message["run_id"] == json!(run_id))
            .map(|message| message.to_string())
            .collect::<Vec<_>>()
    );
    {
        let (flag, cv) = &*release;
        *flag.lock().expect("open proof release") = true;
        cv.notify_all();
    }
    let events = tokio::time::timeout(
        Duration::from_secs(60),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the open group completion never terminated; events={:?}",
            cycle.state.service().run_events(&run_id)
        )
    });
    assert_typed_terminal(&events, "run.failed");
    assert!(
        !events
            .iter()
            .any(|event| event.name == "workspace.published" || event.name == "run.completed"),
        "the lineage predicate must still refuse the open-group completion: {events:?}"
    );
    let failed = http
        .raw_sse(&cycle.token, &run_id)
        .await
        .into_iter()
        .find(|value| value["event"] == "run.failed")
        .expect("lineage refusal payload");
    assert_eq!(
        failed["error_code"], "managed_process_lineage_unsupported",
        "a proven open group reaches the accepted lineage refusal, not busy: {failed}"
    );
    assert_eq!(failed["publication"]["status"], "conflict");
    let entries = run_effect_entries(&http, &cycle.token, &run_id).await;
    let spawn = entries
        .iter()
        .find(|entry| entry["call_id"] == "process-spawn")
        .expect("spawn effect");
    assert_eq!(spawn["state"], "read_only");
    assert_eq!(spawn["branch_id"], json!(branch));
    assert_eq!(spawn["epoch"], json!(epoch));
    let poll = entries
        .iter()
        .find(|entry| entry["call_id"] == "process-poll")
        .expect("poll effect");
    assert_eq!(poll["state"], "read_only");
    let close = entries
        .iter()
        .find(|entry| entry["call_id"] == "process-close")
        .expect("close effect");
    assert_eq!(close["state"], "read_only");
    assert!(
        !entries
            .iter()
            .any(|entry| entry["call_id"] == "process-wait"),
        "no wait may retire the Open writer in this control"
    );
    let workspace_id = spawn["workspace_id"]
        .as_str()
        .expect("workspace")
        .to_string();
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "the proven open group still publishes nothing"
    );
    assert!(
        marker_pids("t16-open-proof").is_empty(),
        "no produced child may survive the proven open group completion"
    );
    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// T4 negative A: while the owned background child is genuinely live, a
/// Required completion may not publish. The live status is a real typed
/// `process poll` result and the OS child is observed through its own marker;
/// the completion fails `busy`, no pointer/terminal appears, and the cleanup
/// reaps the owned OS child without leaking it.
#[tokio::test(flavor = "multi_thread")]
async fn required_process_live_child_blocks_publication_without_pointer() {
    let cycle =
        Cycle::open_required_process(&format!("t16-proc-live-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.embedding.tools",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (provider, entered, release) =
        ProcessLifecycleProvider::barrier("printf 't16-live-marker'; sleep 20", 30000);
    let provider = Arc::new(provider);
    cycle.state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "keep the group live"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        let (flag, _) = &*entered;
        *flag.lock().expect("live child barrier")
    })
    .await;
    assert!(
        contains_marker(&cycle.state, &run_id, "running")
            || cycle
                .state
                .service()
                .session_messages(&session_id)
                .iter()
                .any(|message| message["run_id"] == json!(run_id)
                    && message.to_string().contains("\"status\":\"running\"")),
        "the process poll reports the owned child as running: {:?}",
        cycle
            .state
            .service()
            .session_messages(&session_id)
            .iter()
            .filter(|message| message["run_id"] == json!(run_id))
            .map(|message| message.to_string())
            .collect::<Vec<_>>()
    );
    let live_pids = marker_pids("t16-live-marker");
    assert!(
        !live_pids.is_empty(),
        "the owned OS child is really live at the barrier"
    );
    for pid in &live_pids {
        assert_ne!(
            proc_stat_state(*pid).as_deref(),
            Some("Z"),
            "the marker child is running: pid={pid}"
        );
    }
    let run = persistence.run_get(&run_id).expect("running run read");
    let rows = rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(&run).expect("run rows");
    assert_eq!(
        rows.first()
            .and_then(|row| row.get(3))
            .and_then(Value::as_str),
        Some("running"),
        "no terminal may exist while the owned group is live"
    );
    assert!(
        !event_names(&cycle.state, &run_id)
            .iter()
            .any(|name| matches!(
                name.as_str(),
                "run.completed" | "run.failed" | "workspace.published"
            )),
        "the live group run has no completion yet"
    );
    let effect = run_effect_entries(&http, &cycle.token, &run_id)
        .await
        .into_iter()
        .find(|entry| entry["call_id"] == "process-spawn")
        .expect("spawn effect readable");
    let workspace_id = effect["workspace_id"]
        .as_str()
        .expect("workspace")
        .to_string();
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pre-release pointer"),
        None,
        "no pointer exists while the group is live"
    );
    {
        let (flag, cv) = &*release;
        *flag.lock().expect("live child release") = true;
        cv.notify_all();
    }
    let events = tokio::time::timeout(
        Duration::from_secs(30),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the live group completion never terminated; events={:?}",
            cycle.state.service().run_events(&run_id)
        )
    });
    assert_typed_terminal(&events, "run.failed");
    assert!(
        !events
            .iter()
            .any(|event| event.name == "workspace.published" || event.name == "run.completed"),
        "a live owned group must not publish: {events:?}"
    );
    let failed = http
        .raw_sse(&cycle.token, &run_id)
        .await
        .into_iter()
        .find(|value| value["event"] == "run.failed")
        .expect("busy refusal payload");
    assert_eq!(failed["error_code"], "managed_publication_conflict");
    assert!(
        failed["error_message"]
            .as_str()
            .is_some_and(|message| message.contains("busy")),
        "the real quiescence gate refused: {failed}"
    );
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("post-refusal pointer"),
        None,
        "the refused completion published nothing"
    );
    let reap_deadline = std::time::Instant::now() + Duration::from_secs(15);
    while marker_pids("t16-live-marker")
        .iter()
        .any(|pid| proc_stat_state(*pid).is_some_and(|state| state != "Z"))
        && std::time::Instant::now() < reap_deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for pid in &live_pids {
        assert!(
            proc_stat_state(*pid).is_none() || proc_stat_state(*pid).as_deref() == Some("Z"),
            "the cleanup reaped the owned child: pid={pid}"
        );
    }
    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// T4 positive: the child exits and the typed poll reports `exited`. The run
/// never issues a `process wait`, so the owning Open writer is still in place
/// at completion. The real whole-table observation proves the exited, drained
/// group (no stdin write worker is ever in flight here) and the completion
/// reaches the accepted lineage refusal: no pointer, and no OS process left
/// behind. An open stdin *pipe* is not a live stdin worker; only an in-flight
/// write worker would be. This replaces the previous unsupported claim that
/// this fixture could keep a stdin worker non-zero.
#[tokio::test(flavor = "multi_thread")]
async fn required_process_exited_group_without_wait_reaches_lineage_refusal() {
    let cycle =
        Cycle::open_required_process(&format!("t16-proc-stdin-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden = [cycle.workspace.as_path(), cycle.source.as_path()];
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.embedding.tools",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (provider, entered, release) =
        ProcessLifecycleProvider::barrier("printf 't16-exit-marker'", 4000);
    let provider = Arc::new(provider);
    cycle.state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "leave stdin open"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    wait_until(|| {
        let (flag, _) = &*entered;
        *flag.lock().expect("stdin barrier")
    })
    .await;
    assert!(
        contains_marker(&cycle.state, &run_id, "exited")
            || cycle
                .state
                .service()
                .session_messages(&session_id)
                .iter()
                .any(|message| message["run_id"] == json!(run_id)
                    && message.to_string().contains("\"status\":\"exited\"")),
        "the poll proves the child already exited: {:?}",
        cycle
            .state
            .service()
            .session_messages(&session_id)
            .iter()
            .filter(|message| message["run_id"] == json!(run_id))
            .map(|message| message.to_string())
            .collect::<Vec<_>>()
    );
    {
        let (flag, cv) = &*release;
        *flag.lock().expect("stdin release") = true;
        cv.notify_all();
    }
    let events = tokio::time::timeout(
        Duration::from_secs(30),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the open-stdin run never terminated; events={:?}",
            cycle.state.service().run_events(&run_id)
        )
    });
    assert_typed_terminal(&events, "run.failed");
    assert!(
        !events
            .iter()
            .any(|event| event.name == "workspace.published" || event.name == "run.completed"),
        "an unclosed stdin worker must not publish: {events:?}"
    );
    let failed = http
        .raw_sse(&cycle.token, &run_id)
        .await
        .into_iter()
        .find(|value| value["event"] == "run.failed")
        .expect("stdin refusal payload");
    assert_eq!(
        failed["error_code"], "managed_process_lineage_unsupported",
        "the exited, drained group reaches the accepted lineage refusal: {failed}"
    );
    assert_eq!(failed["publication"]["status"], "conflict");
    let workspace = run_effect_entries(&http, &cycle.token, &run_id)
        .await
        .iter()
        .find(|entry| entry["call_id"] == "process-spawn")
        .and_then(|entry| entry["workspace_id"].as_str())
        .expect("workspace")
        .to_string();
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace, "gateway")
            .expect("pointer read"),
        None,
        "the unclosed stdin worker published nothing"
    );
    let reap_deadline = std::time::Instant::now() + Duration::from_secs(15);
    while marker_pids("t16-exit-marker")
        .iter()
        .any(|pid| proc_stat_state(*pid).is_some_and(|state| state != "Z"))
        && std::time::Instant::now() < reap_deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for pid in marker_pids("t16-exit-marker") {
        assert!(
            proc_stat_state(pid).as_deref() == Some("Z"),
            "the exited child is terminal/reapable: pid={pid}"
        );
    }
    assert_closed(&admitted, &cycle.token, &hidden);
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// T5: a real lost-commit cut on the terminal process group wait leaves the
/// durable owner/base/root identities in place with an indeterminate effect.
/// Same-process Required completion is refused by the retained writer/owner,
/// and after dropping the old service and reopening the exact same home/root
/// (no database copy, no reseed) the startup history scan keeps the run failed
/// and the effect indeterminate; a fresh Required completion still cannot
/// publish. No owned OS child survives, and no PID is reattached or signalled.
#[tokio::test(flavor = "multi_thread")]
async fn unresolved_process_history_blocks_required_publication_across_restart() {
    let cycle = Cycle::open_required_process(&format!(
        "t16-proc-unresolved-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let http = Http::bind(cycle.state.clone()).await;
    let original_token = cycle.token.clone();
    let hidden_paths = [cycle.workspace.clone(), cycle.source.clone()];
    let (_graph, _generation) = activate(
        &http,
        &original_token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.embedding.tools",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    let (status, session) = http
        .request(
            "POST",
            "/api/sessions",
            json!({}),
            Some(&original_token),
            None,
        )
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();

    let (provider, entered, release) = ProcessLifecycleProvider::fault_wait();
    let provider = Arc::new(provider);
    cycle.state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "lose the group commit"}),
            Some(&original_token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let branch = admitted["workspace_branch"]
        .as_str()
        .expect("managed branch")
        .to_string();
    let epoch = admitted["epoch"].as_u64().expect("managed epoch");
    wait_until(|| {
        let (flag, _) = &*entered;
        *flag.lock().expect("wait fault barrier")
    })
    .await;
    // Real Native cut: this exact terminal commit executes durably and the
    // reply is lost, so its owner cannot classify the outcome.
    cycle
        .state
        .service()
        .inject_managed_effect_fault(
            rustscript_agent::effects::ManagedEffectFault::CommitAfterDecision,
        )
        .expect("arm the real lost-commit cut");
    {
        let (flag, cv) = &*release;
        *flag.lock().expect("wait fault release") = true;
        cv.notify_all();
    }
    let events = tokio::time::timeout(
        Duration::from_secs(60),
        http.typed_sse(&original_token, &run_id),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the unresolved process run never terminated; events={:?}",
            cycle.state.service().run_events(&run_id)
        )
    });
    let first_names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
    assert!(
        !first_names
            .iter()
            .any(|name| *name == "workspace.published" || *name == "run.completed"),
        "an unresolved group commit must not publish: {first_names:?}"
    );
    assert!(
        first_names
            .iter()
            .any(|name| matches!(name, &"run.failed" | &"run.cancelled")),
        "the interrupted run is terminal: {first_names:?}"
    );
    let failure = http
        .raw_sse(&original_token, &run_id)
        .await
        .into_iter()
        .find(|value| {
            matches!(
                value["event"].as_str(),
                Some("run.failed" | "run.cancelled")
            )
        })
        .expect("interrupted terminal");
    let first_entries = run_effect_entries(&http, &original_token, &run_id).await;
    let wait_effect = first_entries
        .iter()
        .find(|entry| entry["call_id"] == "process-wait")
        .expect("the cut wait effect is durable")
        .clone();
    assert_eq!(
        wait_effect["state"], "staged",
        "the lost commit leaves the real incomplete prepared effect: {wait_effect}"
    );
    let effect_id = wait_effect["effect_id"].as_str().unwrap().to_string();
    let workspace_id = wait_effect["workspace_id"].as_str().unwrap().to_string();
    assert_eq!(wait_effect["branch_id"], json!(branch));
    assert_eq!(wait_effect["epoch"], json!(epoch));
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "the lost commit published no pointer"
    );
    assert!(
        marker_pids("t16-group-ready").is_empty(),
        "the owned child must not survive the interrupted producer"
    );

    // Same-process reachability: the unresolved branch is refused by the real
    // admission guard before any completion transaction may run.
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("after-unresolved"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, second) = http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "publish over unresolved process history",
                "workspace_branch": branch,
            }),
            Some(&original_token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(
        status,
        409,
        "the retained Unresolved owner refuses a new producer: {}",
        explain(status, &second)
    );
    assert_eq!(second["error"]["code"], "managed_source_conflict");
    assert!(
        second.get("run_id").is_none(),
        "no run may be admitted over unresolved history: {second}"
    );
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("same-process pointer"),
        None
    );
    assert!(
        marker_pids("t16-group-ready").is_empty(),
        "no owned child survives the same-process refusal"
    );

    // Cold restart of the exact original home/source/database bytes.
    http.close().await;
    // Supported lifecycle: shut the old service down. The unresolved owner may
    // keep a handle alive, so the exact error is recorded rather than treated
    // as a successful drain.
    let shutdown = cycle.state.service().shutdown().await;
    let shutdown_error = shutdown.err();
    assert!(
        shutdown_error.is_none(),
        "the supported lifecycle stop succeeds with unresolved history: {shutdown_error:?}"
    );
    drop(persistence);
    let reopened = cycle.reopen();
    let reopened_persistence = reopened.state.persistence().expect("reopened persistence");
    let reopened_http = Http::bind(reopened.state.clone()).await;
    let reopened_run = reopened_persistence.run_get(&run_id).expect("durable run");
    let rows = rustscript_agent::sqlite_storage_rows::sqlite_storage_rows(&reopened_run)
        .expect("durable run rows");
    assert_ne!(
        rows.first()
            .and_then(|row| row.get(3))
            .and_then(Value::as_str),
        Some("running"),
        "the startup scan does not fabricate a live producer"
    );
    let reopened_effect = reopened_persistence
        .managed_effect_by_id(&effect_id)
        .expect("durable effect read")
        .expect("the interrupted effect is durable");
    assert_eq!(
        reopened_effect.state,
        rustscript_agent::effects::ManagedPublicationStatus::Staged,
        "the reopened root keeps the incomplete effect unresolved"
    );
    assert_eq!(
        reopened_persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("reopened pointer"),
        None,
        "no pointer exists for the interrupted group"
    );
    // A fresh Required admission on the reopened root is refused by the same
    // bounded startup history proof; no new business writer, PID reattachment
    // or signal is attempted.
    let provider = ScriptedProvider::new();
    provider.push_ok(stop_turn("after-restart"));
    reopened
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, third) = reopened_http
        .request(
            "POST",
            "/v1/runs",
            json!({
                "session_id": session_id,
                "input": "publish after cold restart",
                "workspace_branch": branch,
            }),
            Some(&reopened.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(
        status,
        409,
        "the reopened root keeps the same Unresolved refusal: {}",
        explain(status, &third)
    );
    assert_eq!(third["error"]["code"], "managed_source_conflict");
    assert!(third.get("run_id").is_none());
    assert_eq!(
        reopened_persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("post-restart pointer"),
        None,
        "no publication after restart"
    );
    assert!(
        marker_pids("t16-group-ready").is_empty(),
        "restart reattached no owned PID and performed no signal"
    );
    assert_closed(
        &admitted,
        &original_token,
        &[hidden_paths[0].as_path(), hidden_paths[1].as_path()],
    );
    reopened_http.close().await;
    shutdown_when_idle(&reopened.state).await;
    let _ = failure;
}

/// T5 at the HTTP/process boundary: one real background group and one real
/// terminal wait/kill. That wait's commit executes and commits durably, while
/// its own reply and the one immediate matching readback reply are discarded,
/// so the controlling path observes unknown. The same original owner later
/// reads the exact finalized row and the established disposition applies
/// without a second commit, provider call, OS action or publication. The
/// Native gate release is asserted by the directly coupled unit; this e2e
/// grades only these product observations because no public Native claim
/// bridge exists.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn lost_process_group_commit_ack_same_owner_later_get_applies_existing_disposition_without_second_mutation()
 {
    let cycle = Cycle::open_required_process(&format!(
        "t16-proc-disposition-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let http = Http::bind(cycle.state.clone()).await;
    let hidden_paths = [cycle.workspace.clone(), cycle.source.clone()];
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.embedding.tools",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();

    let (provider, entered, release) = ProcessLifecycleProvider::fault_wait();
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "lose the group commit and its readback"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let branch = admitted["workspace_branch"]
        .as_str()
        .expect("managed branch")
        .to_string();
    let epoch = admitted["epoch"].as_u64().expect("managed epoch");
    wait_until(|| {
        let (flag, _) = &*entered;
        *flag.lock().expect("wait fault barrier")
    })
    .await;
    // Real dual ACK loss: the exact commit below commits durably, then both
    // its reply and the reply of its one immediate matching `effect.get`
    // readback are discarded. No other get, delegate, checkpoint or
    // admission reply is affected.
    persistence.inject_drop_managed_commit_and_readback_ack();
    {
        let (flag, cv) = &*release;
        *flag.lock().expect("wait fault release") = true;
        cv.notify_all();
    }
    let events = tokio::time::timeout(
        Duration::from_secs(60),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the dual-ACK-lost process run never terminated; events={:?}",
            cycle.state.service().run_events(&run_id)
        )
    });
    let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
    assert!(
        !names
            .iter()
            .any(|name| *name == "workspace.published" || *name == "run.completed"),
        "an unknown group commit publishes nothing: {names:?}"
    );
    assert!(
        names
            .iter()
            .any(|name| matches!(name, &"run.failed" | &"run.cancelled")),
        "the unknown commit terminates this run: {names:?}"
    );
    let first = run_effect_entries(&http, &cycle.token, &run_id).await;
    let wait_effects: Vec<&Value> = first
        .iter()
        .filter(|entry| entry["call_id"] == "process-wait")
        .collect();
    assert_eq!(
        wait_effects.len(),
        1,
        "one real wait issue produces exactly one durable effect row: {first:?}"
    );
    let wait = wait_effects[0];
    assert_eq!(
        wait["state"], "committed",
        "the lost-ACK commit is durably the original finalized receipt: {wait}"
    );
    assert_eq!(wait["branch_id"], json!(branch));
    assert_eq!(wait["epoch"], json!(epoch));
    let effect_id = wait["effect_id"].as_str().unwrap().to_string();
    let workspace_id = wait["workspace_id"].as_str().unwrap().to_string();
    let decided_at = wait["decided_at_ms"].clone();
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "the later disposition never publishes or advances the live pointer"
    );
    assert!(
        marker_pids("t16-group-ready").is_empty(),
        "the one real wait/kill left no owned child and performed no second OS action"
    );
    // The later same-owner read changes nothing else: the durable listing keeps
    // exactly one committed wait receipt with the same decision time.
    let second = run_effect_entries(&http, &cycle.token, &run_id).await;
    assert_eq!(
        second.len(),
        first.len(),
        "the disposition creates no new effect row: {second:?}"
    );
    let second_wait: Vec<&Value> = second
        .iter()
        .filter(|entry| entry["call_id"] == "process-wait")
        .collect();
    assert_eq!(second_wait.len(), 1);
    assert_eq!(second_wait[0]["effect_id"], json!(effect_id));
    assert_eq!(second_wait[0]["state"], "committed");
    assert_eq!(
        second_wait[0]["decided_at_ms"], decided_at,
        "no second commit or recovery rewrote the finalized decision"
    );
    assert_closed(
        &admitted,
        &cycle.token,
        &[hidden_paths[0].as_path(), hidden_paths[1].as_path()],
    );
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
}

/// N5: a completed Required publication, its exact event/message identities,
/// pointer revision and frozen request UUID are captured, the service is shut
/// down through the supported lifecycle, the exact same home/source/database is
/// reopened, and the original typed public request with its original
/// idempotency key is redelivered. It must return the exact old durable result
/// with no provider/tool/OS action, no pointer or revision mutation, and no new
/// event/message identities.
#[tokio::test(flavor = "multi_thread")]
async fn required_publication_replays_exactly_after_supported_shutdown() {
    let cycle = Cycle::open_required(&format!("t16-replay-{}", uuid::Uuid::new_v4().simple()));
    let http = Http::bind(cycle.state.clone()).await;
    let workspace = cycle.workspace.clone();
    let source = cycle.source.clone();
    install_pair(&http, &cycle.token, &cycle.source).await;
    let (_graph, _generation) = activate(
        &http,
        &cycle.token,
        &cycle.config,
        &cycle.db,
        "org.rustscript.tools.effecta",
    )
    .await;
    let persistence = cycle.state.persistence().expect("persistence");
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call("replay-write", "write_file", "replay-out.txt"));
    provider.push_ok(stop_turn("replay-done"));
    cycle
        .state
        .service()
        .inject_provider_host(Arc::new(provider));
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let body = json!({"session_id": session_id, "input": "write the replay marker"});
    let idem = uuid::Uuid::new_v4().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            body.clone(),
            Some(&cycle.token),
            Some(&idem),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let events = tokio::time::timeout(
        Duration::from_secs(20),
        http.typed_sse(&cycle.token, &run_id),
    )
    .await
    .expect("required publication terminates");
    assert_typed_terminal(&events, "run.completed");
    let raw = http.raw_sse(&cycle.token, &run_id).await;
    // The original publication event must exist in the raw stream; the value
    // itself is not compared here.
    let _published = raw
        .iter()
        .find(|value| value["event"] == "workspace.published")
        .expect("original publication event")
        .clone();
    let completed = raw
        .iter()
        .find(|value| value["event"] == "run.completed")
        .expect("original completion event")
        .clone();
    let publication = completed["publication"].clone();
    let request_id = publication["request_id"]
        .as_str()
        .expect("frozen request UUID")
        .to_string();
    let workspace_id = publication["workspace_id"]
        .as_str()
        .expect("workspace identity")
        .to_string();
    let branch = publication["branch_id"]
        .as_str()
        .expect("branch identity")
        .to_string();
    let epoch = publication["epoch"].as_u64().expect("epoch");
    let head_object = publication["head_object_id"]
        .as_str()
        .expect("head object")
        .to_string();
    let head_version = publication["head_version"].as_u64().expect("head version");
    let pointer = persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("pointer read")
        .expect("published pointer");
    assert_eq!(pointer.revision, 1);
    assert_eq!(pointer.request_id, request_id);
    assert_eq!(pointer.branch_id, branch);
    assert_eq!(pointer.epoch, epoch);
    assert_eq!(pointer.head_object_id, head_object);
    assert_eq!(pointer.head_version, head_version);
    let events_before = cycle.state.service().run_events(&run_id);
    let published_before = events_before
        .iter()
        .find(|event| event["event"] == "workspace.published")
        .expect("durable publication event")
        .clone();
    let completed_before = events_before
        .iter()
        .find(|event| event["event"] == "run.completed")
        .expect("durable completion event")
        .clone();
    let published_event_id = published_before["event_id"].clone();
    let published_seq = published_before["seq"].clone();
    let completed_event_id = completed_before["event_id"].clone();
    let completed_seq = completed_before["seq"].clone();
    let entries_before = run_effect_entries(&http, &cycle.token, &run_id).await;
    let receipt = entries_before
        .iter()
        .find(|entry| entry["call_id"] == "replay-write")
        .expect("write receipt")
        .clone();
    let messages_before = http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(&cycle.token),
            None,
        )
        .await;
    assert_eq!(messages_before.0, 200);
    let messages_before = messages_before.1["data"].clone();
    let finalize_message = messages_before
        .as_array()
        .expect("session messages")
        .iter()
        .find(|message| {
            message["run_id"] == json!(run_id)
                && message["content"].to_string().contains("replay-done")
        })
        .expect("durable committed assistant message")
        .clone();

    // Supported lifecycle stop, then reopen the exact original root.
    http.close().await;
    shutdown_when_idle(&cycle.state).await;
    drop(persistence);
    let reopened = cycle.reopen();
    let reopened_http = Http::bind(reopened.state.clone()).await;
    let reopened_persistence = reopened.state.persistence().expect("reopened persistence");
    // Formal redelivery of the original typed public request and proof.
    let never_called = Arc::new(ScriptedProvider::new());
    reopened
        .state
        .service()
        .inject_provider_host(never_called.clone());
    let (status, replayed) = reopened_http
        .request("POST", "/v1/runs", body, Some(&reopened.token), Some(&idem))
        .await;
    assert_eq!(status, 202, "{}", explain(status, &replayed));
    assert_eq!(replayed["run_id"], json!(run_id), "exact old run identity");
    let replayed_identity = json!({
        "run_id": replayed["run_id"],
        "graph_id": replayed["graph_id"],
        "workspace_branch": replayed["workspace_branch"],
        "epoch": replayed["epoch"],
    });
    let admitted_identity = json!({
        "run_id": admitted["run_id"],
        "graph_id": admitted["graph_id"],
        "workspace_branch": admitted["workspace_branch"],
        "epoch": admitted["epoch"],
    });
    assert_eq!(
        replayed_identity, admitted_identity,
        "the replay returns the exact old run/graph/branch/epoch identity"
    );
    assert_eq!(
        replayed["head_object_id"],
        json!(head_object),
        "replay projects the committed published head, not a stale envelope"
    );
    assert_eq!(replayed["head_version"], json!(head_version));
    // No provider/tool/OS action occurred on redelivery.
    assert!(
        never_called.requests().is_empty(),
        "formal replay invoked no provider: {:?}",
        never_called.requests()
    );
    let entries_after = run_effect_entries(&reopened_http, &reopened.token, &run_id).await;
    assert_eq!(
        entries_after, entries_before,
        "replay created no new tool/effect receipt"
    );
    // Event/message identities and ordering are unchanged.
    let events_after = reopened.state.service().run_events(&run_id);
    assert_eq!(events_after, events_before, "replay wrote no new run event");
    let published_after = events_after
        .iter()
        .find(|event| event["event"] == "workspace.published")
        .expect("replayed publication event");
    assert_eq!(published_after["event_id"], published_event_id);
    assert_eq!(published_after["seq"], published_seq);
    let published_request = published_after
        .get("request_id")
        .cloned()
        .or_else(|| published_after["data"].get("request_id").cloned());
    assert_eq!(
        published_request,
        Some(json!(request_id)),
        "the durable publication event keeps the frozen request UUID: {published_after}"
    );
    let completed_after = events_after
        .iter()
        .find(|event| event["event"] == "run.completed")
        .expect("replayed completion event");
    assert_eq!(completed_after["event_id"], completed_event_id);
    assert_eq!(completed_after["seq"], completed_seq);
    let messages_after = reopened_http
        .request(
            "GET",
            &format!("/api/sessions/{session_id}/messages"),
            json!(null),
            Some(&reopened.token),
            None,
        )
        .await;
    assert_eq!(messages_after.0, 200);
    let message_identity = |messages: &Value| {
        messages
            .as_array()
            .expect("session messages")
            .iter()
            .map(|message| {
                json!({
                    "id": message["id"],
                    "content": message["content"],
                    "run_id": message["run_id"],
                })
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        message_identity(&messages_after.1["data"]),
        message_identity(&messages_before),
        "replay inserted or replaced no message"
    );
    let finalize_after = messages_after.1["data"]
        .as_array()
        .expect("session messages")
        .iter()
        .find(|message| {
            message["run_id"] == json!(run_id)
                && message["content"].to_string().contains("replay-done")
        })
        .expect("replayed committed assistant message");
    assert_eq!(finalize_after["id"], finalize_message["id"]);
    // Pointer/receipt stay exactly at the original publication.
    let pointer_after = reopened_persistence
        .managed_workspace_publication(&workspace_id, "gateway")
        .expect("reopened pointer read")
        .expect("pointer survives restart");
    assert_eq!(pointer_after.revision, 1, "no new pointer revision");
    assert_eq!(pointer_after.request_id, request_id, "same request UUID");
    assert_eq!(pointer_after.branch_id, branch);
    assert_eq!(pointer_after.epoch, epoch);
    assert_eq!(pointer_after.head_object_id, head_object);
    assert_eq!(pointer_after.head_version, head_version);
    assert_eq!(
        receipt["state"], "committed",
        "the original write receipt is unchanged"
    );
    assert_closed(
        &admitted,
        &reopened.token,
        &[workspace.as_path(), source.as_path()],
    );
    reopened_http.close().await;
    shutdown_when_idle(&reopened.state).await;
}

/// One real Required admitted run parked at the exact precommit pause with a
/// genuinely committed tool write. Shared by the T10 drift cases: the run,
/// branch, epoch and previously committed output are otherwise legitimate, so
/// only the named fact differs.
struct PausedRequiredRun {
    cycle: Cycle,
    http: Http,
    run_id: String,
    session_id: String,
    branch: String,
    epoch: u64,
}

impl PausedRequiredRun {
    async fn workspace_id(&self, call_id: &str) -> String {
        run_effect_entries(&self.http, &self.cycle.token, &self.run_id)
            .await
            .iter()
            .find(|entry| entry["call_id"] == json!(call_id))
            .and_then(|entry| entry["workspace_id"].as_str())
            .expect("previously committed managed effect workspace identity")
            .to_string()
    }
}

struct PauseControl {
    entered: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl PauseControl {
    async fn wait_entered(&self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if *self.entered.0.lock().expect("pause entered flag") {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the completion never reached its precommit pause"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn finish(&self) {
        let (flag, cv) = &*self.release;
        *flag.lock().expect("pause release flag") = true;
        cv.notify_all();
    }
}

/// Direct minimal helper: admit one real Required run that commits its tool
/// write, then hold it at the existing precommit pause (outside commit_gate).
/// The caller performs its own real work at the pause before `finish()`.
async fn admit_required_run_to_pause(
    label: &str,
    call_id: &'static str,
    marker: &'static str,
    fact_fault: Option<rustscript_agent::gateway::store::ManagedCompletionFactFault>,
) -> (PausedRequiredRun, PauseControl) {
    let cycle = Cycle::open_required(&format!("t16-{label}-{}", uuid::Uuid::new_v4().simple()));
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
    let persistence = cycle.state.persistence().expect("persistence");
    let provider = ScriptedProvider::new();
    provider.push_ok(tool_call(call_id, "write_file", marker));
    provider.push_ok(stop_turn("fact-done"));
    let gate = Arc::new(SecondBusinessGate::new(provider));
    cycle.state.service().inject_provider_host(gate.clone());
    let (status, session) = http
        .request("POST", "/api/sessions", json!({}), Some(&cycle.token), None)
        .await;
    assert_eq!(status, 201, "{}", explain(status, &session));
    let session_id = session["session"]["id"].as_str().unwrap().to_string();
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "commit one managed fact"}),
            Some(&cycle.token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let branch = admitted["workspace_branch"]
        .as_str()
        .expect("managed branch")
        .to_string();
    let epoch = admitted["epoch"].as_u64().expect("managed epoch");
    if let Some(fault) = fact_fault {
        // Armed for exactly this run before its completion can start: the
        // one-shot fact selector is consumed by that completion only.
        persistence.arm_managed_completion_fact_fault(&run_id, fault);
    }
    wait_until(|| gate.holding()).await;
    let entered = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let hook_entered = Arc::clone(&entered);
    let hook_release = Arc::clone(&release);
    persistence.arm_managed_publication_precommit_pause(&run_id, move || {
        let (flag, cv) = &*hook_entered;
        *flag.lock().expect("pause entered flag") = true;
        cv.notify_all();
        let (flag, cv) = &*hook_release;
        let mut released = flag.lock().expect("pause release flag");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !*released {
            assert!(
                std::time::Instant::now() < deadline,
                "the pause was never released"
            );
            let (guard, _) = cv
                .wait_timeout(released, Duration::from_millis(50))
                .expect("pause wait");
            released = guard;
        }
    });
    gate.release();
    let control = PauseControl { entered, release };
    control.wait_entered().await;
    (
        PausedRequiredRun {
            cycle,
            http,
            run_id,
            session_id,
            branch,
            epoch,
        },
        control,
    )
}

/// The refused completion leaves the exact pre-publication disposition: no
/// pointer, no publication event, the single failed terminal through the
/// existing disposition, and no committed finalize message.
async fn assert_refused_without_publication(
    run: &PausedRequiredRun,
    workspace_id: &str,
    expected_publication_status: &str,
) {
    let events = tokio::time::timeout(
        Duration::from_secs(20),
        run.http.typed_sse(&run.cycle.token, &run.run_id),
    )
    .await
    .expect("the refused completion terminates");
    assert_typed_terminal(&events, "run.failed");
    assert!(
        !events
            .iter()
            .any(|event| event.name == "workspace.published" || event.name == "run.completed"),
        "the RSS transaction must refuse before any publication event: {events:?}"
    );
    let raw = run.http.raw_sse(&run.cycle.token, &run.run_id).await;
    let failed = raw
        .iter()
        .find(|value| value["event"] == "run.failed")
        .expect("durable refused terminal");
    assert_eq!(
        failed["error_code"], "managed_publication_conflict",
        "the claimed publication was refused, not silently dropped: {failed}"
    );
    assert_eq!(
        failed["publication"]["status"], expected_publication_status,
        "the refusal reports its existing verified disposition: {failed}"
    );
    let persistence = run.cycle.state.persistence().expect("persistence");
    assert_eq!(
        persistence
            .managed_workspace_publication(workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "the refused publication left no pointer"
    );
    let (status, messages) = run
        .http
        .request(
            "GET",
            &format!("/api/sessions/{}/messages", run.session_id),
            json!(null),
            Some(&run.cycle.token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{}", explain(status, &messages));
    assert!(
        !messages["data"]
            .as_array()
            .expect("session messages")
            .iter()
            .any(|message| message["run_id"] == json!(run.run_id)
                && message["id"]
                    .as_str()
                    .is_some_and(|id| id.ends_with(":finalize:message"))),
        "the refused transaction inserted no finalize message: {messages}"
    );
}

/// Exactly the one previously committed write survives with this run's real
/// branch/epoch identity; the publication itself added nothing.
async fn assert_committed_output_preserved(run: &PausedRequiredRun, call_id: &str) -> Vec<Value> {
    let entries = run_effect_entries(&run.http, &run.cycle.token, &run.run_id).await;
    let written = entries
        .iter()
        .find(|entry| entry["call_id"] == json!(call_id))
        .unwrap_or_else(|| panic!("committed write receipt missing: {entries:?}"));
    assert_eq!(written["state"], "committed", "{entries:?}");
    assert_eq!(written["branch_id"], json!(run.branch));
    assert_eq!(written["epoch"], json!(run.epoch));
    entries
}

/// T10 (a): the precommit pause really replaces the test-owned admitted source
/// directory with an equal-bytes tree at another inode while the captured root
/// capability and its seed stay intact. The Required completion must stat the
/// fresh source path (not the already-captured dirfd) and the existing RSS
/// publication transaction must refuse it against the durable captured source
/// identity, leaving the pointer/receipt/output untouched.
#[tokio::test(flavor = "multi_thread")]
async fn required_finalize_rejects_replaced_source_identity() {
    let (run, pause) = admit_required_run_to_pause(
        "source-replace",
        "write-source",
        "source-replace-out.txt",
        None,
    )
    .await;
    let workspace = run.cycle.workspace.clone();
    let backup = workspace.with_file_name("workspace-original");
    // The run's own committed receipt and pre-publication pointer are read
    // before the replacement, while the durable source identity still resolves.
    let workspace_id = run.workspace_id("write-source").await;
    assert_eq!(
        run.cycle
            .state
            .persistence()
            .expect("persistence")
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "the paused completion has published nothing yet"
    );
    assert_committed_output_preserved(&run, "write-source").await;
    let original_identity = {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(&workspace).expect("admitted root before replacement");
        (metadata.dev(), metadata.ino())
    };
    std::fs::rename(&workspace, &backup).expect("move the admitted root aside");
    std::fs::create_dir(&workspace).expect("create the replacement path");
    std::fs::write(workspace.join("seed.txt"), b"seed")
        .expect("equal seed bytes at the other inode");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700))
            .expect("replacement permissions");
    }
    let fresh_identity = {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(&workspace).expect("fresh source path");
        (metadata.dev(), metadata.ino())
    };
    assert_eq!(
        std::fs::read(workspace.join("seed.txt")).expect("replacement seed bytes"),
        b"seed",
        "the real replacement keeps the original seed bytes"
    );
    assert_ne!(
        fresh_identity, original_identity,
        "the fresh source path must be a different inode than the captured root"
    );
    // The captured root capability still resolves to the original inode.
    assert_eq!(
        std::fs::metadata(&backup)
            .map(|metadata| {
                use std::os::unix::fs::MetadataExt;
                (metadata.dev(), metadata.ino())
            })
            .expect("retained original tree"),
        original_identity,
        "the captured root itself is preserved"
    );
    pause.finish();
    assert_refused_without_publication(&run, &workspace_id, "not_published").await;
    // Restore the original owned tree so the retained root capability and seed
    // stay auditable after the case ends.
    std::fs::remove_dir_all(&workspace).expect("remove the replacement tree");
    std::fs::rename(&backup, &workspace).expect("restore the admitted root");
    // The read-only effect projection re-resolves the live source identity, so
    // the preserved receipt is read after the original tree is restored.
    assert_committed_output_preserved(&run, "write-source").await;
    run.http.close().await;
    shutdown_when_idle(&run.cycle.state).await;
}

/// T10 (b): the one-shot Native producer-boundary fault advances the owner's
/// current workspace epoch past the generation captured by the admitted
/// grant. The Required completion must compare the two real values (a frozen
/// read compared with itself is not the fact) and refuse before the claimed
/// send, leaving the pointer and committed output untouched.
#[tokio::test(flavor = "multi_thread")]
async fn required_finalize_rejects_stale_captured_authority_generation() {
    let (run, pause) = admit_required_run_to_pause(
        "stale-generation",
        "write-generation",
        "generation-out.txt",
        Some(rustscript_agent::gateway::store::ManagedCompletionFactFault::AuthorityGeneration),
    )
    .await;
    let workspace_id = run.workspace_id("write-generation").await;
    pause.finish();
    assert_refused_without_publication(&run, &workspace_id, "conflict").await;
    assert_committed_output_preserved(&run, "write-generation").await;
    run.http.close().await;
    shutdown_when_idle(&run.cycle.state).await;
}

/// T10 (c): the one-shot Native producer-boundary fault freezes the expected
/// head with an epoch the admitted branch no longer has. The real claimed
/// publication command reaches the existing exact branch guard and aborts
/// there; the pointer, committed output and disposition are unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn required_finalize_rejects_stale_binding_epoch() {
    let (run, pause) = admit_required_run_to_pause(
        "stale-epoch",
        "write-epoch",
        "epoch-out.txt",
        Some(rustscript_agent::gateway::store::ManagedCompletionFactFault::BindingEpoch),
    )
    .await;
    let workspace_id = run.workspace_id("write-epoch").await;
    pause.finish();
    assert_refused_without_publication(&run, &workspace_id, "not_published").await;
    assert_committed_output_preserved(&run, "write-epoch").await;
    run.http.close().await;
    shutdown_when_idle(&run.cycle.state).await;
}

/// T10 (d): the one-shot Native producer-boundary fault freezes a stale
/// managed-branch schema version in the expected head. The real claimed
/// publication command reaches the existing exact branch guard and aborts
/// there; no pointer, event or message is written.
#[tokio::test(flavor = "multi_thread")]
async fn required_finalize_rejects_stale_branch_schema() {
    let (run, pause) = admit_required_run_to_pause(
        "stale-schema",
        "write-schema",
        "schema-out.txt",
        Some(rustscript_agent::gateway::store::ManagedCompletionFactFault::BranchSchema),
    )
    .await;
    let workspace_id = run.workspace_id("write-schema").await;
    pause.finish();
    assert_refused_without_publication(&run, &workspace_id, "not_published").await;
    assert_committed_output_preserved(&run, "write-schema").await;
    run.http.close().await;
    shutdown_when_idle(&run.cycle.state).await;
}

/// T10 (e): a genuine quiescent background process makes the branch lineage
/// tainted. The approved one-shot consultation observes the unchanged
/// lineage into the real claimed RSS publication; the absolute `taint=0`
/// success predicate must refuse it even though the frozen expected head
/// agrees that the branch is tainted, and the earlier Native refusal is not
/// the deciding stage here.
#[tokio::test(flavor = "multi_thread")]
async fn required_finalize_transaction_refuses_tainted_lineage() {
    let PlainProcessRun {
        root: _root,
        workspace,
        home: _home,
        source,
        token,
        session_id,
        state,
        http,
    } = open_plain_required_process("taint-txn").await;
    let persistence = state.persistence().expect("persistence");
    let provider = Arc::new(ProcessLifecycleProvider::close_and_wait());
    state.service().inject_provider_host(provider);
    let (status, admitted) = http
        .request(
            "POST",
            "/v1/runs",
            json!({"session_id": session_id, "input": "own one background group"}),
            Some(&token),
            Some(&uuid::Uuid::new_v4().to_string()),
        )
        .await;
    assert_eq!(status, 202, "{}", explain(status, &admitted));
    let run_id = admitted["run_id"].as_str().unwrap().to_string();
    let branch = admitted["workspace_branch"]
        .as_str()
        .expect("managed branch")
        .to_string();
    let epoch = admitted["epoch"].as_u64().expect("managed epoch");
    // The negative control names only this run, and only the already-approved
    // consultation of the Native taint return: OS quiescence, the owner proof
    // and the tainted lineage producer stay unchanged.
    persistence.arm_managed_completion_fact_fault(
        &run_id,
        rustscript_agent::gateway::store::ManagedCompletionFactFault::TaintedLineageRefusal,
    );
    let progress = std::time::Instant::now() + Duration::from_secs(30);
    while event_names(&state, &run_id)
        .iter()
        .filter(|name| *name == "tool.completed")
        .count()
        < 3
    {
        assert!(
            std::time::Instant::now() < progress,
            "the process run never reached its group controls: {:?}",
            state.service().run_events(&run_id)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let events = tokio::time::timeout(Duration::from_secs(30), http.typed_sse(&token, &run_id))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the tainted-lineage run never terminated; events={:?}",
                state.service().run_events(&run_id)
            )
        });
    assert_typed_terminal(&events, "run.failed");
    assert!(
        !events
            .iter()
            .any(|event| event.name == "workspace.published" || event.name == "run.completed"),
        "a tainted lineage publishes nothing: {events:?}"
    );
    let raw = http.raw_sse(&token, &run_id).await;
    let failed = raw
        .iter()
        .find(|value| value["event"] == "run.failed")
        .expect("durable refusal payload");
    assert_eq!(
        failed["error_code"], "managed_publication_conflict",
        "the real claimed RSS publication refused the taint, not the earlier Native return: {failed}"
    );
    assert_ne!(failed["error_code"], "managed_process_lineage_unsupported");
    assert_eq!(failed["publication"]["status"], "not_published");
    let entries = run_effect_entries(&http, &token, &run_id).await;
    let workspace_id = entries
        .iter()
        .find(|entry| entry["call_id"] == "process-spawn")
        .and_then(|entry| entry["workspace_id"].as_str())
        .expect("spawn effect workspace")
        .to_string();
    // The taint is a real, unchanged durable fact: the same branch the
    // publication transaction guarded is tainted.
    let head = persistence
        .managed_workspace_head(&rustscript_agent::effects::ManagedWorkspaceIdentity {
            store_id: "unused-for-head".into(),
            workspace_id: workspace_id.clone(),
            branch_id: branch.clone(),
            source_identity: rustscript_agent::effects::DirectoryIdentity {
                device_decimal: "unused-for-head".into(),
                inode_decimal: "unused-for-head".into(),
            },
        })
        .expect("durable head read");
    assert!(
        head.process_lineage_tainted,
        "the refused branch lineage is genuinely tainted"
    );
    assert_eq!(head.epoch, epoch);
    assert_eq!(
        persistence
            .managed_workspace_publication(&workspace_id, "gateway")
            .expect("pointer read"),
        None,
        "the tainted-lineage transaction left no pointer"
    );
    let spawn = entries
        .iter()
        .find(|entry| entry["call_id"] == "process-spawn")
        .expect("spawn effect");
    assert_eq!(spawn["state"], "read_only");
    let close = entries
        .iter()
        .find(|entry| entry["call_id"] == "process-close")
        .expect("stdin close effect");
    assert_eq!(close["state"], "read_only");
    let wait = entries
        .iter()
        .find(|entry| entry["call_id"] == "process-wait")
        .expect("group wait effect");
    assert_eq!(wait["state"], "committed");
    assert!(
        marker_pids("t16-group-ready").is_empty(),
        "no produced child may survive the refused quiescent group completion"
    );
    let _ = workspace;
    let _ = source;
    http.close().await;
    shutdown_when_idle(&state).await;
}
