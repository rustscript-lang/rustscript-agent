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
    cycle.state.service().inject_provider_host(restored_provider);
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
    let restored_projection =
        projected_run(&http, &cycle.token, &new_session, &new_run).await;
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
