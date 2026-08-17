//! A9 manual session compaction — HTTP end-to-end fixtures through the REAL
//! router, the REAL AgentService `compact_session` composition, the REAL
//! `compact.rss` policy, and the REAL SQLite state (phase-1 durably seeded
//! history, phase-2 gateway so `load()` hydrates the mirror exactly as a
//! restart would).
//!
//! Coverage: pair-preserving boundary (naive boundary on an assistant
//! tool-call message is pushed past its tool result), the documented
//! full-compaction rule, typed skips with zero durable writes, active /
//! compacting run conflicts (409), the double-request race (exactly one
//! committed compaction), storage failure (typed 503, nothing created),
//! retry after a durable failure (same canonical compaction id), restart
//! after start (recovery fails the leftover, retry commits), and the auth /
//! session boundary.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use rustscript_agent::{AgentGatewayConfig, AgentGatewayState, build_agent_gateway_app};
use serde_json::{Value as JsonValue, json};
use tower::ServiceExt;
use uuid::Uuid;

fn temporary_root(label: &str) -> PathBuf {
    let base = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("rustscript-agent-a9-compact-tests"));
    let root = base.join(format!(
        "{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temporary root should be created");
    root
}

/// The gateway config for compaction fixtures: a small window so a handful
/// of seeded messages trigger a compaction, with a durable SQLite state.
fn compact_config(mutate: impl FnOnce(&mut AgentGatewayConfig)) -> AgentGatewayConfig {
    let mut config = AgentGatewayConfig {
        model: "test-model".to_string(),
        max_context_messages: 4,
        retained_tail: 2,
        ..AgentGatewayConfig::default()
    };
    mutate(&mut config);
    config
}

fn open_state(path: &Path, mutate: impl FnOnce(&mut AgentGatewayConfig)) -> AgentGatewayState {
    AgentGatewayState::with_sqlite_path(compact_config(mutate), path)
        .expect("gateway state with SQLite should open")
}

/// Phase 1: opens a gateway on `path`, creates the session through the real
/// API route, appends the canonical history durably (the exact message
/// payload shape the service persists), and drops the gateway. Phase 2
/// reopens `path`, so the in-memory mirror is hydrated from the durable rows
/// exactly like a restart — and compaction plans over REAL rows.
async fn seed_session_history(
    path: &Path,
    session_id: &str,
    messages: &[JsonValue],
    mutate: impl FnOnce(&mut AgentGatewayConfig),
) {
    let state = open_state(path, mutate);
    let app = build_agent_gateway_app(state.clone());
    let (status, body) = post_request(
        &app,
        "/api/sessions",
        Some(json!({"id": session_id, "source": "test", "model": "test-model"})),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "session creation must succeed: {body}"
    );
    let persistence = state.persistence().expect("durable persistence");
    for (index, message) in messages.iter().enumerate() {
        let payload = json!({
            "id": format!("seed-{}", Uuid::new_v4()),
            "session_id": session_id,
            "role": message["role"].as_str().unwrap_or(""),
            "content_json": serde_json::to_string(&message["content"])
                .unwrap_or_else(|_| "[]".to_string()),
            "name": "",
            "tool_call_id": message["tool_call_id"].as_str().unwrap_or(""),
            "parent_message_id": "",
            "token_estimate": 0,
            "metadata_json": "{}",
            "run_id": "",
            "finish_reason": "",
            "now_ms": 1_700_000_000_000_u64 + index as u64,
        });
        persistence
            .message_append(&payload)
            .expect("durable seed message append must succeed");
    }
    drop(state);
    drop(app);
}

/// One canonical message for the RSS policy history.
fn message(role: &str, tool_call_id: &str, parts: JsonValue) -> JsonValue {
    json!({
        "role": role,
        "tool_call_id": tool_call_id,
        "content": parts,
    })
}

fn text_part(text: &str) -> JsonValue {
    json!({"type": "text", "text": text})
}

fn tool_call_part(id: &str) -> JsonValue {
    json!({
        "type": "tool_call",
        "tool_call_id": id,
        "name": "file.write",
        "arguments_json": "{}",
    })
}

fn tool_result_part(id: &str) -> JsonValue {
    json!({
        "type": "tool_result",
        "tool_call_id": id,
        "content": "ok",
        "is_error": false,
    })
}

/// 8-message history where the naive boundary (n - retained_tail = 6) lands
/// EXACTLY on an assistant tool-call message whose tool result sits at
/// ordinal 7: the pair-preserving fixpoint must push the boundary to 7 and
/// keep only message 8 as the retained tail.
fn pair_boundary_history() -> Vec<JsonValue> {
    vec![
        message("user", "", json!([text_part("u1")])),
        message("assistant", "", json!([text_part("a1")])),
        message("user", "", json!([text_part("u2")])),
        message("assistant", "", json!([text_part("a2")])),
        message("user", "", json!([text_part("u3")])),
        message("assistant", "", json!([tool_call_part("call-1")])),
        message("tool", "call-1", json!([tool_result_part("call-1")])),
        message("user", "", json!([text_part("u4")])),
    ]
}

/// 7-message history whose naive boundary (n - retained_tail = 6) lands on an
/// assistant tool-call whose result is the LAST message: the documented
/// full-compaction rule — the fixpoint reaches n and the tail is empty.
fn full_compaction_history() -> Vec<JsonValue> {
    vec![
        message("user", "", json!([text_part("u1")])),
        message("assistant", "", json!([text_part("a1")])),
        message("user", "", json!([text_part("u2")])),
        message("assistant", "", json!([text_part("a2")])),
        message("user", "", json!([text_part("u3")])),
        message("assistant", "", json!([tool_call_part("call-1")])),
        message("tool", "call-1", json!([tool_result_part("call-1")])),
    ]
}

async fn post_request(
    app: &axum::Router,
    uri: &str,
    body: Option<JsonValue>,
    bearer: Option<&str>,
) -> (StatusCode, JsonValue) {
    let mut builder = Request::builder().method(Method::POST).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let body = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).expect("request should build"))
        .await
        .expect("router should respond");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body should be readable");
    (
        status,
        serde_json::from_slice(&body).expect("response should be JSON"),
    )
}

/// The latest durable compaction row for one session (compaction.latest row
/// shape: id, session_id, run_id, generation, source_start_ordinal,
/// source_end_ordinal, retained_tail_ordinal, summary_json, token_estimate,
/// model, state, error_message, created_at_ms, completed_at_ms).
fn durable_compaction(state: &AgentGatewayState, session_id: &str) -> Option<Vec<JsonValue>> {
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence
        .compaction_latest(session_id)
        .expect("compaction.latest must succeed");
    data.get("rows")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(JsonValue::as_array)
        .cloned()
}

fn durable_compaction_count(state: &AgentGatewayState, session_id: &str) -> usize {
    state
        .persistence()
        .expect("durable persistence")
        .compaction_latest(session_id)
        .expect("compaction.latest must succeed")
        .get("rows")
        .and_then(JsonValue::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn durable_run_status(state: &AgentGatewayState, run_id: &str) -> String {
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence.run_get(run_id).expect("run.get must succeed");
    data.get("rows")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(JsonValue::as_array)
        .and_then(|row| row.get(3))
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string()
}

fn durable_session_generation(state: &AgentGatewayState, session_id: &str) -> u64 {
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence.session_get(session_id).expect("session.get");
    data.get("rows")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(JsonValue::as_array)
        .and_then(|row| row.get(7))
        .and_then(JsonValue::as_u64)
        .unwrap_or(0)
}

/// The maintenance run's durable events: (event_type, payload).
fn durable_run_events(state: &AgentGatewayState, run_id: &str) -> Vec<(String, JsonValue)> {
    let persistence = state.persistence().expect("durable persistence");
    let data = persistence
        .event_replay(&json!({
            "run_id": run_id,
            "after_seq": 1,
            "max_events": 512,
            "max_bytes": 65536,
        }))
        .expect("event replay");
    data.get("rows")
        .and_then(JsonValue::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(|row| {
                    let row = row.as_array()?;
                    let event_type = row.get(3)?.as_str()?.to_string();
                    let payload: JsonValue =
                        serde_json::from_str(row.get(4)?.as_str().unwrap_or("{}"))
                            .unwrap_or(JsonValue::Null);
                    Some((event_type, payload))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Crafts the durable mid-flight state exactly as the service leaves it:
/// a maintenance run durably `compacting` plus a pending compaction row for
/// the target (session, generation). Returns the run id.
fn craft_compacting_state(
    state: &AgentGatewayState,
    session_id: &str,
    run_id: &str,
    generation: i64,
    start: i64,
    end: i64,
    tail: i64,
) {
    let persistence = state.persistence().expect("durable persistence");
    let now = 1_700_000_000_000_i64;
    let run = json!({
        "id": run_id,
        "session_id": session_id,
        "parent_run_id": "",
        "input_json": json!({"kind": "session_compaction"}).to_string(),
        "provider": "",
        "model": "test-model",
        "script_hash": "compact",
        "idempotency_scope": "",
        "idempotency_key": "",
        "now_ms": now,
    });
    persistence
        .run_create(&run)
        .expect("run.create must succeed");
    for (from, to) in [("queued", "running"), ("running", "compacting")] {
        let transition = json!({
            "run_id": run_id,
            "from_status": from,
            "to_status": to,
            "error_code": "",
            "error_message": "",
            "recovery_reason": "",
            "now_ms": now,
        });
        persistence
            .run_transition(&transition)
            .expect("crafted transition must succeed");
    }
    let start_payload = json!({
        "id": format!("compact:{session_id}:{generation}"),
        "session_id": session_id,
        "run_id": run_id,
        "generation": generation,
        "source_start_ordinal": start,
        "source_end_ordinal": end,
        "retained_tail_ordinal": tail,
        "summary_json": json!({
            "count": end - start + 1,
            "source_start_ordinal": start,
            "source_end_ordinal": end,
            "retained_tail_ordinal": tail,
        }).to_string(),
        "token_estimate": 0,
        "model": "test-model",
        "now_ms": now,
    });
    persistence
        .compaction_start(&start_payload)
        .expect("compaction.start must succeed");
}

// ---------------------------------------------------------------------------
// RED: pair boundary and real values
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_commits_pair_preserving_range_and_real_values() {
    let root = temporary_root("a9-pair");
    let db = root.join("state.db");
    let session_id = "pair-session";
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;
    let state = open_state(&db, |_| {});
    let app = build_agent_gateway_app(state.clone());

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "compact must commit: {body}");
    assert_eq!(body["object"], json!("hermes.compaction"));
    assert_eq!(body["status"], json!("committed"));
    assert_eq!(
        body["compaction_id"],
        json!(format!("compact:{session_id}:2")),
        "the canonical service-owned compaction id"
    );
    assert_eq!(body["generation"], json!(2));
    // The naive boundary (8 - 2 = 6) lands on the assistant tool-call at
    // ordinal 6; pair preservation must push it to 7 (its tool result).
    assert_eq!(body["source_start_ordinal"], json!(1));
    assert_eq!(body["source_end_ordinal"], json!(7));
    assert_eq!(body["retained_tail_ordinal"], json!(7));
    assert_eq!(body["session_id"], json!(session_id));

    // Durable truth: one committed row with the same values.
    let row = durable_compaction(&state, session_id).expect("committed row");
    assert_eq!(row[0], json!(format!("compact:{session_id}:2")));
    assert_eq!(row[3], json!(2));
    assert_eq!(row[4], json!(1));
    assert_eq!(row[5], json!(7));
    assert_eq!(row[6], json!(7));
    assert_eq!(row[10], json!("committed"));
    assert_eq!(durable_session_generation(&state, session_id), 2);

    // The maintenance run is durably terminal (completed) and auditable.
    let maintenance_run = row[2].as_str().expect("maintenance run id").to_string();
    assert!(
        maintenance_run.starts_with(&format!("compact-run:{session_id}:2:")),
        "bounded maintenance run id: {maintenance_run}"
    );
    assert_eq!(durable_run_status(&state, &maintenance_run), "completed");

    // Exact-once event trail: compact.started + compact.completed + the
    // run.status_changed chain (queued->running, running->compacting,
    // compacting->completed).
    let events = durable_run_events(&state, &maintenance_run);
    let types = events
        .iter()
        .map(|(event_type, _)| event_type.as_str())
        .collect::<Vec<_>>();
    assert!(
        types.contains(&"compact.started") && types.contains(&"compact.completed"),
        "compaction events must be durably appended: {types:?}"
    );
    assert_eq!(
        types.iter().filter(|t| **t == "run.status_changed").count(),
        3,
        "one status event per transition: {types:?}"
    );
    let (_, started) = events
        .iter()
        .find(|(event_type, _)| event_type == "compact.started")
        .expect("compact.started event");
    assert_eq!(
        started["compaction_id"],
        json!(format!("compact:{session_id}:2"))
    );
    let (_, completed) = events
        .iter()
        .find(|(event_type, _)| event_type == "compact.completed")
        .expect("compact.completed event");
    assert_eq!(completed["ok"], json!(true));

    // In-memory mirror: the covered range is compacted, the tail is not —
    // read through the public messages route (the mirror is the store).
    let (_, messages) =
        get_request(&app, &format!("/api/sessions/{session_id}/messages"), None).await;
    let compacted_flags = messages["data"]
        .as_array()
        .expect("message list")
        .iter()
        .map(|message| message["compacted"].as_bool().unwrap_or(false))
        .collect::<Vec<_>>();
    assert_eq!(
        compacted_flags,
        vec![true, true, true, true, true, true, true, false],
        "the mirror must mark exactly the covered range compacted"
    );

    // A second compact in the same session plans over the compacted mirror
    // (only the tail message remains in context) and the advanced
    // generation: it is a typed skip, never a second compaction.
    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "second compact: {body}");
    assert_eq!(body["status"], json!("skipped"));
    assert_eq!(durable_compaction_count(&state, session_id), 1);

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_full_history_rule_when_tail_would_split_a_pair() {
    let root = temporary_root("a9-full");
    let db = root.join("state.db");
    let session_id = "full-session";
    // The documented full-compaction rule uses retained_tail = 1 so the
    // naive boundary lands on the assistant tool-call itself.
    seed_session_history(&db, session_id, &full_compaction_history(), |config| {
        config.retained_tail = 1;
    })
    .await;
    let state = open_state(&db, |config| {
        config.retained_tail = 1;
    });
    let app = build_agent_gateway_app(state.clone());

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "compact must commit: {body}");
    assert_eq!(body["status"], json!("committed"));
    // The documented full-compaction rule: the fixpoint reaches n (7) and
    // the retained tail is empty.
    assert_eq!(body["source_end_ordinal"], json!(7));
    assert_eq!(body["retained_tail_ordinal"], json!(7));
    assert_eq!(body["generation"], json!(2));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// RED: typed skips with zero durable writes
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_within_window_is_typed_skip_without_durable_writes() {
    let root = temporary_root("a9-skip");
    let db = root.join("state.db");
    let session_id = "skip-session";
    let history = vec![
        message("user", "", json!([text_part("u1")])),
        message("assistant", "", json!([text_part("a1")])),
        message("user", "", json!([text_part("u2")])),
    ];
    seed_session_history(&db, session_id, &history, |_| {}).await;
    let state = open_state(&db, |_| {});
    let app = build_agent_gateway_app(state.clone());

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a skip is a valid answer: {body}");
    assert_eq!(body["object"], json!("hermes.compaction"));
    assert_eq!(body["status"], json!("skipped"));
    assert_eq!(body["reason"], json!("history_within_window"));
    assert_eq!(
        durable_compaction_count(&state, session_id),
        0,
        "a skip must never create a compaction row"
    );
    assert_eq!(
        durable_session_generation(&state, session_id),
        1,
        "a skip must never advance the generation"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_empty_session_is_typed_skip() {
    let root = temporary_root("a9-empty");
    let db = root.join("state.db");
    let session_id = "empty-session";
    seed_session_history(&db, session_id, &[], |_| {}).await;
    let state = open_state(&db, |_| {});
    let app = build_agent_gateway_app(state.clone());

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an empty session is a valid skip: {body}"
    );
    assert_eq!(body["status"], json!("skipped"));
    assert_eq!(durable_compaction_count(&state, session_id), 0);

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// RED: active / compacting run conflicts (typed 409)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_active_run_conflict_409_and_run_untouched() {
    let root = temporary_root("a9-active");
    let server = spawn_scripted_server(
        vec![(
            200,
            wire_tool_calls(json!([tool_call(
                "call-1",
                "file.write",
                json!({"path": root.join("raced.txt"), "content": "x"})
            )])),
        )],
        0,
    );
    let mut config = compact_config(|_| {});
    config.approval_mode = "manual".to_string();
    config.stream = false;
    config.provider = Some("openai_chat".to_string());
    config.provider_options = json!({
        "base_url": format!("http://127.0.0.1:{}", server.port()),
        "api_key": "test-key",
        "model": "test-model"
    });
    config.http = rustscript_vm::HttpConfig {
        allowed_schemes: vec!["http".to_string()],
        allowed_hosts: vec!["127.0.0.1".to_string()],
        allowed_ports: vec![server.port()],
        allow_private_ips: true,
        ..rustscript_vm::HttpConfig::default()
    };
    config.run_timeout = Duration::from_secs(60);
    let state =
        AgentGatewayState::with_default_agent_program_and_sqlite(config, root.join("state.db"))
            .expect("gateway with the built-in program");
    let app = build_agent_gateway_app(state.clone());

    // A REAL active run parked on a pending approval (waiting_approval).
    let (status, run) = post_request(&app, "/v1/runs", Some(json!({"input": "hello"})), None).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let run_id = run["run_id"].as_str().expect("run id").to_string();
    wait_for_durable_status(&state, &run_id, "waiting_approval").await;
    let session_id = {
        let (_, view) = get_request(&app, &format!("/v1/runs/{run_id}"), None).await;
        view["session_id"].as_str().expect("session id").to_string()
    };

    // The manual compact is refused while the run is active: typed 409 and
    // the run stays parked and resolvable.
    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], json!("run_active_conflict"));
    assert_eq!(durable_compaction_count(&state, &session_id), 0);
    assert_eq!(durable_run_status(&state, &run_id), "waiting_approval");

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_durable_compacting_run_conflict_409() {
    let root = temporary_root("a9-compacting");
    let db = root.join("state.db");
    let session_id = "crafted-session";
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;
    let state = open_state(&db, |_| {});
    let app = build_agent_gateway_app(state.clone());

    // A run durably in `compacting` (as a crashed cross-process compactor
    // would leave one) is a conflict even though no in-memory handle exists.
    craft_compacting_state(&state, session_id, "other-process-run", 2, 1, 7, 7);

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], json!("run_active_conflict"));
    assert_eq!(
        durable_compaction_count(&state, session_id),
        1,
        "the crafted pending row is untouched"
    );
    assert_eq!(
        durable_run_status(&state, "other-process-run"),
        "compacting"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// RED: double-request race — exactly once
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_double_compact_race_is_exactly_once() {
    let root = temporary_root("a9-race");
    let db = root.join("state.db");
    let session_id = "race-session";
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;
    let state = open_state(&db, |_| {});
    let app = build_agent_gateway_app(state.clone());

    let app_a = app.clone();
    let app_b = app.clone();
    let uri_a = format!("/api/sessions/{session_id}/compact");
    let uri_b = uri_a.clone();
    let (first, second) = tokio::join!(
        async move { post_request(&app_a, &uri_a, None, None).await },
        async move { post_request(&app_b, &uri_b, None, None).await },
    );

    let committed = [&first, &second]
        .iter()
        .filter(|(_, body)| body["status"] == json!("committed"))
        .count();
    assert_eq!(
        committed, 1,
        "exactly one request may commit: first={first:?} second={second:?}"
    );
    // The loser is either the in-process race guard (409 compaction_in_progress)
    // or a sequential interleaving where the second plan found the history
    // within the window (200 skipped) — never a second committed row.
    for (status, body) in [&first, &second] {
        if body["status"] == json!("committed") {
            continue;
        }
        let ok_skipped = *status == StatusCode::OK && body["status"] == json!("skipped");
        let in_progress = *status == StatusCode::CONFLICT
            && body["error"]["code"] == json!("compaction_in_progress");
        assert!(
            ok_skipped || in_progress,
            "the loser must be a typed skip or in-progress conflict: {status} {body}"
        );
    }

    // Exactly one durable row, generation advanced exactly once.
    assert_eq!(durable_compaction_count(&state, session_id), 1);
    assert_eq!(durable_session_generation(&state, session_id), 2);
    let row = durable_compaction(&state, session_id).expect("committed row");
    assert_eq!(row[10], json!("committed"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// RED: storage failure — typed 503, nothing created
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_storage_failure_before_any_write_503() {
    let root = temporary_root("a9-storage");
    let db = root.join("state.db");
    let session_id = "storage-session";
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;
    let state = open_state(&db, |_| {});
    let app = build_agent_gateway_app(state.clone());

    // Kill the storage worker: every durable command fails typed.
    state.persistence().expect("persistence").shutdown();

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], json!("persistence_unavailable"));
    drop(state);

    // The failed request must have created nothing: a fresh gateway on the
    // same database reads the durable truth (no rows, no runs).
    let restored = open_state(&db, |_| {});
    assert_eq!(
        durable_compaction_count(&restored, session_id),
        0,
        "a failed compact must never create a row"
    );
    let runs = restored
        .persistence()
        .expect("durable persistence")
        .run_list(session_id, "")
        .expect("run.list must succeed");
    assert_eq!(
        runs["rows"].as_array().map(Vec::len).unwrap_or(0),
        0,
        "a failed compact must never create a maintenance run"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// RED: retry after a durable failure reuses the canonical compaction id
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_retry_after_durable_failure_reuses_compaction_id() {
    let root = temporary_root("a9-retry");
    let db = root.join("state.db");
    let session_id = "retry-session";
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;
    let state = open_state(&db, |_| {});
    let app = build_agent_gateway_app(state.clone());

    // The durable failure state exactly as the failure path leaves it: a
    // failed pending row (same canonical id) and its maintenance run failed.
    craft_compacting_state(&state, session_id, "failed-run", 2, 1, 7, 7);
    let persistence = state.persistence().expect("durable persistence");
    persistence
        .compaction_fail(&json!({
            "id": format!("compact:{session_id}:2"),
            "error_message": "injected failure",
            "completed_at_ms": 1_700_000_000_100_i64,
        }))
        .expect("compaction.fail must succeed");
    persistence
        .run_transition(&json!({
            "run_id": "failed-run",
            "from_status": "compacting",
            "to_status": "failed",
            "error_code": "compaction_failed",
            "error_message": "injected failure",
            "recovery_reason": "",
            "now_ms": 1_700_000_000_100_i64,
        }))
        .expect("run failure transition must succeed");
    let row = durable_compaction(&state, session_id).expect("failed row");
    assert_eq!(row[10], json!("failed"));

    // The retry must commit the SAME canonical compaction id (the storage
    // layer's failed-row reset) and advance the generation exactly once.
    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the retry must commit: {body}");
    assert_eq!(body["status"], json!("committed"));
    assert_eq!(
        body["compaction_id"],
        json!(format!("compact:{session_id}:2"))
    );
    assert_eq!(body["generation"], json!(2));

    let row = durable_compaction(&state, session_id).expect("committed row");
    assert_eq!(row[0], json!(format!("compact:{session_id}:2")));
    assert_eq!(row[10], json!("committed"));
    assert_eq!(durable_session_generation(&state, session_id), 2);
    let maintenance_run = row[2].as_str().expect("maintenance run id").to_string();
    assert_ne!(maintenance_run, "failed-run", "a fresh maintenance run");
    assert_eq!(durable_run_status(&state, &maintenance_run), "completed");

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// RED: restart after start — recovery fails the leftover, the retry commits
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_restart_after_start_recovers_and_retry_commits() {
    let root = temporary_root("a9-restart");
    let db = root.join("state.db");
    let session_id = "restart-session";
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;

    // Phase 1: the service crashed mid-flight — a durably compacting
    // maintenance run and a pending compaction row, then the gateway is
    // dropped without any terminal.
    {
        let state = open_state(&db, |_| {});
        craft_compacting_state(&state, session_id, "crashed-run", 2, 1, 7, 7);
        drop(state);
    }

    // Phase 2: reopening runs restart recovery — the compacting run is
    // failed and the pending compaction row is failed by the sweep.
    let state = open_state(&db, |_| {});
    assert_eq!(durable_run_status(&state, "crashed-run"), "failed");
    let row = durable_compaction(&state, session_id).expect("recovered row");
    assert_eq!(row[10], json!("failed"));
    let app = build_agent_gateway_app(state.clone());

    // The retry plans against the unchanged generation and commits with the
    // same canonical compaction id.
    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the restart retry must commit: {body}"
    );
    assert_eq!(
        body["compaction_id"],
        json!(format!("compact:{session_id}:2"))
    );
    assert_eq!(body["status"], json!("committed"));
    let row = durable_compaction(&state, session_id).expect("committed row");
    assert_eq!(row[10], json!("committed"));
    assert_eq!(durable_session_generation(&state, session_id), 2);

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// RED: auth and session boundary
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_requires_auth_and_unknown_sessions_are_404() {
    let root = temporary_root("a9-auth");
    let db = root.join("state.db");
    let session_id = "auth-session";
    // Seeding runs without the bearer token (the durable rows do not care);
    // the phase-2 gateway enforces it.
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;
    let state = open_state(&db, |config| {
        config.bearer_token = Some("secret-token".to_string());
    });
    let app = build_agent_gateway_app(state.clone());

    // Unauthenticated: rejected before any service work.
    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], json!("unauthorized"));

    // Authenticated: the real compaction runs.
    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        Some("secret-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], json!("committed"));

    // A foreign / never-created session id is a typed 404 even with a valid
    // token (the session boundary holds; nothing is fabricated).
    let (status, body) = post_request(
        &app,
        "/api/sessions/never-existed/compact",
        None,
        Some("secret-token"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], json!("session_not_found"));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Helpers duplicated from the A7 harness (scripted provider + production
// loop) for the real active-run fixture.
// ---------------------------------------------------------------------------

struct ScriptedServer {
    port: u16,
    shutdown: std::sync::mpsc::Sender<()>,
}

impl ScriptedServer {
    fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for ScriptedServer {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
    }
}

fn spawn_scripted_server(responses: Vec<(u16, String)>, delay_ms: u64) -> ScriptedServer {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("local addr").port();
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking fixture");
        let mut served = 0usize;
        loop {
            if shutdown_rx.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 4096];
                    let mut content_length = None;
                    loop {
                        match stream.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(read) => {
                                request.extend_from_slice(&buffer[..read]);
                                let text = String::from_utf8_lossy(&request);
                                if content_length.is_none() {
                                    content_length = text.lines().find_map(|line| {
                                        line.to_ascii_lowercase()
                                            .strip_prefix("content-length:")
                                            .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                                    });
                                }
                                let head_end = text.find("\r\n\r\n").unwrap_or(0);
                                if let Some(length) = content_length
                                    && request.len() >= head_end + 4 + length
                                {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    if delay_ms > 0 {
                        std::thread::sleep(Duration::from_millis(delay_ms));
                    }
                    let (status, body) = responses.get(served).cloned().unwrap_or_else(|| {
                        responses.last().cloned().unwrap_or((200, String::new()))
                    });
                    served += 1;
                    let reason = if status == 200 { "OK" } else { "Error" };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return,
            }
        }
    });
    ScriptedServer {
        port,
        shutdown: shutdown_tx,
    }
}

fn wire_tool_calls(calls: JsonValue) -> String {
    json!({
        "id": "chatcmpl-2",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "", "tool_calls": calls},
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4}
    })
    .to_string()
}

fn tool_call(id: &str, name: &str, arguments: JsonValue) -> JsonValue {
    json!({
        "id": id,
        "type": "function",
        "function": {"name": name, "arguments": arguments.to_string()}
    })
}

async fn get_request(
    app: &axum::Router,
    uri: &str,
    bearer: Option<&str>,
) -> (StatusCode, JsonValue) {
    let mut builder = Request::builder().method(Method::GET).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).expect("request should build"))
        .await
        .expect("router should respond");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body should be readable");
    (
        status,
        serde_json::from_slice(&body).expect("response should be JSON"),
    )
}

async fn wait_for_durable_status(state: &AgentGatewayState, run_id: &str, expected: &str) {
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if durable_run_status(state, run_id) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "run {run_id} did not reach durable status {expected}; actual {}",
        durable_run_status(state, run_id)
    );
}

// ---------------------------------------------------------------------------
// Review follow-up: fault injection helpers and fixtures
// ---------------------------------------------------------------------------

/// Crafts the durable cross-process already-committed state: a committed
/// compaction row for (session, generation) whose maintenance run is
/// terminal — exactly what a peer process leaves behind after its own
/// commit and recovery. The open gateway's mirror stays stale (generation
/// 1), so the next manual compact plans against the SAME target generation
/// and the storage layer answers `compaction_already_committed`.
fn craft_committed_state(
    state: &AgentGatewayState,
    session_id: &str,
    run_id: &str,
    generation: i64,
    start: i64,
    end: i64,
    tail: i64,
) {
    let persistence = state.persistence().expect("durable persistence");
    let now = 1_700_000_000_000_i64;
    persistence
        .run_create(&json!({
            "id": run_id,
            "session_id": session_id,
            "parent_run_id": "",
            "input_json": json!({"kind": "session_compaction"}).to_string(),
            "provider": "",
            "model": "test-model",
            "script_hash": "compact",
            "idempotency_scope": "",
            "idempotency_key": "",
            "now_ms": now,
        }))
        .expect("run.create must succeed");
    for (from, to) in [("queued", "running"), ("running", "compacting")] {
        let transition = json!({
            "run_id": run_id,
            "from_status": from,
            "to_status": to,
            "error_code": "",
            "error_message": "",
            "recovery_reason": "",
            "now_ms": now,
        });
        persistence
            .run_transition(&transition)
            .expect("crafted transition must succeed");
    }
    let start_payload = json!({
        "id": format!("compact:{session_id}:{generation}"),
        "session_id": session_id,
        "run_id": run_id,
        "generation": generation,
        "source_start_ordinal": start,
        "source_end_ordinal": end,
        "retained_tail_ordinal": tail,
        "summary_json": json!({
            "count": end - start + 1,
            "source_start_ordinal": start,
            "source_end_ordinal": end,
            "retained_tail_ordinal": tail,
        }).to_string(),
        "token_estimate": 0,
        "model": "test-model",
        "now_ms": now,
    });
    persistence
        .compaction_start(&start_payload)
        .expect("compaction.start must succeed");
    persistence
        .compaction_commit(&json!({
            "id": format!("compact:{session_id}:{generation}"),
            "session_id": session_id,
            "generation": generation,
            "start_ordinal": start,
            "end_ordinal": end,
            "completed_at_ms": now,
        }))
        .expect("compaction.commit must succeed");
    // The peer process's maintenance run reaches a terminal (restart
    // recovery would fail it); the durable active-run gate must pass.
    persistence
        .run_transition(&json!({
            "run_id": run_id,
            "from_status": "compacting",
            "to_status": "failed",
            "error_code": "gateway_restart",
            "error_message": "peer process recovered",
            "recovery_reason": "gateway_restart",
            "now_ms": now,
        }))
        .expect("run failure transition must succeed");
}

/// Crafts the durable failed-row conflict state: a FAILED compaction row
/// for the target (session, generation) with a DIFFERENT id (the durable
/// audit identity is owned by a peer attempt), and its run terminal.
fn craft_failed_row_conflict(
    state: &AgentGatewayState,
    session_id: &str,
    run_id: &str,
    generation: i64,
    start: i64,
    end: i64,
    tail: i64,
) {
    let persistence = state.persistence().expect("durable persistence");
    let now = 1_700_000_000_000_i64;
    let foreign_id = format!("compact:{session_id}:{generation}:peer");
    persistence
        .run_create(&json!({
            "id": run_id,
            "session_id": session_id,
            "parent_run_id": "",
            "input_json": json!({"kind": "session_compaction"}).to_string(),
            "provider": "",
            "model": "test-model",
            "script_hash": "compact",
            "idempotency_scope": "",
            "idempotency_key": "",
            "now_ms": now,
        }))
        .expect("run.create must succeed");
    for (from, to) in [("queued", "running"), ("running", "compacting")] {
        let transition = json!({
            "run_id": run_id,
            "from_status": from,
            "to_status": to,
            "error_code": "",
            "error_message": "",
            "recovery_reason": "",
            "now_ms": now,
        });
        persistence
            .run_transition(&transition)
            .expect("crafted transition must succeed");
    }
    persistence
        .compaction_start(&json!({
            "id": foreign_id,
            "session_id": session_id,
            "run_id": run_id,
            "generation": generation,
            "source_start_ordinal": start,
            "source_end_ordinal": end,
            "retained_tail_ordinal": tail,
            "summary_json": json!({
                "count": end - start + 1,
                "source_start_ordinal": start,
                "source_end_ordinal": end,
                "retained_tail_ordinal": tail,
            }).to_string(),
            "token_estimate": 0,
            "model": "test-model",
            "now_ms": now,
        }))
        .expect("compaction.start must succeed");
    persistence
        .compaction_fail(&json!({
            "id": foreign_id,
            "error_message": "peer attempt failed",
            "completed_at_ms": now,
        }))
        .expect("compaction.fail must succeed");
    persistence
        .run_transition(&json!({
            "run_id": run_id,
            "from_status": "compacting",
            "to_status": "failed",
            "error_code": "compaction_failed",
            "error_message": "peer attempt failed",
            "recovery_reason": "",
            "now_ms": now,
        }))
        .expect("run failure transition must succeed");
}

/// Reads the mirror events of one run through the SSE replay route (the
/// stream ends after retained history for runs without a live sender).
async fn read_mirror_run_events(app: &axum::Router, run_id: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/runs/{run_id}/events"))
                .body(Body::empty())
                .expect("SSE request should build"),
        )
        .await
        .expect("SSE route should respond");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("SSE body should be readable");
    String::from_utf8(body.to_vec()).expect("SSE body should be UTF-8")
}

/// Parses the SSE replay text into (event_type, data-payload) pairs; the
/// data payload carries the event envelope merged with the event fields.
fn parse_mirror_events(text: &str) -> Vec<(String, JsonValue)> {
    text.split("\n\n")
        .filter_map(|block| {
            let mut event_type = None;
            let mut data = None;
            for line in block.lines() {
                if let Some(value) = line.strip_prefix("event: ") {
                    event_type = Some(value.to_string());
                }
                if let Some(value) = line.strip_prefix("data: ") {
                    data = serde_json::from_str(value).ok();
                }
            }
            match (event_type, data) {
                (Some(event_type), Some(data)) => Some((event_type, data)),
                _ => None,
            }
        })
        .collect()
}

/// Finds the durable maintenance run of one session created by a request
/// (id prefix `compact-run:`), excluding a known peer run id.
fn maintenance_run_of(state: &AgentGatewayState, session_id: &str, exclude: &str) -> String {
    let persistence = state.persistence().expect("durable persistence");
    let runs = persistence.run_list(session_id, "").expect("run.list");
    runs["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .filter_map(JsonValue::as_array)
        .find_map(|row| {
            let id = row.first().and_then(JsonValue::as_str).unwrap_or("");
            (id.starts_with("compact-run:") && id != exclude).then(|| id.to_string())
        })
        .expect("the maintenance run must exist")
}

// ---------------------------------------------------------------------------
// Review follow-up: already_committed read failure is a TYPED storage error
// (never a fabricated completed attribution) — fault injection
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_already_committed_read_failure_is_typed_storage_error() {
    let root = temporary_root("a9-already-get");
    let db = root.join("state.db");
    let session_id = "already-get-session";
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;
    let state = open_state(&db, |_| {});
    let app = build_agent_gateway_app(state.clone());

    // A peer process already committed generation 2; this gateway's mirror
    // is stale, so the next compact plans against the same generation and
    // compaction.start answers compaction_already_committed.
    craft_committed_state(&state, session_id, "peer-run", 2, 1, 7, 7);

    // Fault injection: the committed-row read fails right after the typed
    // already-committed answer. The request must fail TYPED — falling
    // through to the success path would fabricate a completed attribution
    // and run ownership that the durable side never recorded.
    state
        .persistence()
        .expect("durable persistence")
        .inject_storage_failure("compaction.get", 1);

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a failed committed-row read must be a typed storage error, never a \
         fabricated completed answer: {body}"
    );
    assert_eq!(body["error"]["code"], json!("persistence_unavailable"));

    // Durable truth untouched: exactly one committed row, the peer run
    // still terminal-failed, and THIS process's maintenance run durably
    // failed (never left compacting, never fabricated as completed).
    assert_eq!(durable_compaction_count(&state, session_id), 1);
    let row = durable_compaction(&state, session_id).expect("committed row");
    assert_eq!(row[0], json!(format!("compact:{session_id}:2")));
    assert_eq!(row[10], json!("committed"));
    assert_eq!(durable_run_status(&state, "peer-run"), "failed");
    let maintenance_run = maintenance_run_of(&state, session_id, "peer-run");
    assert_eq!(
        durable_run_status(&state, &maintenance_run),
        "failed",
        "the losing maintenance run must be durably failed"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Review follow-up: continuous run.transition failure — the maintenance run
// terminal is parked observably `terminal_pending` and the SAME process
// commits it once storage recovers, then the compact retry commits
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_continuous_transition_failure_parks_terminal_and_recovers() {
    let root = temporary_root("a9-transition");
    let db = root.join("state.db");
    let session_id = "transition-session";
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;
    let state = open_state(&db, |config| {
        config.janitor_interval = Duration::from_millis(20);
        config.terminal_persist_retries = 1;
        config.terminal_persist_retry_delay = Duration::from_millis(10);
        config.terminal_commit_retry_window = Duration::from_secs(10);
    });
    let app = build_agent_gateway_app(state.clone());
    let service = state.service();
    let persistence = state.persistence().expect("durable persistence");

    // Continuous storage failure on EVERY run.transition: the maintenance
    // run can neither reach compacting nor its terminal.
    persistence.inject_storage_failure("run.transition", usize::MAX);

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], json!("persistence_unavailable"));

    // The maintenance run terminal is parked observably `terminal_pending`
    // (never a false terminal, never left silently compacting) and the
    // bounded retry loop owns it.
    assert_eq!(
        service.pending_terminal_count(),
        1,
        "the maintenance run terminal must be parked for the bounded retry"
    );
    let maintenance_run = maintenance_run_of(&state, session_id, "");
    assert_eq!(
        durable_run_status(&state, &maintenance_run),
        "queued",
        "the run never reached compacting and its terminal is parked"
    );
    assert_eq!(
        durable_compaction_count(&state, session_id),
        0,
        "no compaction row may exist before the run reached compacting"
    );

    // Storage recovers IN-PROCESS: the bounded retry commits the terminal
    // exactly once (queued -> failed); the run never stays compacting.
    persistence.inject_storage_failure("run.transition", 0);
    wait_for_durable_status(&state, &maintenance_run, "failed").await;
    assert_eq!(service.pending_terminal_count(), 0);

    // The same process can retry the manual compact and commit.
    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the in-process retry must commit: {body}"
    );
    assert_eq!(body["status"], json!("committed"));
    assert_eq!(
        body["compaction_id"],
        json!(format!("compact:{session_id}:2"))
    );
    assert_eq!(body["generation"], json!(2));

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Review follow-up: cross-process already_committed — the idempotent answer
// carries the committed row's REAL values and the mirror is refreshed
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_already_committed_returns_committed_row_and_refreshes_mirror() {
    let root = temporary_root("a9-already");
    let db = root.join("state.db");
    let session_id = "already-session";
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;
    let state = open_state(&db, |_| {});
    let app = build_agent_gateway_app(state.clone());

    craft_committed_state(&state, session_id, "peer-run", 2, 1, 7, 7);

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "already committed is an idempotent answer: {body}"
    );
    assert_eq!(body["status"], json!("committed"));
    assert_eq!(
        body["compaction_id"],
        json!(format!("compact:{session_id}:2"))
    );
    assert_eq!(body["generation"], json!(2));
    assert_eq!(body["run_id"], json!("peer-run"), "the real committed run");
    assert_eq!(body["source_start_ordinal"], json!(1));
    assert_eq!(body["source_end_ordinal"], json!(7));
    assert_eq!(body["retained_tail_ordinal"], json!(7));

    // The mirror is refreshed from the durable committed row: the covered
    // range is compacted in memory and the generation advanced, so later
    // plans and message views never see stale state.
    let (_, messages) =
        get_request(&app, &format!("/api/sessions/{session_id}/messages"), None).await;
    let compacted_flags = messages["data"]
        .as_array()
        .expect("message list")
        .iter()
        .map(|message| message["compacted"].as_bool().unwrap_or(false))
        .collect::<Vec<_>>();
    assert_eq!(
        compacted_flags,
        vec![true, true, true, true, true, true, true, false],
        "the mirror must reflect the committed range"
    );
    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refreshed plan is a skip: {body}"
    );
    assert_eq!(body["status"], json!("skipped"));

    // This process's maintenance run is durably failed (exact-once
    // terminal) and exactly one committed row exists.
    let maintenance_run = maintenance_run_of(&state, session_id, "peer-run");
    assert_eq!(durable_run_status(&state, &maintenance_run), "failed");
    assert_eq!(durable_compaction_count(&state, session_id), 1);

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Review follow-up: durable failed-row conflict — the losing maintenance
// run reaches its durably failed terminal (exact-once), never left
// compacting, and the peer's failed row is untouched
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_failed_row_conflict_fails_maintenance_run_durably() {
    let root = temporary_root("a9-conflict");
    let db = root.join("state.db");
    let session_id = "conflict-session";
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;
    let state = open_state(&db, |_| {});
    let app = build_agent_gateway_app(state.clone());

    // A peer attempt failed with a DIFFERENT compaction id for the same
    // (session, generation): the durable audit identity is owned.
    craft_failed_row_conflict(&state, session_id, "peer-run", 2, 1, 7, 7);

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], json!("compaction_in_progress"));

    // The losing maintenance run is durably terminal-failed (exact-once
    // terminal), never left compacting.
    let maintenance_run = maintenance_run_of(&state, session_id, "peer-run");
    assert_eq!(
        durable_run_status(&state, &maintenance_run),
        "failed",
        "the losing run must be durably failed"
    );
    // The peer's failed row is untouched (no clobber, no fabrication).
    let row = durable_compaction(&state, session_id).expect("failed row");
    assert_eq!(row[0], json!(format!("compact:{session_id}:2:peer")));
    assert_eq!(row[10], json!("failed"));
    assert_eq!(durable_session_generation(&state, session_id), 1);

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Review follow-up: a failed commit step (after a pending row exists) fails
// the pending row AND the maintenance run durably, closing the event trail
// exactly once — fault injection
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_commit_step_failure_fails_pending_row_and_run_durably() {
    let root = temporary_root("a9-commit");
    let db = root.join("state.db");
    let session_id = "commit-session";
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;
    let state = open_state(&db, |_| {});
    let app = build_agent_gateway_app(state.clone());

    // Fault injection: the commit step fails AFTER compaction.start created
    // the pending row (the durable-failure path).
    state
        .persistence()
        .expect("durable persistence")
        .inject_storage_failure("compaction.commit", 1);

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], json!("persistence_unavailable"));

    // The pending row is durably failed and the maintenance run terminal-
    // failed (never left compacting); the history stays recoverable.
    let row = durable_compaction(&state, session_id).expect("failed row");
    assert_eq!(row[0], json!(format!("compact:{session_id}:2")));
    assert_eq!(row[10], json!("failed"));
    assert_eq!(durable_session_generation(&state, session_id), 1);
    let maintenance_run = maintenance_run_of(&state, session_id, "");
    assert_eq!(
        durable_run_status(&state, &maintenance_run),
        "failed",
        "the maintenance run must be durably failed"
    );
    // The exact-once event trail closes: one started + one completed event.
    let events = durable_run_events(&state, &maintenance_run);
    assert_eq!(
        events
            .iter()
            .filter(|(t, _)| t == "compact.started")
            .count(),
        1,
        "exactly one compact.started event"
    );
    assert_eq!(
        events
            .iter()
            .filter(|(t, _)| t == "compact.completed")
            .count(),
        1,
        "exactly one compact.completed event"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Review follow-up: canonical message content (string content normalized to
// the parts array the policy contract documents) and mirror event payloads
// matching the durable trail (compact.started carries the real range)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_canonical_content_and_mirror_events_match_durable() {
    let root = temporary_root("a9-canonical");
    let db = root.join("state.db");
    let session_id = "canonical-session";
    // The production loop persists plain assistant output as STRING
    // content; the compaction context must canonicalize it into the parts
    // array the policy contract documents (pairing still lands at 7).
    let history = vec![
        message("user", "", json!([text_part("u1")])),
        message("assistant", "", json!("plain text output")),
        message("user", "", json!([text_part("u2")])),
        message("assistant", "", json!([text_part("a2")])),
        message("user", "", json!([text_part("u3")])),
        message("assistant", "", json!([tool_call_part("call-1")])),
        message("tool", "call-1", json!([tool_result_part("call-1")])),
        message("user", "", json!([text_part("u4")])),
    ];
    seed_session_history(&db, session_id, &history, |_| {}).await;
    let state = open_state(&db, |_| {});
    let app = build_agent_gateway_app(state.clone());

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "compact must commit: {body}");
    assert_eq!(body["status"], json!("committed"));
    assert_eq!(
        body["source_end_ordinal"],
        json!(7),
        "the pair-preserving boundary must still land at 7"
    );

    let row = durable_compaction(&state, session_id).expect("committed row");
    let maintenance_run = row[2].as_str().expect("maintenance run id").to_string();
    let durable_events = durable_run_events(&state, &maintenance_run);

    // The MIRROR events (SSE replay) must carry the same payloads as the
    // durable trail: compact.started with the real range, compact.completed
    // with the real id/generation.
    let mirror = parse_mirror_events(&read_mirror_run_events(&app, &maintenance_run).await);
    let (_, mirror_started) = mirror
        .iter()
        .find(|(event_type, _)| event_type == "compact.started")
        .expect("mirror compact.started event");
    let (_, durable_started) = durable_events
        .iter()
        .find(|(event_type, _)| event_type == "compact.started")
        .expect("durable compact.started event");
    assert_eq!(
        mirror_started["compaction_id"], durable_started["compaction_id"],
        "mirror started event must carry the real compaction id"
    );
    assert_eq!(
        mirror_started["generation"], durable_started["generation"],
        "mirror started event must carry the real generation"
    );
    assert_eq!(
        mirror_started["source_start_ordinal"], durable_started["source_start_ordinal"],
        "mirror started event must carry the real range start"
    );
    assert_eq!(
        mirror_started["source_end_ordinal"], durable_started["source_end_ordinal"],
        "mirror started event must carry the real range end"
    );
    assert_eq!(
        mirror_started["retained_tail_ordinal"], durable_started["retained_tail_ordinal"],
        "mirror started event must carry the real retained tail"
    );
    let (_, mirror_completed) = mirror
        .iter()
        .find(|(event_type, _)| event_type == "compact.completed")
        .expect("mirror compact.completed event");
    let (_, durable_completed) = durable_events
        .iter()
        .find(|(event_type, _)| event_type == "compact.completed")
        .expect("durable compact.completed event");
    assert_eq!(mirror_completed["ok"], durable_completed["ok"]);
    assert_eq!(
        mirror_completed["compaction_id"], durable_completed["compaction_id"],
        "mirror completed event must carry the real compaction id"
    );
    assert_eq!(
        mirror_completed["generation"], durable_completed["generation"],
        "mirror completed event must carry the real generation"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

// ---------------------------------------------------------------------------
// Review closing: exact-once event append under an ambiguous commit (SQLite
// committed but the store response was lost / timed out) — the SAME fixed
// event_id is retried and must replay idempotently, never die on
// UNIQUE(event_id), so started is not misjudged as an abort and the
// completed terminal is never parked `terminal_pending`
// ---------------------------------------------------------------------------

/// Counts durable events of one type on a run.
fn durable_run_event_count(state: &AgentGatewayState, run_id: &str, event_type: &str) -> usize {
    durable_run_events(state, run_id)
        .iter()
        .filter(|(etype, _)| etype == event_type)
        .count()
}

/// RED/GREEN, started path: the `compact.started` event append commits
/// durably to SQLite but the store response is lost for the FIRST
/// `event.append` (skip 0). `append_maintenance_event_bounded` retries the
/// SAME fixed event_id; the exact-once storage layer must replay the already
/// durable row as success so the compaction proceeds and commits. Before the
/// fix the retry hit UNIQUE(event_id) and the started event misjudged the
/// compaction as aborted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_started_event_ambiguous_commit_replays_exactly_once() {
    let root = temporary_root("a9-started-ambiguous");
    let db = root.join("state.db");
    let session_id = "started-ambiguous-session";
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;
    let state = open_state(&db, |_| {});
    let app = build_agent_gateway_app(state.clone());
    let persistence = state.persistence().expect("durable persistence");
    let service = state.service();

    // The first event.append (compact.started) commits durably but its
    // response is lost; every later event.append round-trips normally.
    persistence.inject_commit_lost_response("event.append", 0, 1);

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the started retry must replay idempotently and the compact commit: {body}"
    );
    assert_eq!(body["status"], json!("committed"));
    assert_eq!(
        body["compaction_id"],
        json!(format!("compact:{session_id}:2"))
    );

    // The maintenance run reached its canonical terminal and no terminal is
    // parked.
    let row = durable_compaction(&state, session_id).expect("committed row");
    let maintenance_run = row[2].as_str().expect("maintenance run id").to_string();
    assert_eq!(durable_run_status(&state, &maintenance_run), "completed");
    assert_eq!(service.pending_terminal_count(), 0);

    // Exactly one durable started + one durable completed event (the lost
    // response produced no duplicate row).
    assert_eq!(
        durable_run_event_count(&state, &maintenance_run, "compact.started"),
        1,
        "exactly one compact.started despite the lost response + retry"
    );
    assert_eq!(
        durable_run_event_count(&state, &maintenance_run, "compact.completed"),
        1,
        "exactly one compact.completed"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}

/// RED, terminal path: the `compact.completed` terminal event append commits
/// durably but loses its response. `maintenance_terminal_once` retries the
/// SAME fixed event_id across the bounded terminal loop; the exact-once
/// storage layer replays it so the terminal is committed (run `completed`),
/// never left `terminal_pending`. Before the fix the UNIQUE(event_id) clash
/// made the completed event permanent `terminal_pending`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a9_compact_completed_terminal_ambiguous_lost_converges_never_parked() {
    let root = temporary_root("a9-terminal-ambiguous");
    let db = root.join("state.db");
    let session_id = "terminal-ambiguous-session";
    seed_session_history(&db, session_id, &pair_boundary_history(), |_| {}).await;
    let state = open_state(&db, |config| {
        config.terminal_persist_retries = 3;
        config.terminal_persist_retry_delay = Duration::from_millis(10);
        config.terminal_commit_retry_window = Duration::from_secs(10);
    });
    let service = state.service();
    let app = build_agent_gateway_app(state.clone());
    let persistence = state.persistence().expect("durable persistence");

    // The started event (first event.append) succeeds normally; the terminal
    // compact.completed append (the SECOND event.append) commits durably but
    // loses its response exactly once. The terminal retry must converge.
    persistence.inject_commit_lost_response("event.append", 1, 1);

    let (status, body) = post_request(
        &app,
        &format!("/api/sessions/{session_id}/compact"),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the terminal event must converge and the compact commit: {body}"
    );
    assert_eq!(body["status"], json!("committed"));

    let row = durable_compaction(&state, session_id).expect("committed row");
    let maintenance_run = row[2].as_str().expect("maintenance run id").to_string();
    wait_for_durable_status(&state, &maintenance_run, "completed").await;
    assert_eq!(
        service.pending_terminal_count(),
        0,
        "the maintenance run terminal must never be parked terminal_pending"
    );

    assert_eq!(
        durable_run_event_count(&state, &maintenance_run, "compact.completed"),
        1,
        "exactly one completed event despite the lost response + retry"
    );
    assert_eq!(
        durable_run_event_count(&state, &maintenance_run, "compact.started"),
        1,
        "exactly one started event"
    );

    std::fs::remove_dir_all(&root).expect("temporary root should be removed");
}
