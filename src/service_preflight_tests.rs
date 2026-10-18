use super::*;
use crate::AgentGatewayState;

struct Fixture {
    state: AgentGatewayState,
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"),
        )
        .join(format!("preflight-result-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let state = AgentGatewayState::with_sqlite_path(
            AgentGatewayConfig::default(),
            root.join("agent.sqlite"),
        )
        .unwrap();
        Self { state, root }
    }
    async fn run(&self) -> AdmittedRun {
        self.state
            .service()
            .admit(AdmitRunRequest {
                input: json!("bounded tool validation"),
                ..Default::default()
            })
            .await
            .unwrap()
    }
    fn parent(&self, run: &AdmittedRun, ids: &[&str]) {
        let blocks: Vec<_> = ids
            .iter()
            .map(|id| LlmContentBlock {
                block_type: "tool_call".into(),
                tool_call_id: Some((*id).into()),
                name: Some("search_files".into()),
                arguments_json: Some("{\"pattern\":\"*\",\"path\":\".\"}".into()),
                ..Default::default()
            })
            .collect();
        self.state
            .service()
            .commit_provider_step(
                &run.run_id,
                1,
                &blocks,
                None,
                Some("tool_calls"),
                None,
                None,
                None,
            )
            .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn context(id: &str, name: &str, is_error: bool) -> JsonValue {
    json!({"messages":[{"role":"user","content":[{"type":"tool_result","tool_call_id":id,"name":name,"is_error":is_error,"content":"","error":{"code":"path_denied","message":"dot components are rejected"}}]}]})
}
#[tokio::test]
async fn preflight_failure_is_idempotent_and_never_persists_unstarted_success() {
    let f = Fixture::new();
    let run = f.run().await;
    f.parent(&run, &["failed", "success"]);
    let s = f.state.service();
    let ctx = context("failed", "search_files", true);
    s.persist_unstarted_tool_failures(&run.run_id, &ctx)
        .unwrap();
    s.persist_unstarted_tool_failures(&run.run_id, &ctx)
        .unwrap();
    s.persist_unstarted_tool_failures(&run.run_id, &context("success", "search_files", false))
        .unwrap();
    assert_eq!(
        s.session_messages(&run.session_id)
            .iter()
            .filter(|m| m["tool_call_id"] == "failed")
            .count(),
        1
    );
    assert_eq!(
        s.session_messages(&run.session_id)
            .iter()
            .filter(|m| m["tool_call_id"] == "success")
            .count(),
        0
    );
    assert!(
        !s.run_events(&run.run_id)
            .iter()
            .any(|e| e["event"] == "tool.started")
    );
    assert!(
        s.commit_tool_step(
            &run.run_id,
            "tool.failed",
            json!({"tool_call_id":"success","name":"search_files","validation_only":true}),
            Some(&ToolResult::success("forged", json!({})))
        )
        .is_err()
    );
}
#[tokio::test]
async fn preflight_failure_rejects_missing_wrong_name_cross_run_and_started_effect() {
    let f = Fixture::new();
    let a = f.run().await;
    f.parent(&a, &["name", "started", "cross"]);
    let b = f.run().await;
    let s = f.state.service();
    for (run, id, name) in [
        (&a, "missing", "search_files"),
        (&a, "name", "write_file"),
        (&b, "cross", "search_files"),
    ] {
        assert!(
            s.persist_unstarted_tool_failures(&run.run_id, &context(id, name, true))
                .is_err()
        );
    }
    s.commit_tool_step(
        &a.run_id,
        "tool.started",
        json!({"tool_call_id":"started","name":"search_files"}),
        None,
    )
    .unwrap();
    assert!(
        s.persist_unstarted_tool_failures(&a.run_id, &context("started", "search_files", true))
            .is_err()
    );
    assert!(
        !s.run_events(&a.run_id)
            .iter()
            .any(|e| e["event"] == "tool.failed")
    );
}
#[tokio::test]
async fn preflight_failure_cannot_claim_a_parent_from_another_run_in_the_same_session() {
    let f = Fixture::new();
    let run = f.run().await;
    f.parent(&run, &["cross"]);
    let s = f.state.service();
    {
        let mut store = s.inner.store.write();
        let session = store.sessions.get_mut(&run.session_id).unwrap();
        session
            .messages
            .iter_mut()
            .find(|m| m.role == "assistant")
            .unwrap()
            .run_id = Some("other-run".into());
    }
    assert!(
        s.persist_unstarted_tool_failures(&run.run_id, &context("cross", "search_files", true))
            .is_err()
    );
    assert!(
        !s.run_events(&run.run_id)
            .iter()
            .any(|e| e["event"] == "tool.failed")
    );
}
#[tokio::test]
async fn preflight_failure_persist_failure_stops_context_refresh_and_cancellation_denies_commit() {
    let f = Fixture::new();
    let run = f.run().await;
    f.parent(&run, &["persist", "cancel"]);
    let s = f.state.service();
    s.inner
        .persistence
        .as_ref()
        .unwrap()
        .inject_persist_failure();
    let mut ctx = context("persist", "search_files", true);
    ctx["session_id"] = json!(run.session_id);
    let refreshed = s.refresh_provider_context(&run.run_id, &ctx, &RunCancellation::new());
    assert_eq!(refreshed["ok"], false);
    assert_eq!(refreshed["error"]["code"], "tool_failure_persist_failed");
    let expired = s.refresh_provider_context(
        &run.run_id,
        &ctx,
        &RunCancellation::with_timeout(Duration::ZERO),
    );
    assert_eq!(expired["ok"], false);
    assert_eq!(expired["error"]["code"], "cancelled");
    assert!(
        !s.run_events(&run.run_id)
            .iter()
            .any(|e| e["event"] == "tool.failed")
    );
    s.handle(&run.run_id)
        .unwrap()
        .cancel
        .request(CancellationReason::Requested);
    assert!(
        s.persist_unstarted_tool_failures(&run.run_id, &context("cancel", "search_files", true))
            .is_err()
    );
}
