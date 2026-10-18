use super::*;

#[test]
fn managed_aggregate_sql_parameter_budget_precedes_sdk_enqueue_and_matches_fixed_rss() {
    let source = include_str!("../../rss/storage/effects.rss");
    for op in [
        "workspace_get",
        "workspace_register",
        "head",
        "get",
        "begin",
        "prepare",
        "commit",
        "pending",
        "recover_one",
        "recovery_context",
    ] {
        let function = source
            .split(&format!("pub fn {op}("))
            .nth(1)
            .unwrap()
            .split("pub fn ")
            .next()
            .unwrap();
        let mut actual = std::collections::BTreeMap::new();
        for tail in function.split("text(input.").skip(1) {
            let field = tail.split(['.', ')']).next().unwrap();
            *actual.entry(field).or_insert(0usize) += 1;
        }
        let declared = managed_parameter_bindings(&format!("effect.{op}"))
            .iter()
            .copied()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            declared, actual,
            "fixed RSS parameter accounting drift for {op}"
        );
    }
    let (_root, persistence) = persistence();
    let before = persistence.executed_storage_commands();
    // Private transport negative: encoded request fits, but repeated fixed SQL
    // parameters exceed the aggregate contract. No SQL or DB bytes are authored.
    let payload = json!({"workspace_json":"x".repeat(100_000)});
    assert!(serde_json::to_vec(&payload).unwrap().len() < crate::effects::journal::METADATA_BYTES);
    let error = persistence
        .managed_effect_command("effect.workspace_register", &payload)
        .unwrap_err();
    assert_eq!(persistence.executed_storage_commands(), before);
    assert!(error.message.contains("aggregate parameter"));
    persistence.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_reopen_preserves_nonzero_formal_provider_usage() {
    use crate::config::{ManagedRetentionLimits, ManagedWorkspaceConfig};
    let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("managed-usage-{}", Uuid::new_v4().simple()));
    let workspace = root.join("workspace");
    let home = root.join("home");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir(&home).unwrap();
    std::fs::write(home.join("config.yaml"),format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",workspace.display(),workspace.display())).unwrap();
    let config = AgentGatewayConfig {
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace,
            quota: crate::effects::ResourceQuota::new(1000, 1048576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
        }),
        ..Default::default()
    };
    let database = root.join("gateway.sqlite");
    let state = crate::AgentGatewayState::with_sqlite_path(config.clone(), &database)
        .unwrap()
        .with_workspace_home(&home);
    let run = state
        .service()
        .admit_external_with_workspace_selector(
            crate::AdmitRunRequest {
                input: json!({"message":"retained usage audit"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let persistence = state.persistence().unwrap();
    // Use the original formal RSS usage command on the existing SDK worker.
    // These are explicit synthetic accounting facts, not reported model usage.
    let usage=persistence.command_data("run.usage",&json!({"id":"managed-usage-fact","run_id":run.run_id,"provider":"synthetic","model":"synthetic","request_count":1,"input_tokens":17,"output_tokens":9,"reasoning_tokens":3,"cached_tokens":2,"now_ms":1})).unwrap();
    assert_eq!(usage["rows"][0][1], 17);
    assert_eq!(usage["rows"][0][2], 9);
    drop(persistence);
    state.service().shutdown().await.unwrap();
    drop(state);
    let reopened = crate::AgentGatewayState::with_sqlite_path(config, &database)
        .unwrap()
        .with_workspace_home(&home);
    let persistence = reopened.persistence().unwrap();
    let row = persistence.run_get(&run.run_id).unwrap();
    for (name, count) in [("input_tokens", 17), ("output_tokens", 9)] {
        let column = row["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|value| value == name)
            .unwrap();
        assert_eq!(row["rows"][0][column], count);
    }
    drop(persistence);
    reopened.service().shutdown().await.unwrap();
}
fn persistence() -> (std::path::PathBuf, GatewayPersistence) {
    let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("managed-budget-{}", Uuid::new_v4().simple()));
    std::fs::create_dir(&root).unwrap();
    let persistence =
        GatewayPersistence::open(&AgentGatewayConfig::default(), &root.join("state.sqlite"))
            .unwrap();
    persistence.load().unwrap();
    (root, persistence)
}
#[test]
fn managed_pending_32_admissions_reject_33rd_before_sdk_and_recover_after_real_native_permit_drop()
{
    let (_root, persistence) = persistence();
    let mut permits = (0..32)
        .map(|_| ManagedStoragePermit::acquire(&persistence.managed_pending).unwrap())
        .collect::<Vec<_>>();
    let before = persistence.executed_storage_commands();
    assert!(
        persistence
            .managed_effect_command("effect.workspace_get", &json!({}))
            .is_err(),
        "all Native managed request admissions, including metadata queries, must obey the 32-pending bound"
    );
    assert_eq!(persistence.executed_storage_commands(), before);
    permits.pop();
    let result = persistence
        .managed_effect_command("effect.workspace_get", &json!({}))
        .unwrap();
    assert_eq!(result["rows"], json!([]));
    drop(permits);
    assert_eq!(persistence.managed_pending.load(Ordering::Acquire), 0);
    persistence.shutdown();
}
#[test]
fn managed_native_permit_is_owned_by_queued_request_until_worker_acknowledgement_even_without_receiver()
 {
    let (_root, persistence) = persistence();
    let (respond, receiver) = mpsc::channel();
    drop(receiver);
    let permit = ManagedStoragePermit::acquire(&persistence.managed_pending).unwrap();
    persistence
        .worker
        .sender
        .send(StorageRequest {
            op: "load".into(),
            payload: json!({}),
            respond,
            cancellation: Some(crate::RunCancellation::with_timeout(Duration::from_secs(5))),
            _managed_permit: Some(permit),
        })
        .unwrap();
    // The following SDK request is ordered after the dropped-receiver request.
    // Its acknowledgement proves that the first owned request has settled.
    persistence
        .managed_effect_command("effect.workspace_get", &json!({}))
        .unwrap();
    assert_eq!(persistence.managed_pending.load(Ordering::Acquire), 0);
    persistence.shutdown();
}
#[test]
fn original_native_cancellation_while_waiting_for_storage_admission_does_not_enqueue_or_release_early()
 {
    let (_root, persistence) = persistence();
    let persistence = Arc::new(persistence);
    let block = persistence.inject_block_persist();
    let original = crate::RunCancellation::with_timeout(Duration::from_secs(5));
    let (owner, cancellation) = (Arc::clone(&persistence), original.clone());
    let worker = std::thread::spawn(move || {
        owner.managed_effect_command_with_cancellation(
            "effect.workspace_get",
            &json!({}),
            &cancellation,
        )
    });
    block.wait_entered();
    let charged = persistence.managed_pending.load(Ordering::Acquire);
    let before = persistence.executed_storage_commands();
    original.request(crate::CancellationReason::Requested);
    block.release();
    let result = worker.join().unwrap();
    assert_eq!(charged, 1);
    assert!(result.is_err());
    assert_eq!(persistence.executed_storage_commands(), before);
    assert_eq!(persistence.managed_pending.load(Ordering::Acquire), 0);
    persistence.shutdown();
}
#[test]
fn original_native_cancellation_and_deadline_are_checked_before_storage_enqueue_without_renewal() {
    let (_root, persistence) = persistence();
    let original = crate::RunCancellation::with_timeout(Duration::from_secs(5));
    let deadline = original.deadline_instant();
    original.request(crate::CancellationReason::Requested);
    let before = persistence.executed_storage_commands();
    assert!(
        persistence
            .managed_effect_command_with_cancellation("effect.workspace_get", &json!({}), &original)
            .is_err(),
        "a Native caller cancellation cannot be replaced with a fresh storage timeout"
    );
    assert_eq!(persistence.executed_storage_commands(), before);
    assert_eq!(original.deadline_instant(), deadline);
    let expired = crate::RunCancellation::with_deadline(Instant::now());
    assert!(
        persistence
            .managed_effect_command_with_cancellation("effect.workspace_get", &json!({}), &expired)
            .is_err()
    );
    assert_eq!(persistence.executed_storage_commands(), before);
    let active = crate::RunCancellation::with_timeout(Duration::from_secs(5));
    let deadline = active.deadline_instant();
    persistence
        .managed_effect_command_with_cancellation("effect.workspace_get", &json!({}), &active)
        .unwrap();
    assert_eq!(active.deadline_instant(), deadline);
    persistence.shutdown();
}
