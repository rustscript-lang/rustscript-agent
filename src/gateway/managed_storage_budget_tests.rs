use super::*;

#[test]
fn graph_pin_and_pair_repeated_parameters_reject_before_enqueue() {
    let (_root, p) = persistence();
    for (op, payload) in [
        (
            "admission.create",
            json!({"tool_graph_id":"g".repeat(70000)}),
        ),
        (
            "event.append_pair",
            json!({"run_id":"r".repeat(70000),"payload_json_a":"{}","payload_json_b":"{}"}),
        ),
    ] {
        assert!(
            serde_json::to_vec(&payload).unwrap().len() < crate::effects::journal::METADATA_BYTES
        );
        let before = p.executed_storage_commands();
        let result = p.command_data(op, &payload);
        assert!(result.is_err());
        assert_eq!(
            p.executed_storage_commands(),
            before,
            "{op} repeated text parameters must reject before enqueue: {result:?}"
        );
    }
    p.shutdown();
}

#[test]
fn managed_draft_repeated_projection_bytes_use_updated_weights_before_enqueue() {
    let (_root, persistence) = persistence();
    for (op, weight) in [
        ("effect.begin", 10),
        ("effect.commit", 15),
        ("effect.recover_one", 15),
    ] {
        let padding = "x".repeat(crate::effects::journal::METADATA_BYTES / weight);
        let projection = json!({"output":{"created_at_ms":11},"terminal":{"created_at_ms":12},"message":{"created_at_ms":13}});
        let payload = json!({"sealed_class":"workspace_read","projections_json":json!({"normal":projection,"conflict":projection,"padding":padding}).to_string()});
        assert!(
            serde_json::to_vec(&payload).unwrap().len() < crate::effects::journal::METADATA_BYTES
        );
        let before = persistence.executed_storage_commands();
        let error = persistence
            .managed_effect_command(op, &payload)
            .unwrap_err();
        assert!(error.message.contains("aggregate parameter"));
        assert_eq!(persistence.executed_storage_commands(), before);
    }
    persistence.shutdown();
}

#[test]
fn composed_restore_repeated_envelope_rejects_before_enqueue() {
    let (_root, persistence) = persistence();
    let before = persistence.executed_storage_commands();
    let payload = json!({"restore_json":json!({"original_request_proof":"\\\"\n".repeat(12000)}).to_string()});
    assert!(serde_json::to_vec(&payload).unwrap().len() < 1048576);
    let error = persistence.admission_create(&payload).unwrap_err();
    assert_eq!(
        persistence.executed_storage_commands(),
        before,
        "aggregate restore bindings must reject before worker enqueue"
    );
    assert_eq!(error.message, "managed_metadata_budget_exceeded");
    assert_eq!(persistence.managed_pending.load(Ordering::Acquire), 0);
    persistence.shutdown();
}

#[test]
fn composed_restore_fixed_statement_parameter_census_matches_native_weights() {
    let source = include_str!("../../rss/storage/effects.rss");
    let mut envelope = 0;
    for (function, expected) in [
        ("restore_before_admission", 31),
        ("restore_history_statements", 5),
        ("restore_receipt_statements", 12),
    ] {
        let body = source
            .split(&format!("pub fn {function}("))
            .nth(1)
            .unwrap()
            .split("pub fn ")
            .next()
            .unwrap();
        let actual: usize = body
            .lines()
            .filter_map(|line| line.split("params:").nth(1))
            .map(|params| {
                params
                    .split(']')
                    .next()
                    .unwrap()
                    .matches("text(input.restore_json")
                    .count()
            })
            .sum();
        assert_eq!(
            actual, expected,
            "actual fixed SQL parameter-array census: {function}"
        );
        envelope += actual;
    }
    assert_eq!(RESTORE_ENVELOPE_BINDINGS, envelope);
    let admission = include_str!("../../rss/storage/admission.rss");
    let transaction = admission
        .split("let mut statements: array<SqliteStatement> = [];")
        .nth(1)
        .unwrap()
        .split("let transaction_result:")
        .next()
        .unwrap();
    let mut actual = std::collections::BTreeMap::new();
    let mut derived = std::collections::BTreeMap::new();
    for line in transaction.lines().filter(|line| line.contains("params:")) {
        if line.contains("sql_text(input.model.copy()), sql_text(input.model.copy())") || line.contains("sql_text(input.parent_run_id.copy()), sql_text(input.run_id.copy()), sql_int(input.now_ms.copy())") {continue;}
        let params = line
            .split("params:")
            .nth(1)
            .unwrap()
            .split(']')
            .next()
            .unwrap();
        // The original admission census remains distinct from the added
        // fixed graph predicate, whose complete alternatives are checked below.
        let guard = "sql_text(input.tool_graph_id.copy()), sql_text(input.tool_graph_id.copy()), sql_text(input.run_id.copy()), sql_text(input.tool_graph_id.copy()), sql_text(input.tool_ref_id.copy())";
        let params = params.trim().trim_end_matches(',').trim();
        let params = params
            .strip_suffix(guard)
            .unwrap_or(params)
            .trim_end_matches(',')
            .trim();
        for tail in params.split("sql_text(").skip(1) {
            let expression = tail.split(")").next().unwrap().trim_end_matches(".copy(");
            if let Some(field) = expression.strip_prefix("input.") {
                *actual.entry(field.to_string()).or_insert(0usize) += 1;
            } else {
                *derived.entry(expression.to_string()).or_insert(0usize) += 1;
            }
        }
    }
    let declared = RESTORE_ADMISSION_BINDINGS
        .iter()
        .map(|(name, count)| (name.to_string(), *count))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        actual, declared,
        "fresh-session statement parameter weights drifted"
    );
    assert_eq!(
        derived,
        [
            ("encoded_content".into(), 1),
            ("receipt_key".into(), 2),
            ("receipt_scope".into(), 1),
            ("registry_identity".into(), 1),
            ("restore_harness_json".into(), 1),
            ("workspace".into(), 1)
        ]
        .into_iter()
        .collect()
    );
    // Formal pinned SQLite host accounts only text/blob payload bytes. The
    // existing normalization's five whole-wire binds are separate queries.
    let normalization = admission
        .split("fn admission_with_pin_fields(")
        .nth(1)
        .unwrap();
    assert_eq!(
        normalization
            .split("[sql_text(")
            .nth(1)
            .unwrap()
            .split(']')
            .next()
            .unwrap()
            .matches("payload_json.copy()")
            .count(),
        5
    );
}

#[test]
fn managed_aggregate_sql_parameter_budget_precedes_sdk_enqueue_and_matches_fixed_rss() {
    let source = include_str!("../../rss/storage/effects.rss");
    for op in [
        "run_binding",
        "run_list",
        "run_list_has_more",
        "run_cursor",
        "workspace_get",
        "workspace_register",
        "head",
        "get",
        "begin",
        "prepare",
        "delegate_intent",
        "commit",
        "pending",
        "recover_one",
        "recovery_context",
        "checkpoint_context",
        "checkpoint_get",
        "checkpoint_create",
        "branch_create",
        "branch_receipt",
        "branch_origin",
        "publish_eligibility",
        "publish_submit",
        "publish_receipt",
        "publication_get",
        "maintenance_receipt",
        "branch_publication_history",
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
    use std::os::unix::fs::PermissionsExt;
    let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
        .join(format!("managed-usage-{}", Uuid::new_v4().simple()));
    let workspace = root.join("workspace");
    let home = root.join("home");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir(&home).unwrap();
    for directory in [&root, &home] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(home.join("config.yaml"),format!("version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",workspace.display(),workspace.display())).unwrap();
    std::fs::set_permissions(
        home.join("config.yaml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let config = AgentGatewayConfig {
        managed_workspace: Some(ManagedWorkspaceConfig {
            source_root: workspace,
            quota: crate::effects::ResourceQuota::new(1000, 1048576, 16).unwrap(),
            retention: ManagedRetentionLimits::default(),
            maintenance_policy: Default::default(),
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
#[test]
fn graph_fixed_statement_arrays_and_guard_bindings_match_complete_post_edit_census() {
    fn body<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        source
            .split(start)
            .nth(1)
            .unwrap()
            .split(end)
            .next()
            .unwrap()
    }
    fn census(source: &str, prefix: &str) -> std::collections::BTreeMap<String, usize> {
        let mut counts = std::collections::BTreeMap::new();
        for line in source.lines().filter(|line| line.contains("params:")) {
            let params = line
                .split("params:")
                .nth(1)
                .unwrap()
                .split(']')
                .next()
                .unwrap();
            for tail in params.split(prefix).skip(1) {
                *counts
                    .entry(tail.split(['.', ')']).next().unwrap().to_string())
                    .or_insert(0) += 1;
            }
        }
        counts
    }
    let plugins = include_str!("../../rss/storage/plugins.rss");
    let helper = body(
        plugins,
        "fn storage_pin_requirement_statement(",
        "pub fn storage_admission_pin_statements(",
    );
    let classification = body(
        plugins,
        "pub fn storage_admission_pin_classification(",
        "pub fn storage_pin_text(",
    );
    for (name, end, declared) in [
        (
            "storage_admission_pin_statements",
            "storage_checkpoint_pin_statements",
            ORDINARY_PIN_BINDINGS,
        ),
        (
            "storage_checkpoint_pin_statements",
            "storage_admission_pin_classification",
            CHECKPOINT_PIN_BINDINGS,
        ),
    ] {
        let source = format!(
            "{}\n{helper}\n{classification}",
            body(
                plugins,
                &format!("pub fn {name}("),
                &format!("pub fn {end}(")
            )
        );
        let actual = census(&source, "sql_text(");
        let expected = declared
            .iter()
            .map(|(field, n)| {
                (
                    (match *field {
                        "tool_graph_id" => "graph_id",
                        "tool_ref_id" => "ref_id",
                        x => x,
                    })
                    .to_string(),
                    *n,
                )
            })
            .chain(if name == "storage_checkpoint_pin_statements" {
                vec![("checkpoint_id".into(), 1), ("checkpoint_ref".into(), 1)]
            } else {
                vec![]
            })
            .collect();
        assert_eq!(
            actual, expected,
            "complete helper-expanded pin census {name}"
        );
    }
    let events = include_str!("../../rss/storage/events.rss");
    let pair = body(
        events,
        "pub fn storage_event_append_pair(",
        "/// Returns the persisted retention",
    )
    .split("let statements:")
    .nth(1)
    .unwrap();
    let mut actual = census(pair, "sql_text(input.");
    actual.insert(
        "failpoint".into(),
        pair.matches("sql_text(failpoint)").count(),
    );
    assert_eq!(
        actual,
        EVENT_PAIR_BINDINGS
            .iter()
            .map(|(field, n)| (field.to_string(), *n))
            .collect()
    );
    let admission = include_str!("../../rss/storage/admission.rss");
    let transaction = body(
        admission,
        "let mut statements: array<SqliteStatement> = [];",
        "let transaction_result:",
    );
    let predicate_tail = "sql_text(input.tool_graph_id.copy()), sql_text(input.tool_graph_id.copy()), sql_text(input.run_id.copy()), sql_text(input.tool_graph_id.copy()), sql_text(input.tool_ref_id.copy())";
    let guard_count = transaction.matches(predicate_tail).count();
    assert_eq!(guard_count, 10);
    assert_eq!(
        ADMISSION_GRAPH_GUARD_BINDINGS,
        &[
            ("tool_graph_id", guard_count * 3),
            ("run_id", guard_count),
            ("tool_ref_id", guard_count)
        ]
    );
    let effects = include_str!("../../rss/storage/effects.rss");
    for (start, end, declared) in [
        (
            "pub fn restore_before_admission(",
            "pub fn maintenance_receipt(",
            RESTORE_GRAPH_GUARD_BINDINGS,
        ),
        (
            "pub fn admission_statements(",
            "pub fn begin(",
            MANAGED_ADMISSION_GRAPH_GUARD_BINDINGS,
        ),
    ] {
        let source = body(effects, start, end);
        let graph = census(source, "text(");
        let run_count = if start.contains("admission_statements") {
            2
        } else {
            13
        };
        assert_eq!(graph.get("graph_id"), Some(&(run_count * 3)));
        assert_eq!(graph.get("ref_id"), Some(&run_count));
        let actual_run = if start.contains("admission_statements") {
            source.matches("text(input.run_id.copy())").count() - 1
        } else {
            graph["run_id"]
        };
        assert_eq!(actual_run, run_count);
        assert_eq!(
            declared,
            &[
                ("tool_graph_id", run_count * 3),
                ("run_id", run_count),
                ("tool_ref_id", run_count)
            ]
        );
    }
}

#[test]
fn plugin_control_current_owner_count_is_eight_without_new_version_or_hidden_ddl() {
    let schema = include_str!("../../rss/storage/schema.rss");
    assert!(schema.contains("if migration_index == 4 => { 8 }"));
    assert!(schema.contains("pub fn schema_current_version() -> int {\n    6\n}"));
    assert!(schema.contains("rss-storage-v5-plugin-control"));
    assert!(schema.contains("statement_index == 6"));
    assert!(schema.contains("statement_index == 7"));
    for table in ["plugin_graph_revocations", "plugin_graph_pin_requirements"] {
        assert_eq!(
            schema
                .matches(&format!("CREATE TABLE IF NOT EXISTS {table} "))
                .count(),
            1
        );
        assert!(
            !include_str!("../../rss/storage/main.rss")
                .contains(&format!("CREATE TABLE IF NOT EXISTS {table}"))
        );
    }
}

#[test]
fn graph_parameter_real_boundary_controls_and_integer_zero_accounting() {
    let (_root, p) = persistence();
    let cap = crate::effects::journal::METADATA_BYTES;
    for (op, field, weight) in [
        ("admission.create", "tool_graph_id", 61usize),
        ("event.append_pair", "run_id", 21usize),
    ] {
        let overhead = if op == "admission.create" {
            serde_json::to_vec(&json!({field:""})).unwrap().len() * 5
                + "native.tool-pin".len() * 2
                + 8
                + serde_json::to_vec(&json!([{"type":"text","text":"null"}]))
                    .unwrap()
                    .len()
        } else {
            0
        };
        let n = (cap - overhead) / weight;
        let payload = json!({field:"x".repeat(n)});
        assert!(validate_graph_parameter_budget(op, &payload).is_ok());
        let before = p.executed_storage_commands();
        assert!(p.command_data(op, &payload).is_err());
        assert_eq!(
            p.executed_storage_commands(),
            before + 1,
            "below-bound control must reach formal worker"
        );
        let payload = json!({field:"x".repeat(n+1)});
        let before = p.executed_storage_commands();
        assert_eq!(
            validate_graph_parameter_budget(op, &payload),
            Err("managed_metadata_budget_exceeded".into())
        );
        assert!(p.command_data(op, &payload).is_err());
        assert_eq!(p.executed_storage_commands(), before);
    }
    assert_eq!(
        fixed_parameter_bytes(&json!({"run_id":7,"max_events":1}), EVENT_PAIR_BINDINGS).unwrap(),
        0
    );
    let unpinned = json!({"run_id":"r".repeat(70000),"tool_graph_id":""});
    assert!(validate_graph_parameter_budget("admission.create", &unpinned).is_ok());
    p.shutdown();
}

#[test]
fn required_pin_lifetime_is_independent_of_completed_receipt_expiry() {
    let (root, p) = persistence();
    let packages = crate::plugins::PackageStore::open(root.join("packages")).unwrap();
    packages.bind_policy(&crate::plugins::InstallAuthorization {
        admin: true,
        accepted_publishers: vec![],
        unsigned_dev_space: None,
    });
    packages.install_embedding_owned().unwrap();
    let graph = packages
        .resolve(&crate::plugins::ResolveRequest {
            harness_selection: crate::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: crate::runtime::native_tools::EMBEDDING_PACKAGE_ID.into(),
            },
            roots: vec![crate::plugins::PackageRequirement {
                id: crate::runtime::native_tools::EMBEDDING_PACKAGE_ID.into(),
                version: "1.0.0".into(),
            }],
            host_runtime: crate::plugins::HOST_RUNTIME.into(),
        })
        .unwrap();
    let control = crate::plugins::PluginControlStore::new(&p);
    control.store_lock(&graph).unwrap();
    let refs: Vec<_> = graph
        .packages
        .iter()
        .map(|package| crate::plugins::PackageArtifactRef {
            package_id: package.id.clone(),
            version: package.version.clone(),
            kind: package.kind.clone(),
            artifact_id: package.artifact_id.clone(),
        })
        .collect();
    control.activate(&graph.graph_id, 0, &refs).unwrap();
    p.admission_create(&json!({
        "session_id":"expiry-session","session_new":1,"profile":"gateway","platform":"api_server","account_id":"expiry-session",
        "model":"m","provider":"p","system_prompt":"","session_metadata_json":"{}","run_id":"expiry-run","parent_run_id":"",
        "input_json":"{\"text\":\"expiry\"}","message_id":"expiry-message","message_run_id":"expiry-run","script_hash":"s",
        "idempotency_scope":"expiry-scope","idempotency_key":"expiry-key","request_hash":"expiry-proof","workspace_identity_json":"",
        "event_id":"expiry-event","now_ms":100,"expires_at_ms":101,"tool_graph_id":graph.graph_id,"tool_graph_generation":1,"tool_ref_id":"expiry-ref","tool_pin_now_ms":100
    })).unwrap();
    let required = control.pin_requirement_for_run("expiry-run").unwrap();
    let receipt = p.command_data("idempotency.begin", &json!({"scope":"expiry-scope","key":"expiry-key","request_hash":"expiry-proof","resource_type":"run","resource_id":"expiry-run","claim_token":"new-claim","now_ms":200,"expires_at_ms":300})).unwrap();
    assert_eq!(receipt["rows"][0][5], "completed");
    assert_eq!(
        control.pin_requirement_for_run("expiry-run").unwrap(),
        required
    );
    assert!(required.is_some());
    p.shutdown();
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
            _managed_permit: Some(Arc::new(permit)),
            maintenance: None,
            _maintenance_read: None,
            state_owner: None,
            report_health: true,
            reply_block: None,
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
