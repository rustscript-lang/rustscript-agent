use super::*;
#[cfg(feature = "workspace-io-fault")]
fn register_native_budget_intent(
    binding: &Arc<crate::effects::broker::ManagedRunBinding>,
    index: usize,
    deadline_ms: u64,
    max_events: usize,
) {
    let call = binding
        .register(
            &format!("reference-budget-{index}"),
            "read_file",
            r#"{"path":"never-executed.txt"}"#,
            "read",
            deadline_ms,
        )
        .unwrap();
    let record = call.record();
    let seq = (index % 128) * 2 + 1000;
    let output = json!({"event_id":uuid::Uuid::new_v4().to_string(),"event_type":"tool.requested","seq":seq,"payload_json":"{}"});
    let terminal = json!({"event_id":uuid::Uuid::new_v4().to_string(),"event_type":"tool.started","seq":seq+1,"payload_json":"{}"});
    let projections = json!({"normal":{"output":output,"terminal":terminal}});
    binding.runtime.repository.command_with_cancellation("effect.begin",&json!({"effect_id":call.effect_id,"run_id":record.identity.owner.run_id,"call_id":record.identity.call_id,"workspace_id":record.identity.workspace.workspace_id,"branch_id":record.identity.workspace.branch_id,"record_json":serde_json::to_string(&record).unwrap(),"commit_id":call.receipt_id,"projections_json":projections.to_string(),"max_events":max_events}),&binding.cancel).unwrap();
    call.interrupt_unpublished();
    assert!(call.adapters("not-a-token").is_err());
}
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn real_native_factory_and_formal_rss_512_reference_boundary_uses_sdk_truncation_to_reject_513_without_silent_loss()
 {
    let (root, state) = fixture();
    let service = state.service();
    service
        .set_run_limits(
            crate::config::RunLimits::new(64, 128, 4 * 1024 * 1024, root.join("workspace"))
                .unwrap(),
        )
        .unwrap();
    let persistence = state.persistence().unwrap();
    let mut total = 0usize;
    let mut target = None;
    let mut last = None;
    while total < 508 {
        let run = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"Native metadata-only admitted intents"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let host = service
            .capability_host_bridges(&run.run_id)
            .unwrap()
            .unwrap();
        let deadline = host.lifecycle.as_ref().unwrap().original_deadline_ms();
        let handle = service.handle(&run.run_id).unwrap();
        let binding = handle
            .pinned_tool
            .as_ref()
            .unwrap()
            .managed
            .as_ref()
            .unwrap()
            .clone();
        let head = persistence
            .managed_workspace_head(&binding.workspace.identity)
            .unwrap();
        let request = crate::effects::ManagedObjectReferencesRequest {
            store_id: head.store_id,
            object_id: head.head_object_id,
        };
        if target.is_none() {
            let initial = persistence.managed_object_references(&request).unwrap();
            assert_eq!(initial.len(), 4);
            target = Some(request.clone());
        }
        let batch = (508 - total).min(128);
        for _ in 0..batch {
            register_native_budget_intent(
                &binding,
                total,
                deadline,
                service.inner.config.max_events_per_run,
            );
            total += 1;
        }
        last = Some((binding, deadline));
    }
    assert_eq!(total, 508);
    let request = target.unwrap();
    let exact = persistence
        .managed_object_references(&request)
        .expect("the actual SDK 512-row aggregate boundary must remain usable");
    assert_eq!(exact.len(), 512);
    assert_eq!(
        exact
            .iter()
            .filter(|reference| reference.reference_kind
                == crate::effects::ManagedObjectReferenceKind::CallBase)
            .count(),
        508
    );
    let (binding, deadline) = last.unwrap();
    register_native_budget_intent(
        &binding,
        total,
        deadline,
        service.inner.config.max_events_per_run,
    );
    assert!(
        persistence.managed_object_references(&request).is_err(),
        "513 real Native references must never be reported as a complete 512-row set"
    );
    drop(binding);
    drop(persistence);
    service.shutdown().await.unwrap();
}
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn actual_sdk_commit_acknowledgement_loss_reads_exact_durable_outcome_without_second_process_or_publication()
 {
    let (root, state) = fixture();
    let service = state.service();
    let persistence = state.persistence().unwrap();
    persistence.inject_drop_managed_commit_ack();
    let sentinel = root.join("lost-ack-sentinel");
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(json!({"id":"lost-native-ack","name":"terminal","arguments":{"argv":["/bin/sh","-c",format!("printf x >> '{}'; printf durable",sentinel.display())],"timeout_ms":1000}}))));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"reconcile a lost SDK acknowledgement"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    assert!(
        !persistence.managed_commit_ack_drop_armed(),
        "fixture must discard the actual successful SDK commit response, not only suppress live apply"
    );
    let request = crate::effects::ManagedEffectGetRequest {
        owner: crate::effects::ManagedOwnerScope {
            profile: "gateway".into(),
            session_id: run.session_id.clone(),
            run_id: run.run_id.clone(),
        },
        call_id: "lost-native-ack".into(),
    };
    let record = persistence.managed_effect_get(&request).unwrap().unwrap();
    let outcome = record
        .outcome
        .as_ref()
        .expect("durable final outcome after transport loss");
    let head = persistence
        .managed_workspace_head(&record.identity.workspace)
        .unwrap();
    assert_eq!(head.head_version, 2);
    assert_eq!(fs::read(&sentinel).unwrap(), b"x");
    let live = service.run_events(&run.run_id);
    for event in [&outcome.output_event, &outcome.terminal_event] {
        let found = live
            .iter()
            .filter(|value| value["event_id"] == event.event_id)
            .collect::<Vec<_>>();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["seq"], event.seq);
    }
    let crate::effects::ManagedCallReplay::Final {
        canonical_result, ..
    } = service.replay_managed_call(request.clone()).unwrap()
    else {
        panic!("lost acknowledgement was incorrectly assumed rolled back")
    };
    let full: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
    let facade = service
        .replay_durable_tool_result(&run.run_id, "lost-native-ack", "terminal")
        .unwrap()
        .unwrap();
    assert!(serde_json::to_value(facade).unwrap() == full);
    let messages = persistence.message_list(&run.session_id, 0).unwrap();
    let call_column = messages["columns"]
        .as_array()
        .unwrap()
        .iter()
        .position(|name| name == "tool_call_id")
        .unwrap();
    assert_eq!(
        messages["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|message| message[call_column] == "lost-native-ack")
            .count(),
        1
    );
    assert_eq!(
        persistence.managed_effect_get(&request).unwrap().unwrap(),
        record
    );
    assert_eq!(
        persistence
            .managed_workspace_head(&record.identity.workspace)
            .unwrap(),
        head
    );
    let config = (*service.inner.config).clone();
    drop(persistence);
    service.shutdown().await.unwrap();
    drop(service);
    drop(state);
    let reopened = AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite"))
        .unwrap()
        .with_workspace_home(root.join("home"));
    let service = reopened.service();
    assert!(
        serde_json::to_value(
            service
                .replay_durable_tool_result(&run.run_id, "lost-native-ack", "terminal")
                .unwrap()
                .unwrap()
        )
        .unwrap()
            == full
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
        reopened
            .persistence()
            .unwrap()
            .message_list(&run.session_id, 0)
            .unwrap(),
        messages
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"x");
    service.shutdown().await.unwrap();
}
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn managed_precommit_native_revocation_generation_and_original_deadline_never_resume_prepared_execution()
 {
    for cut in ["policy", "generation", "deadline"] {
        let (root, state) = fixture_config(|config| {
            if cut == "deadline" {
                config.run_timeout = std::time::Duration::from_secs(10);
            }
        });
        let service = state.service();
        let gate = service
            .arm_managed_call_prepare_gate("fenced-native")
            .unwrap();
        let provider = Arc::new(crate::ScriptedProvider::new());
        provider.push_ok(response(Some(json!({"id":"fenced-native","name":"write_file","arguments":{"path":"never.txt","content":"private-only"}}))));
        provider.push_ok(response(None));
        service.inject_provider_host(provider);
        let run = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"prepare under original Native authority"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let worker = tokio::spawn(
            service
                .clone()
                .run_worker(run.run_id.clone(), "ignored".into()),
        );
        let arrived = gate.wait_arrived(1);
        if arrived.is_err() {
            gate.release();
            worker.await.unwrap();
            panic!("owned Native precommit barrier absent: {arrived:?}");
        }
        let request = crate::effects::ManagedEffectGetRequest {
            owner: crate::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: run.session_id,
                run_id: run.run_id.clone(),
            },
            call_id: "fenced-native".into(),
        };
        let before = state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        let handle = service.handle(&run.run_id).unwrap();
        match cut {
            "policy" => handle.workspace_authority.as_ref().unwrap().revoke(),
            "generation" => {
                let host = service
                    .capability_host_bridges(&run.run_id)
                    .unwrap()
                    .unwrap();
                host.lifecycle.unwrap().recover_open_tokens().unwrap();
            }
            "deadline" => {}
            _ => unreachable!(),
        };
        if cut != "deadline" {
            gate.release();
        }
        worker.await.unwrap();
        drop(gate);
        if cut == "deadline" {
            assert!(
                handle.cancellation().deadline_passed(),
                "the unchanged original deadline must actually have elapsed"
            );
        }
        drop(handle);
        let after = state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap();
        assert!(after.outcome.is_none());
        assert_eq!(after.prepared, before.prepared);
        assert_eq!(
            after.identity.original_deadline_ms,
            before.identity.original_deadline_ms
        );
        assert_eq!(
            state
                .persistence()
                .unwrap()
                .managed_workspace_head(&before.identity.workspace)
                .unwrap()
                .head_version,
            1
        );
        assert!(!root.join("workspace/never.txt").exists());
        assert!(
            matches!(
                service.replay_managed_call(request).unwrap(),
                crate::effects::ManagedCallReplay::Staged { .. }
            ),
            "fresh read authorization cannot resume the revoked or expired execution"
        );
        service.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_transport_bytes_and_exact_row_decoders_reject_before_sdk_enqueue_without_coercion()
{
    let (_root, state) = fixture();
    let persistence = state.persistence().unwrap();
    let before = persistence.executed_storage_commands();
    for text in [
        "a".repeat(crate::effects::journal::METADATA_BYTES),
        "\"".repeat(600000),
        "界".repeat(350000),
    ] {
        assert!(
            persistence
                .managed_effect_command("effect.workspace_get", &json!({"record_json":text}))
                .is_err()
        );
    }
    assert_eq!(
        persistence.executed_storage_commands(),
        before,
        "oversized actual UTF-8/escaped transport must never enter the dedicated SDK worker"
    );
    for value in [
        json!({"columns":["record_json"],"rows":[[1]],"truncated":false}),
        json!({"columns":["wrong"],"rows":[],"truncated":false}),
        json!({"columns":["record_json"],"rows":[],"truncated":true}),
        json!({"columns":["record_json"],"rows":[["{}"],["{}"]],"truncated":false}),
    ] {
        assert!(
            crate::effects::journal::decode_record::<crate::effects::ManagedEffectRecord>(&value)
                .is_err()
        );
    }
    let source = include_str!("../../rss/storage/effects.rss");
    let mut statements = 0;
    let mut maximum = 0;
    let mut parameter_max = 0;
    for line in source.lines() {
        if line.contains("let statements:") {
            statements = 0;
        }
        if line.trim_start().starts_with("{ sql:") {
            statements += 1;
            maximum = maximum.max(statements);
            if let Some((_, tail)) = line.split_once("params: [") {
                let params = tail.split_once("], query:").unwrap().0;
                parameter_max = parameter_max
                    .max(params.matches("text(").count() + params.matches("integer(").count());
            }
        }
    }
    assert!((1..=32).contains(&maximum));
    assert!((1..=128).contains(&parameter_max));
    assert!(
        source.contains("max_rows: 512")
            && source.contains("max_result_bytes: 1048576")
            && source.contains("max_columns: 16")
            && source.contains("max_transaction_ms: 5000")
    );
    state.service().shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn exact_begin_and_prepared_resends_preserve_staged_receipt_without_new_authority() {
    let (root, state) = fixture();
    let service = state.service();
    service
        .inject_managed_effect_fault(crate::effects::ManagedEffectFault::AfterPrepared)
        .unwrap();
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(json!({"id":"staged","name":"write_file","arguments":{"path":"staged.txt","content":"staged evidence"}}))));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"formal phase resends"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    let request = crate::effects::ManagedEffectGetRequest {
        owner: crate::effects::ManagedOwnerScope {
            profile: "gateway".into(),
            session_id: run.session_id.clone(),
            run_id: run.run_id.clone(),
        },
        call_id: "staged".into(),
    };
    let persistence = state.persistence().unwrap();
    let before = persistence.managed_effect_get(&request).unwrap().unwrap();
    let call = service
        .handle(&run.run_id)
        .unwrap()
        .pinned_tool
        .as_ref()
        .unwrap()
        .managed
        .as_ref()
        .unwrap()
        .call("staged")
        .unwrap();
    let head = persistence
        .managed_workspace_head(&before.identity.workspace)
        .unwrap();
    let messages = persistence.message_list(&run.session_id, 0).unwrap();
    let begin = json!({"effect_id":call.effect_id,"run_id":run.run_id,"call_id":"staged","record_json":serde_json::to_string(&call.record()).unwrap()});
    let prepared = json!({"effect_id":call.effect_id,"receipt_id":call.receipt_id,"prepared_json":serde_json::to_string(before.prepared.as_ref().unwrap()).unwrap()});
    for (op, payload) in [("effect.begin", begin), ("effect.prepare", prepared)] {
        let reply = persistence
            .managed_effect_command(op, &payload)
            .expect("exact immutable phase resend must return the existing staged classification");
        let record: crate::effects::ManagedEffectRecord =
            crate::effects::journal::decode_record(&reply)
                .unwrap()
                .unwrap();
        assert_eq!(record, before);
    }
    assert_eq!(
        persistence
            .managed_workspace_head(&before.identity.workspace)
            .unwrap(),
        head
    );
    assert_eq!(
        persistence.message_list(&run.session_id, 0).unwrap(),
        messages
    );
    assert!(!root.join("workspace/staged.txt").exists());
    drop(call);
    drop(persistence);
    service.shutdown().await.unwrap();
}

#[test]
fn managed_formal_rss_parses_with_production_dialect() {
    let parsed = rustscript_vm::parse_source_with_dialect(
        include_str!("../../rss/storage/effects.rss"),
        crate::runtime::module_snapshot::snapshot_parser_dialect(),
        rustscript_vm::SharedParserOptions {
            source_id: 0,
            allow_implicit_externs: true,
            allow_implicit_semicolons: false,
            enforce_mutable_bindings: false,
            import_scan_mode: true,
        },
    );
    assert!(
        parsed.is_ok(),
        "formal RSS parser diagnostic: {:?}",
        parsed.err()
    );
    let compiled = crate::AgentRunner::from_source(
        include_str!("../../rss/storage/effects.rss"),
        crate::AgentConfig::default(),
    );
    assert!(
        compiled.is_ok(),
        "formal RSS compile diagnostic: {:?}",
        compiled.err()
    );
}
#[tokio::test(flavor = "multi_thread")]
async fn final_formal_commit_resend_returns_same_outcome_without_events_head_or_message_changes() {
    let (root, state) = fixture();
    let service = state.service();
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(
        json!({"id":"resend","name":"write_file","arguments":{"path":"once.txt","content":"once"}}),
    )));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"formal same-attempt resend"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    let request = crate::effects::ManagedEffectGetRequest {
        owner: crate::effects::ManagedOwnerScope {
            profile: "gateway".into(),
            session_id: run.session_id.clone(),
            run_id: run.run_id.clone(),
        },
        call_id: "resend".into(),
    };
    let persistence = state.persistence().unwrap();
    let before = persistence.managed_effect_get(&request).unwrap().unwrap();
    let call = service
        .handle(&run.run_id)
        .unwrap()
        .pinned_tool
        .as_ref()
        .unwrap()
        .managed
        .as_ref()
        .unwrap()
        .call("resend")
        .unwrap();
    let head = persistence
        .managed_workspace_head(&before.identity.workspace)
        .unwrap();
    let messages = persistence.message_list(&run.session_id, 0).unwrap();
    let events = service.run_events(&run.run_id);
    let payload = json!({"effect_id":call.effect_id,"receipt_id":call.receipt_id,"commit_id":call.receipt_id,"run_id":run.run_id,"workspace_id":before.identity.workspace.workspace_id,"branch_id":before.identity.workspace.branch_id,"prepared_json":serde_json::to_string(before.prepared.as_ref().unwrap()).unwrap()});
    let returned=persistence.managed_effect_command("effect.commit",&payload).expect("same exact finalized attempt must return the original receipt, even after the run completed");
    let decoded: crate::effects::ManagedEffectRecord =
        crate::effects::journal::decode_record(&returned)
            .unwrap()
            .unwrap();
    assert_eq!(decoded, before);
    let mut wrong = payload.clone();
    wrong["receipt_id"] = json!("receipt-00000000000000000000000000000000");
    assert!(
        persistence
            .managed_effect_command("effect.commit", &wrong)
            .is_err()
    );
    assert_eq!(
        persistence.managed_effect_get(&request).unwrap().unwrap(),
        before
    );
    assert_eq!(
        persistence
            .managed_workspace_head(&before.identity.workspace)
            .unwrap(),
        head
    );
    assert_eq!(
        persistence.message_list(&run.session_id, 0).unwrap(),
        messages
    );
    assert_eq!(service.run_events(&run.run_id), events);
    drop(call);
    drop(persistence);
    service.shutdown().await.unwrap();
    drop(service);
    drop(state);
    assert!(root.join(".gateway.sqlite.effects").is_dir());
}
