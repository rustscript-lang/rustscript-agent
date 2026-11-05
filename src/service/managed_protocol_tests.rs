use super::*;
#[tokio::test(flavor = "multi_thread")]
async fn guardian207_toolonly_ref_requirement_and_artifact_consumers() {
    use crate::AgentProviderHost;
    for fault in ["drop_requirement", "replace_ref", "artifact"] {
        let (root, state) = fixture();
        let service = state.service();
        let run = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"typed full ToolOnly guard"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let handle = service.handle(&run.run_id).unwrap();
        let p = state.persistence().unwrap();
        let provider = Arc::new(crate::ScriptedProvider::new());
        provider.push_ok(response(None));
        provider.push_ok(response(None));
        let durable = crate::durable_provider::DurableProviderHost::new(
            (*service).clone(),
            run.run_id.clone(),
            provider.clone(),
            service.inner.metrics.clone(),
        );
        let request = json!({"model":"synthetic","messages":[]});
        assert_eq!(durable.call(&request, &handle.cancel)["ok"], true);
        let mut held = None;
        if fault == "artifact" {
            let graph = crate::plugins::PluginControlStore::new(&p)
                .load_lock(handle.pinned_tool.as_ref().unwrap().graph_id())
                .unwrap()
                .lock;
            let path = crate::plugins::trusted_tool_package_root(&root.join("gateway.sqlite"))
                .join("artifacts")
                .join(&graph.packages[0].artifact_id);
            let aside = root.join("held-artifact");
            fs::rename(&path, &aside).unwrap();
            held = Some((path, aside));
        } else {
            p.mutate_graph_pin_for_test(&run.run_id, fault).unwrap();
        }
        let expected = if fault == "artifact" {
            "plugin_artifact_unavailable"
        } else {
            "plugin_graph_pin_required"
        };
        assert_eq!(
            service.check_harness_run(&run.run_id, &handle.cancel),
            Err(expected),
            "{fault}"
        );
        assert_eq!(
            durable.call(&request, &handle.cancel)["error"]["code"],
            expected,
            "{fault}"
        );
        assert_eq!(provider.requests().len(), 1);
        let context = serde_json::to_value(service.run_context(&run.run_id).unwrap()).unwrap();
        assert_eq!(
            service.refresh_provider_context(&run.run_id, &context, &handle.cancel)["error"]["code"],
            expected,
            "{fault}"
        );
        if let Some((path, aside)) = held {
            fs::rename(aside, path).unwrap();
        }
        service.shutdown().await.unwrap();
    }
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn guardian207_toolonly_ref_and_artifact_checkpoint_consumers() {
    for fault in ["drop_requirement", "replace_ref", "artifact"] {
        let (root, state, request) = maintenance_source().await;
        let service = state.service();
        let handle = service.handle(&request.source_run_id).unwrap();
        let p = state.persistence().unwrap();
        let mut held = None;
        if fault == "artifact" {
            let graph = crate::plugins::PluginControlStore::new(&p)
                .load_lock(handle.pinned_tool.as_ref().unwrap().graph_id())
                .unwrap()
                .lock;
            let path = crate::plugins::trusted_tool_package_root(&root.join("gateway.sqlite"))
                .join("artifacts")
                .join(&graph.packages[0].artifact_id);
            let aside = root.join("held-artifact");
            fs::rename(&path, &aside).unwrap();
            held = Some((path, aside));
        } else {
            p.mutate_graph_pin_for_test(&request.source_run_id, fault)
                .unwrap();
        }
        let expected = if fault == "artifact" {
            "plugin_artifact_unavailable"
        } else {
            "plugin_graph_pin_required"
        };
        assert_eq!(
            service
                .create_managed_checkpoint(request.clone())
                .await
                .unwrap_err()
                .to_string(),
            expected,
            "{fault}"
        );
        if let Some((path, aside)) = held {
            fs::rename(aside, path).unwrap();
        }
        let clock = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
        assert!(
            service
                .managed_runtime_for_test()
                .unwrap()
                .repository
                .checkpoint_receipt(&request, &clock, None)
                .unwrap()
                .is_none()
        );
        service.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn guardian207_managed_missing_durable_binding_or_runtime_refuses_reconstruction() {
    for fault in ["drop_binding", "runtime"] {
        let (_root, state) = fixture();
        let service = state.service();
        let run = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"missing original managed facts"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let p = state.persistence().unwrap();
        if fault == "drop_binding" {
            p.mutate_graph_pin_for_test(&run.run_id, "drop_binding")
                .unwrap();
        } else {
            *service.inner.managed_effects.write() = None;
        }
        service.evict_run_handle(&run.run_id);
        assert!(
            matches!(
                service.restore_handle_from_frozen_context(&run.run_id),
                Err(crate::AdmitError::PluginGraphPinRequired)
            ),
            "{fault}"
        );
        assert!(service.handle(&run.run_id).is_none());
        service.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn guardian207_stateless_affirmative_proof_and_storage_uncertainty() {
    let (_root, state) = fixture_config(|config| config.managed_workspace = None);
    let service = state.service();
    service
        .inner
        .stateless_tools
        .store(true, std::sync::atomic::Ordering::Release);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"explicit stateless positive"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let handle = service.handle(&run.run_id).unwrap();
    assert!(matches!(
        handle.native_disposition,
        Some(crate::service::NativeRuntimeDisposition::ExplicitStateless(
            _
        ))
    ));
    assert_eq!(
        service.check_harness_run(&run.run_id, &handle.cancel),
        Ok(())
    );
    // Later global activation intent cannot reclassify the original proof.
    service
        .inner
        .stateless_tools
        .store(false, std::sync::atomic::Ordering::Release);
    assert_eq!(
        service.check_harness_run(&run.run_id, &handle.cancel),
        Ok(())
    );
    state.persistence().unwrap().inject_persist_failure();
    assert_eq!(
        service.check_harness_run(&run.run_id, &handle.cancel),
        Err("plugin_graph_pin_required"),
        "N01 typed read error is uncertainty, not physical row deletion"
    );
    assert_eq!(
        service.check_harness_run(&run.run_id, &handle.cancel),
        Ok(())
    );
    service.shutdown().await.unwrap();
}

async fn guardian207_toolonly_consumer(revoke_provider: bool) {
    use crate::AgentProviderHost;
    let (_root, state) = fixture();
    let service = state.service();
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"guard consumer"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let handle = service.handle(&run.run_id).unwrap();
    let p = state.persistence().unwrap();
    let control = crate::plugins::PluginControlStore::new(&p);
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(None));
    provider.push_ok(response(None));
    let durable = crate::durable_provider::DurableProviderHost::new(
        (*service).clone(),
        run.run_id.clone(),
        provider.clone(),
        service.inner.metrics.clone(),
    );
    let request = json!({"model":"synthetic","messages":[]});
    let context = serde_json::to_value(service.run_context(&run.run_id).unwrap()).unwrap();
    if revoke_provider {
        assert_eq!(durable.call(&request, &handle.cancel)["ok"], true);
        assert_eq!(provider.requests().len(), 1);
    } else {
        assert_eq!(
            service.refresh_provider_context(&run.run_id, &context, &handle.cancel)["ok"],
            true
        );
    }
    control
        .revoke_graph(
            &service.tool_store().unwrap(),
            handle.pinned_tool.as_ref().unwrap().graph_id(),
        )
        .unwrap();
    if revoke_provider {
        let denied = durable.call(&request, &handle.cancel);
        assert_eq!(
            denied["error"]["code"], "plugin_graph_revoked",
            "F02 durable provider must refuse revoked ToolOnly before transport"
        );
        assert_eq!(provider.requests().len(), 1);
    } else {
        let denied = service.refresh_provider_context(&run.run_id, &context, &handle.cancel);
        assert_eq!(
            denied["error"]["code"], "plugin_graph_revoked",
            "F02 context refresh must refuse revoked ToolOnly"
        );
    }
    service.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread")]
async fn guardian207_toolonly_revoked_provider() {
    guardian207_toolonly_consumer(true).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn guardian207_toolonly_revoked_refresh() {
    guardian207_toolonly_consumer(false).await;
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn guardian207_toolonly_revoked_checkpoint() {
    let (_root, state, mut request) = maintenance_source().await;
    let service = state.service();
    assert!(
        service
            .create_managed_checkpoint(request.clone())
            .await
            .is_ok()
    );
    let p = state.persistence().unwrap();
    let control = crate::plugins::PluginControlStore::new(&p);
    let handle = service.handle(&request.source_run_id).unwrap();
    control
        .revoke_graph(
            &service.tool_store().unwrap(),
            handle.pinned_tool.as_ref().unwrap().graph_id(),
        )
        .unwrap();
    request.request_id = uuid::Uuid::new_v4().to_string();
    let result = service.create_managed_checkpoint(request.clone()).await;
    assert_eq!(
        result.unwrap_err().to_string(),
        "plugin_graph_revoked",
        "F02 checkpoint must refuse revoked ToolOnly"
    );
    let clock = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    assert!(
        service
            .managed_runtime_for_test()
            .unwrap()
            .repository
            .checkpoint_receipt(&request, &clock, None)
            .unwrap()
            .is_none()
    );
    service.shutdown().await.unwrap();
}

async fn guardian207_managed_reconstruction() {
    let (root, state) = fixture();
    let service = state.service();
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(json!({"id":"restore-write","name":"write_file","arguments":{"path":"restored.txt","content":"original managed identity"}}))));
    provider.push_ok(response(Some(json!({"id":"restore-terminal","name":"terminal","arguments":{"argv":["/bin/cat","restored.txt"],"timeout_ms":1000}}))));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"write and read original managed identity"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let original = service.handle(&run.run_id).unwrap();
    let original_binding = original
        .pinned_tool
        .as_ref()
        .unwrap()
        .managed
        .clone()
        .unwrap();
    let deadline = service.run_context(&run.run_id).unwrap().metadata["deadline_at_ms"].clone();
    service.evict_run_handle(&run.run_id);
    drop(original);
    let restored = service
        .restore_handle_from_frozen_context(&run.run_id)
        .unwrap()
        .unwrap();
    let binding = restored
        .pinned_tool
        .as_ref()
        .unwrap()
        .managed
        .as_ref()
        .expect("F01 original managed binding must survive persistent reconstruction");
    assert_eq!(binding.owner, original_binding.owner);
    assert_eq!(binding.code, original_binding.code);
    assert_eq!(binding.admitted_branch, original_binding.admitted_branch);
    assert_eq!(binding.admitted_epoch(), original_binding.admitted_epoch());
    assert!(binding.cancel.same_root(&restored.cancel));
    assert_eq!(
        service.run_context(&run.run_id).unwrap().metadata["deadline_at_ms"],
        deadline
    );
    let capabilities = service
        .build_capability_host_state(&run.run_id, &restored)
        .unwrap();
    assert!(capabilities.filesystem.is_none());
    assert!(capabilities.processes.is_none());
    drop(capabilities);
    service
        .clone()
        .run_worker(run.run_id.clone(), String::new())
        .await;
    for call_id in ["restore-write", "restore-terminal"] {
        let request = crate::effects::ManagedEffectGetRequest {
            owner: binding.owner.clone(),
            call_id: call_id.into(),
        };
        let record = state
            .persistence()
            .unwrap()
            .managed_effect_get(&request)
            .unwrap()
            .unwrap_or_else(|| {
                panic!(
                    "missing {call_id}; public events {:?}",
                    service
                        .run_events(&run.run_id)
                        .iter()
                        .map(|event| (
                            event["event"].clone(),
                            event["data"]["error_code"].clone(),
                            event["data"]["code"].clone()
                        ))
                        .collect::<Vec<_>>()
                )
            });
        assert!(
            record.outcome.is_some(),
            "actual restored managed effect {call_id}"
        );
        let crate::effects::ManagedCallReplay::Final {
            canonical_result, ..
        } = service.replay_managed_call(request).unwrap()
        else {
            panic!("terminal typed readback required")
        };
        let result: Value = serde_json::from_str(canonical_result.as_str()).unwrap();
        assert_eq!(result["ok"], true);
        if call_id == "restore-terminal" {
            assert_eq!(result["data"]["stdout"], "original managed identity");
            assert_eq!(result["data"]["exit_code"], 0);
        }
    }
    assert!(!root.join("workspace/restored.txt").exists());
    service.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread")]
async fn guardian207_toolonly_managed_reconstruction() {
    guardian207_managed_reconstruction().await;
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_rejects_unknown_mutable_context_without_partial_record() {
    let (_root, state, request) = maintenance_source().await;
    let service = state.service();
    service
        .inner
        .contexts
        .lock()
        .unwrap()
        .get_mut(&request.source_run_id)
        .unwrap()
        .metadata["custom_mutable_context"] = json!({"revision":7});
    let result = service.create_managed_checkpoint(request.clone()).await;
    let repository = service
        .managed_runtime_for_test()
        .unwrap()
        .repository
        .clone();
    let receipt = repository
        .checkpoint_receipt(
            &request,
            &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5)),
            None,
        )
        .unwrap();
    service.shutdown().await.unwrap();
    assert_eq!(result.unwrap_err().to_string(), "managed_state_unsupported");
    assert!(receipt.is_none());
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn pending_compaction_refuses_restore_without_branch_or_admission() {
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let request = restore_request(&state, &source).await;
    let p = state.persistence().unwrap();
    let session = service
        .run_context(&source.source_run_id)
        .unwrap()
        .session_id;
    p.run_create(&json!({"id":"pending-compactor","session_id":session,"parent_run_id":"","input_json":"{}","provider":"synthetic","model":"m","script_hash":"","idempotency_scope":"","idempotency_key":"","now_ms":1})).unwrap();
    for (from, to) in [("queued", "running"), ("running", "compacting")] {
        p.run_transition(&json!({"run_id":"pending-compactor","from_status":from,"to_status":to,"error_code":"","error_message":"","recovery_reason":"","now_ms":2})).unwrap();
    }
    p.compaction_start(&json!({"id":"pending-summary","session_id":session,"run_id":"pending-compactor","generation":2,"source_start_ordinal":1,"source_end_ordinal":1,"retained_tail_ordinal":1,"summary_json":"{}","token_estimate":0,"model":"m","now_ms":3})).unwrap();
    let result = service
        .restore_managed_checkpoint_and_admit(request.clone())
        .await;
    let receipt = service
        .managed_runtime_for_test()
        .unwrap()
        .repository
        .lookup_restore_receipt(
            &request,
            &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5)),
        )
        .unwrap();
    service.shutdown().await.unwrap();
    assert_eq!(
        result.unwrap_err().to_string(),
        "managed_history_incomplete"
    );
    assert!(receipt.is_none());
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn composed_restore_budget_refusal_preserves_source_and_original_clock() {
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let mut request = restore_request(&state, &source).await;
    request.input.text = "\n\\\"".repeat(6000);
    let runtime = service.managed_runtime_for_test().unwrap();
    let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    let before = runtime
        .repository
        .checkpoint_context(&source, &cancel)
        .unwrap()
        .head;
    let clock =
        service.run_context(&source.source_run_id).unwrap().metadata["deadline_at_ms"].clone();
    let result = service
        .restore_managed_checkpoint_and_admit(request.clone())
        .await;
    let after = runtime
        .repository
        .checkpoint_context(&source, &cancel)
        .unwrap()
        .head;
    let receipt = runtime
        .repository
        .lookup_restore_receipt(&request, &cancel)
        .unwrap();
    let attempts = service.inner.maintenance_attempts.lock().len();
    let after_clock =
        service.run_context(&source.source_run_id).unwrap().metadata["deadline_at_ms"].clone();
    service.shutdown().await.unwrap();
    assert_eq!(
        result.unwrap_err().to_string(),
        "managed_metadata_budget_exceeded"
    );
    assert_eq!(after, before);
    assert_eq!(clock, after_clock);
    assert!(receipt.is_none());
    assert_eq!(attempts, 0);
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_closed_inventory_and_history_refusals_have_no_partial_receipt() {
    for (case, expected) in [
        ("history_rows", "managed_history_budget_exceeded"),
        ("history_bytes", "managed_history_budget_exceeded"),
        ("unclosed_tool", "managed_history_incomplete"),
        ("missing_result", "managed_artifact_unavailable"),
    ] {
        let (root, state, request) = maintenance_source().await;
        let service = state.service();
        let runtime = service.managed_runtime_for_test().unwrap();
        let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
        let before = runtime
            .repository
            .checkpoint_context(&request, &cancel)
            .unwrap();
        let p = state.persistence().unwrap();
        let mut missing = None;
        if case == "missing_result" {
            let result = &before.effects[0]
                .outcome
                .as_ref()
                .unwrap()
                .canonical_result_ref
                .object_id;
            let path = root.join(".gateway.sqlite.effects/results").join(result);
            let held = root.join("owned-unavailable-result");
            fs::rename(&path, &held).unwrap();
            missing = Some((path, held));
        } else {
            for index in 0..if case == "history_rows" {
                125
            } else if case == "history_bytes" {
                9
            } else {
                1
            } {
                let content = if case == "unclosed_tool" {
                    json!([{"type":"tool_call","tool_call_id":"unclosed","name":"write_file","arguments_json":"{}"}])
                } else {
                    json!([{"type":"text","text":if case=="history_bytes" {"x".repeat(62000)} else {"closed retained fact".into()}}])
                };
                p.message_append(&json!({"id":format!("extra-{index}"),"session_id":before.session_id,"role":if case=="unclosed_tool" {"assistant"} else {"user"},"content_json":content.to_string(),"name":"","tool_call_id":"","parent_message_id":"","token_estimate":1,"metadata_json":"{}","run_id":"","finish_reason":"","now_ms":index+100})).unwrap();
            }
        }
        let result = service.create_managed_checkpoint(request.clone()).await;
        if let Some((path, held)) = missing {
            fs::rename(held, path).unwrap();
        }
        let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
        let receipt = runtime
            .repository
            .checkpoint_receipt(&request, &cancel, None)
            .unwrap();
        let after = runtime
            .repository
            .checkpoint_context(&request, &cancel)
            .unwrap()
            .head;
        service.shutdown().await.unwrap();
        assert_eq!(result.unwrap_err().to_string(), expected, "{case}");
        assert!(receipt.is_none(), "{case}");
        assert_eq!(after, before.head, "{case}");
    }
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_inventory_uses_actual_captured_manifest_and_complete_effect_declarations() {
    let (_root, state, request) = maintenance_source().await;
    let service = state.service();
    let binding = service
        .retained_tool_for_test(&request.source_run_id)
        .unwrap()
        .managed
        .clone()
        .unwrap();
    let code = &binding.code;
    let actual = service
        .tool_store()
        .unwrap()
        .read_installed(&code.artifact_id)
        .unwrap();
    let validate = crate::service::managed_checkpoints::validate_captured_inventory;
    validate(&actual, code).unwrap();
    assert!(actual.manifest.state.is_none());
    assert!(!actual.manifest.effects.entries.is_empty());
    let mut declared = actual.clone();
    let files = crate::runtime::native_tools::embedding_package_files().unwrap();
    let manifest = String::from_utf8(files["manifest.yaml"].clone()).unwrap();
    declared.manifest = crate::plugins::parse_plugin_manifest(
        &(manifest + "\nstate:\n  scope: run\n  schema: 1\n"),
    )
    .unwrap();
    validate(&declared, code).expect("declared run state is now versioned inventory");
    let mut state_effect = actual.clone();
    state_effect
        .manifest
        .effects
        .entries
        .values_mut()
        .find_map(|entry| entry.direct.first_mut())
        .unwrap()
        .kind = "plugin_state.write".into();
    assert_eq!(
        validate(&state_effect, code).unwrap_err(),
        "managed_state_unsupported"
    );
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn restore_preserves_old_messages_audit_usage_approval_delivery_and_new_readonly_prefix() {
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let p = state.persistence().unwrap();
    let session = service
        .run_context(&source.source_run_id)
        .unwrap()
        .session_id;
    // Explicit synthetic accounting fact through the original fixed usage producer.
    p.record_synthetic_usage_for_test(&source.source_run_id)
        .unwrap();
    p.delivery_advance(&session, "synthetic-frozen-consumer", 1)
        .unwrap();
    p.run_create(&json!({"id":"approval-audit-run","session_id":session,"parent_run_id":"","input_json":"{}","provider":"synthetic","model":"m","script_hash":"","idempotency_scope":"","idempotency_key":"","now_ms":1})).unwrap();
    p.run_transition(&json!({"run_id":"approval-audit-run","from_status":"queued","to_status":"running","error_code":"","error_message":"","recovery_reason":"","now_ms":2})).unwrap();
    let approval=p.approval_request(&json!({"id":"closed-old-approval","run_id":"approval-audit-run","session_id":session,"tool_call_id":"historical-call","tool_name":"write_file","arguments_json":"{}","risk_class":"write","decision_scope":"once","one_time":1,"requested_at_ms":3,"expires_at_ms":1000})).unwrap();
    assert_eq!(approval["rows"].as_array().unwrap().len(), 1);
    p.approval_resolve(&json!({"id":"closed-old-approval","run_id":"approval-audit-run","state":"approved","resolver":"synthetic","decision_reason":"owned fixture","resolved_at_ms":4})).unwrap();
    p.run_transition(&json!({"run_id":"approval-audit-run","from_status":"running","to_status":"completed","error_code":"","error_message":"","recovery_reason":"","now_ms":5})).unwrap();
    let request = restore_request(&state, &source).await;
    let events =
        json!({"run_id":source.source_run_id,"after_seq":0,"max_events":128,"max_bytes":1048576});
    let messages = p.message_list(&session, 0).unwrap();
    let audit = p.event_replay(&events).unwrap();
    let usage = p.run_get(&source.source_run_id).unwrap();
    let approval = p.approval_get("closed-old-approval").unwrap();
    let delivery = p
        .delivery_get(&session, "synthetic-frozen-consumer")
        .unwrap();
    let result = service
        .restore_managed_checkpoint_and_admit(request)
        .await
        .unwrap();
    assert_eq!(p.message_list(&session, 0).unwrap(), messages);
    assert_eq!(p.event_replay(&events).unwrap(), audit);
    assert_eq!(p.run_get(&source.source_run_id).unwrap(), usage);
    assert_eq!(p.approval_get("closed-old-approval").unwrap(), approval);
    assert_eq!(
        p.delivery_get(&session, "synthetic-frozen-consumer")
            .unwrap(),
        delivery
    );
    assert!(
        result
            .external_effects_not_reverted
            .contains(&crate::effects::ManagedExternalNotice::ProviderUsageNotReverted)
    );
    assert!(
        result
            .external_effects_not_reverted
            .contains(&crate::effects::ManagedExternalNotice::DeliveredContentNotReverted)
    );
    let inherited = p.message_list(&result.new_session_id, 0).unwrap();
    assert_eq!(
        inherited["rows"].as_array().unwrap().len(),
        messages["rows"].as_array().unwrap().len() + 1
    );
    let memory = service.run_context(&result.new_run_id).unwrap();
    let prefix = memory.messages.as_array().unwrap();
    assert_eq!(prefix.len(), 5);
    for message in &prefix[..4] {
        assert!(
            message["id"]
                .as_str()
                .unwrap()
                .starts_with(&format!("restored-{}-", result.new_session_id))
        );
        assert!(message["run_id"].is_null());
        assert!(message["metadata"]["origin"]["source_message_id"].is_string());
        if let Some(parent) = message["parent_message_id"].as_str() {
            assert!(parent.starts_with(&format!("restored-{}-", result.new_session_id)));
        }
    }
    assert_eq!(
        p.approval_list(&result.new_run_id, &result.new_session_id)
            .unwrap()["rows"],
        json!([])
    );
    assert!(
        p.managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: crate::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: result.new_session_id.clone(),
                run_id: result.new_run_id.clone()
            },
            call_id: "maintenance-write".into()
        })
        .unwrap()
        .is_none()
    );
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(None));
    service.inject_provider_host(provider.clone());
    service
        .clone()
        .run_worker(result.new_run_id.clone(), String::new())
        .await;
    assert_eq!(provider.requests().len(), 1);
    assert!(
        provider.requests()[0]["messages"]
            .to_string()
            .contains("synthetic Native checkpoint source")
    );
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn composed_restore_budget_boundary_matches_actual_typed_admission_payload() {
    use crate::gateway::store::validate_composed_restore_budget as admits;
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let request = restore_request(&state, &source).await;
    let captured = Arc::new(std::sync::Mutex::new(None));
    let seen = captured.clone();
    state
        .persistence()
        .unwrap()
        .inject_admission_precommit_hook(move |payload| {
            *seen.lock().unwrap() = Some(payload.clone());
        });
    service
        .restore_managed_checkpoint_and_admit(request)
        .await
        .unwrap();
    service.shutdown().await.unwrap();
    let original = captured.lock().unwrap().take().unwrap();
    let with_text = |count: usize| {
        let mut payload = original.clone();
        let mut envelope: Value =
            serde_json::from_str(payload["restore_json"].as_str().unwrap()).unwrap();
        envelope["request"]["input"]["text"] = json!("x".repeat(count));
        envelope["original_request_proof"] =
            json!(serde_json::to_string(&envelope["request"]).unwrap());
        payload["restore_json"] = json!(envelope.to_string());
        let mut input: Value =
            serde_json::from_str(payload["input_json"].as_str().unwrap()).unwrap();
        input["run_context"]["input"]["message"] = json!("x".repeat(count));
        payload["input_json"] = json!(input.to_string());
        payload
    };
    let (mut low, mut high) = (0usize, 65536usize);
    assert!(admits(&with_text(low)).is_ok());
    assert!(admits(&with_text(high)).is_err());
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if admits(&with_text(middle)).is_ok() {
            low = middle;
        } else {
            high = middle;
        }
    }
    assert_eq!(high, low + 1);
    for (count, positive) in [(low, true), (high, false)] {
        let (_root, state, source) = maintenance_source().await;
        let service = state.service();
        let p = state.persistence().unwrap();
        let mut request = restore_request(&state, &source).await;
        request.input.text = "x".repeat(count);
        let payload = Arc::new(std::sync::Mutex::new(None));
        let seen = payload.clone();
        let observing = p.clone();
        p.inject_admission_precommit_hook(move |value| {
            *seen.lock().unwrap() = Some((value.clone(), observing.executed_storage_commands()));
        });
        let result = service
            .restore_managed_checkpoint_and_admit(request.clone())
            .await;
        let after = p.executed_storage_commands();
        let (actual, before) = payload.lock().unwrap().take().unwrap();
        assert_eq!(
            admits(&actual).is_ok(),
            positive,
            "actual final payload at {count}"
        );
        assert!(
            serde_json::to_vec(&actual).unwrap().len() < 1048576,
            "aggregate bound, not only transport"
        );
        if positive {
            assert!(result.is_ok(), "last admitted byte boundary: {result:?}");
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                "managed_metadata_budget_exceeded"
            );
            assert_eq!(
                after, before,
                "no final admission enqueue at first rejected byte boundary"
            );
            let receipt = service
                .managed_runtime_for_test()
                .unwrap()
                .repository
                .lookup_restore_receipt(
                    &request,
                    &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5)),
                )
                .unwrap();
            assert!(receipt.is_none());
        }
        service.shutdown().await.unwrap();
    }
    eprintln!(
        "actual typed restore aggregate boundary: accepted input bytes {low}, rejected input bytes {high}"
    );
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn pending_compaction_after_frozen_read_cannot_publish_restore() {
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let p = state.persistence().unwrap();
    let request = restore_request(&state, &source).await;
    let session = service
        .run_context(&source.source_run_id)
        .unwrap()
        .session_id;
    p.run_create(&json!({"id":"late-compactor","session_id":session,"parent_run_id":"","input_json":"{}","provider":"synthetic","model":"m","script_hash":"","idempotency_scope":"","idempotency_key":"","now_ms":1})).unwrap();
    for (from, to) in [("queued", "running"), ("running", "compacting")] {
        p.run_transition(&json!({"run_id":"late-compactor","from_status":from,"to_status":to,"error_code":"","error_message":"","recovery_reason":"","now_ms":2})).unwrap();
    }
    let late = p.clone();
    p.inject_admission_precommit_hook(move |_| {late.compaction_start(&json!({"id":"late-summary","session_id":session,"run_id":"late-compactor","generation":2,"source_start_ordinal":1,"source_end_ordinal":1,"retained_tail_ordinal":1,"summary_json":"{}","token_estimate":0,"model":"m","now_ms":3})).unwrap();});
    let result = service
        .restore_managed_checkpoint_and_admit(request.clone())
        .await;
    let runtime = service.managed_runtime_for_test().unwrap();
    let receipt = runtime
        .repository
        .lookup_restore_receipt(
            &request,
            &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5)),
        )
        .unwrap();
    if matches!(
        &result,
        Err(crate::effects::ManagedMaintenanceFailure::SubmittedUnknown { .. })
    ) {
        let reconciled = service.restore_managed_checkpoint_and_admit(request).await;
        assert!(reconciled.is_err());
    }
    service.shutdown().await.unwrap();
    assert!(
        result.is_err(),
        "a compaction becoming pending after capture must prevent the actual restore transaction"
    );
    assert!(receipt.is_none());
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn pending_compaction_after_frozen_read_cannot_publish_checkpoint() {
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let p = state.persistence().unwrap();
    let session = service
        .run_context(&source.source_run_id)
        .unwrap()
        .session_id;
    p.run_create(&json!({"id":"late-capture-compactor","session_id":session,"parent_run_id":"","input_json":"{}","provider":"synthetic","model":"m","script_hash":"","idempotency_scope":"","idempotency_key":"","now_ms":1})).unwrap();
    for (from, to) in [("queued", "running"), ("running", "compacting")] {
        p.run_transition(&json!({"run_id":"late-capture-compactor","from_status":from,"to_status":to,"error_code":"","error_message":"","recovery_reason":"","now_ms":2})).unwrap();
    }
    let late = p.clone();
    let once = std::sync::atomic::AtomicBool::new(false);
    *p.managed_request_hook.lock().unwrap() = Some(Arc::new(move |op, _, enqueued| {
        if op == "effect.checkpoint_create"
            && !enqueued
            && !once.swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            late.compaction_start(&json!({"id":"late-capture-summary","session_id":session,"run_id":"late-capture-compactor","generation":2,"source_start_ordinal":1,"source_end_ordinal":1,"retained_tail_ordinal":1,"summary_json":"{}","token_estimate":0,"model":"m","now_ms":3})).unwrap();
        }
    }));
    let result = service.create_managed_checkpoint(source.clone()).await;
    *p.managed_request_hook.lock().unwrap() = None;
    let receipt = service
        .managed_runtime_for_test()
        .unwrap()
        .repository
        .checkpoint_receipt(
            &source,
            &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5)),
            None,
        )
        .unwrap();
    if matches!(
        &result,
        Err(crate::effects::ManagedMaintenanceFailure::SubmittedUnknown { .. })
    ) {
        assert!(service.create_managed_checkpoint(source).await.is_err());
    }
    service.shutdown().await.unwrap();
    assert!(
        result.is_err(),
        "a compaction becoming pending after capture must prevent the actual checkpoint transaction"
    );
    assert!(receipt.is_none());
}

#[cfg(feature = "workspace-io-fault")]
pub(super) async fn maintenance_source() -> (
    PathBuf,
    AgentGatewayState,
    crate::effects::ManagedCheckpointCreateRequest,
) {
    maintenance_source_timeout(std::time::Duration::from_secs(300)).await
}
#[cfg(feature = "workspace-io-fault")]
async fn maintenance_source_timeout(
    timeout: std::time::Duration,
) -> (
    PathBuf,
    AgentGatewayState,
    crate::effects::ManagedCheckpointCreateRequest,
) {
    let (root, state) = fixture_config(|config| {
        config.run_timeout = timeout;
        config.bearer_token = Some("synthetic-maintenance-fixture".into());
        let policy = &mut config
            .managed_workspace
            .as_mut()
            .unwrap()
            .maintenance_policy;
        policy.create_checkpoint = true;
        policy.restore = true;
    });
    let service = state.service();
    // Code-only fixture setup precedes the source admission's original short
    // clock; no run, deadline, authority or admission is created here.
    service
        .materialize_cached_runner()
        .expect("materialize maintenance fixture code");
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(json!({"id":"maintenance-write", "name":"write_file", "arguments":{"path":"original.txt","content":"frozen A"}}))));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"synthetic Native checkpoint source"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    service
        .clone()
        .run_worker(run.run_id.clone(), String::new())
        .await;
    let record = state
        .persistence()
        .unwrap()
        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: crate::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: run.session_id,
                run_id: run.run_id.clone(),
            },
            call_id: "maintenance-write".into(),
        })
        .unwrap()
        .unwrap();
    assert!(
        record.outcome.is_some(),
        "maintenance source stage state={:?}; event/code={:?}",
        record.state,
        service
            .run_events(&run.run_id)
            .iter()
            .map(|e| (e["event"].clone(), e["data"]["error_code"].clone()))
            .collect::<Vec<_>>()
    );
    let request = crate::effects::ManagedCheckpointCreateRequest {
        source_run_id: run.run_id,
        workspace_id: record.identity.workspace.workspace_id,
        source_branch_id: record.identity.workspace.branch_id,
        expected_epoch: record.identity.epoch,
        request_id: uuid::Uuid::new_v4().to_string(),
        mode: crate::effects::ManagedCheckpointMode::AtClosedBatch,
    };
    (root, state, request)
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn restore_http_repairs_missing_initial_start_once() {
    maintenance_http_once(false).await;
}
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn restore_http_unknown_retries_execute_once() {
    maintenance_http_once(true).await;
}
#[cfg(feature = "workspace-io-fault")]
pub(super) async fn restore_request(
    state: &AgentGatewayState,
    source: &crate::effects::ManagedCheckpointCreateRequest,
) -> crate::effects::ManagedRestoreAndAdmitRequest {
    let checkpoint = state
        .service()
        .create_managed_checkpoint(source.clone())
        .await
        .unwrap()
        .checkpoint;
    let runtime = state.service().managed_runtime_for_test().unwrap();
    let context = runtime
        .repository
        .checkpoint_context(
            source,
            &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5)),
        )
        .unwrap();
    crate::effects::ManagedRestoreAndAdmitRequest {
        workspace_id: source.workspace_id.clone(),
        source_branch_id: source.source_branch_id.clone(),
        checkpoint_id: checkpoint.checkpoint_id,
        expected_source: crate::effects::ManagedSourceCas {
            store_id: context.head.store_id,
            workspace_id: context.head.workspace_id,
            branch_id: context.head.branch_id,
            epoch: context.head.epoch,
            head_object_id: context.head.head_object_id,
            head_version: context.head.head_version,
        },
        request_id: uuid::Uuid::new_v4().to_string(),
        input: crate::effects::ManagedRestoreRunInput {
            text: "synthetic restored read".into(),
        },
        cancel_active_source: true,
        graph_selection: crate::effects::ManagedRestoreGraphSelection::CheckpointExact,
    }
}

#[cfg(feature = "workspace-io-fault")]
pub(super) async fn maintenance_http(
    address: std::net::SocketAddr,
    path: &str,
    body: Value,
) -> (u16, Value) {
    use http_body_util::{BodyExt, Full};
    let client: hyper_util::client::legacy::Client<_, Full<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let request = hyper::Request::post(format!("http://{address}{path}"))
        .header("content-type", "application/json")
        .header("authorization", "Bearer synthetic-maintenance-fixture")
        .body(Full::new(bytes::Bytes::from(body.to_string())))
        .unwrap();
    let response = client.request(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}
#[cfg(feature = "workspace-io-fault")]
struct RestoreCountingProvider(std::sync::atomic::AtomicUsize, std::sync::Mutex<Vec<Value>>);
#[cfg(feature = "workspace-io-fault")]
impl crate::AgentProviderHost for RestoreCountingProvider {
    fn call(&self, request: &Value, _: &crate::RunCancellation) -> Value {
        self.1.lock().unwrap().push(request.clone());
        let step = self.0.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        json!({"ok":true,"response":response(if step==0 {Some(json!({"id":"restored-once-write","name":"write_file","arguments":{"path":"restored-once.txt","content":"C"}}))}else{None}),"error":{}})
    }
}

#[cfg(feature = "workspace-io-fault")]
async fn maintenance_http_once(ack_lost: bool) {
    use std::future::IntoFuture;

    struct Cleanup {
        service: Arc<crate::AgentService>,
        run_id: Option<String>,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if std::thread::panicking()
                && let Some(run_id) = &self.run_id
            {
                self.service.stop(run_id);
            }
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
        }
    }
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let restore = restore_request(&state, &source).await;
    let initial = if ack_lost {
        None
    } else {
        Some(
            service
                .restore_managed_checkpoint_and_admit(restore.clone())
                .await
                .unwrap(),
        )
    };
    let provider = Arc::new(RestoreCountingProvider(
        std::sync::atomic::AtomicUsize::new(0),
        std::sync::Mutex::new(Vec::new()),
    ));
    service.inject_provider_host(provider.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(
        axum::serve(listener, crate::build_agent_gateway_app(state.clone()))
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .into_future(),
    );
    let mut cleanup = Cleanup {
        service: service.clone(),
        run_id: None,
        stop: Some(stop),
    };
    let path = format!("/v1/workspaces/{}/restore", restore.workspace_id);
    let body = serde_json::to_value(&restore).unwrap();
    let receipt = if let Some(receipt) = initial {
        receipt
    } else {
        state
            .persistence()
            .unwrap()
            .inject_drop_managed_commit_ack();
        let unknown = maintenance_http(address, &path, body.clone()).await;
        assert_eq!(unknown.0, 202);
        assert_eq!(unknown.1["disposition"], "submitted_unknown");
        assert_eq!(unknown.1["request_id"], restore.request_id);
        service
            .managed_runtime_for_test()
            .unwrap()
            .repository
            .restore_receipt(
                &restore,
                &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5)),
            )
            .unwrap()
    };
    cleanup.run_id = Some(receipt.new_run_id.clone());
    let (a, b) = tokio::join!(
        maintenance_http(address, &path, body.clone()),
        maintenance_http(address, &path, body.clone())
    );
    assert_eq!(a.0, 202, "first exact retry {a:?}; other {b:?}");
    assert_eq!(b.0, 202, "second exact retry {b:?}");
    // Publication can first occur in these retries. Subscribe and inspect the
    // retained terminal under one store lock, including an already-finished run.
    let handle = service.handle(&receipt.new_run_id).unwrap();
    let original_deadline = handle.cancel.deadline_instant();
    let remaining = || {
        let remaining = handle
            .cancel
            .remaining_deadline()
            .expect("restored run must retain its original finite clock");
        assert!(
            !remaining.is_zero(),
            "original restore clock expired before observation"
        );
        remaining
    };
    let (mut events, mut terminal, mut status) = {
        let store = service.inner.store.read();
        let run = store.runs.get(&receipt.new_run_id).unwrap();
        (
            run.sender.as_ref().map(|sender| sender.subscribe()),
            run.events
                .iter()
                .rev()
                .find(|event| event.is_terminal())
                .map(|event| event.event.clone()),
            run.status.clone(),
        )
    };
    let completed = tokio::time::timeout(remaining(), async {
        loop {
            if let Some(event) = terminal.take() {
                break event;
            }
            assert!(
                !matches!(status.as_str(), "completed" | "failed" | "cancelled"),
                "retained terminal event missing for status {status}"
            );
            match events
                .as_mut()
                .expect("restored run event channel missing")
                .recv()
                .await
            {
                Ok(event) if event.is_terminal() => break event.event,
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    let store = service.inner.store.read();
                    let run = store.runs.get(&receipt.new_run_id).unwrap();
                    terminal = run
                        .events
                        .iter()
                        .rev()
                        .find(|event| event.is_terminal())
                        .map(|event| event.event.clone());
                    status = run.status.clone();
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    panic!("restored run event channel closed before completion");
                }
            }
        }
    })
    .await
    .expect("restored run did not complete within its original clock");
    assert_eq!(completed, "run.completed");
    // Terminal broadcast precedes worker return. Observe occupancy separately;
    // shutdown is not a join and must not race an active worker.
    tokio::time::timeout(remaining(), async {
        while !handle.worker_is_idle_for_test()
            || !handle.terminal.load(std::sync::atomic::Ordering::Acquire)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("restored worker did not become idle within its original clock");
    assert!(Arc::ptr_eq(
        &handle,
        &service.handle(&receipt.new_run_id).unwrap()
    ));
    assert!(
        handle
            .restore_worker_started
            .as_ref()
            .unwrap()
            .load(std::sync::atomic::Ordering::Acquire)
    );
    let run_ids = || {
        service
            .inner
            .runs
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
    };
    let before_run_ids = run_ids();
    let count = provider.0.load(std::sync::atomic::Ordering::Acquire);
    assert_eq!(
        count, 2,
        "completed restore must execute both provider turns"
    );
    {
        let persistence = state.persistence().unwrap();
        let before = persistence.run_get(&receipt.new_run_id).unwrap();
        let messages = persistence
            .message_list(&receipt.new_session_id, 0)
            .unwrap();
        let late = maintenance_http(address, &path, body).await;
        assert_eq!(late.0, 202);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(provider.0.load(std::sync::atomic::Ordering::Acquire), 2);
        assert_eq!(persistence.run_get(&receipt.new_run_id).unwrap(), before);
        assert_eq!(
            persistence
                .message_list(&receipt.new_session_id, 0)
                .unwrap(),
            messages
        );
    }
    assert!(Arc::ptr_eq(
        &handle,
        &service.handle(&receipt.new_run_id).unwrap()
    ));
    assert_eq!(handle.cancel.deadline_instant(), original_deadline);
    assert_eq!(run_ids(), before_run_ids);
    assert!(handle.worker_is_idle_for_test());
    assert!(
        handle
            .restore_worker_started
            .as_ref()
            .unwrap()
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert_eq!(
        service.inner.store.read().runs[&receipt.new_run_id].status,
        "completed"
    );
    let _ = cleanup.stop.take().unwrap().send(());
    server.await.unwrap().unwrap();
    service.shutdown().await.unwrap();
    assert!(
        service
            .handle(&receipt.new_run_id)
            .unwrap()
            .terminal
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert_eq!(
        count, 2,
        "lost initial worker start must be claimed once despite concurrent exact HTTP retries"
    );
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn confirmed_commit_with_receipt_read_failure_retains_same_publication() {
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let request = restore_request(&state, &source).await;
    let persistence = state.persistence().unwrap();
    let weak = Arc::downgrade(&persistence);
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = reads.clone();
    *persistence.managed_request_hook.lock().unwrap() = Some(Arc::new(move |op, _, enqueued| {
        if !enqueued
            && op == "effect.maintenance_receipt"
            && count.fetch_add(1, std::sync::atomic::Ordering::AcqRel) == 1
        {
            weak.upgrade().unwrap().inject_persist_failure();
        }
    }));
    let outcome = service
        .restore_managed_checkpoint_and_admit(request.clone())
        .await;
    *persistence.managed_request_hook.lock().unwrap() = None;
    assert_eq!(
        outcome.unwrap_err().to_string(),
        "managed_submitted_unknown",
        "COMMIT succeeded; only exact receipt read failed"
    );
    let runtime = service.managed_runtime_for_test().unwrap();
    let durable = runtime
        .repository
        .restore_receipt(
            &request,
            &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5)),
        )
        .unwrap();
    let original = service.handle(&durable.new_run_id).unwrap();
    let retry = service
        .restore_managed_checkpoint_and_admit(request)
        .await
        .unwrap();
    assert_eq!(retry.new_run_id, durable.new_run_id);
    assert!(Arc::ptr_eq(
        &original,
        &service.handle(&retry.new_run_id).unwrap()
    ));
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn restore_ack_lost_reconciles_once() {
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let request = restore_request(&state, &source).await;
    let persistence = state.persistence().unwrap();
    persistence.inject_drop_managed_commit_ack();
    let unknown = service
        .restore_managed_checkpoint_and_admit(request.clone())
        .await;
    assert!(
        !persistence.managed_commit_ack_drop_armed(),
        "real restore/admission COMMIT ack discarded"
    );
    assert_eq!(
        unknown.unwrap_err().to_string(),
        "managed_submitted_unknown"
    );
    let runtime = service.managed_runtime_for_test().unwrap();
    let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    let durable = runtime
        .repository
        .restore_receipt(&request, &cancel)
        .unwrap();
    assert!(
        service.handle(&durable.new_run_id).is_none(),
        "no publication before reconciliation"
    );
    let restored = service
        .restore_managed_checkpoint_and_admit(request.clone())
        .await
        .unwrap();
    assert_eq!(restored.new_run_id, durable.new_run_id);
    assert_eq!(
        restored.new_run_deadline_at_ms,
        durable.new_run_deadline_at_ms
    );
    assert!(
        service.handle(&restored.new_run_id).is_some(),
        "same original admission published"
    );
    let repeated = service
        .restore_managed_checkpoint_and_admit(request)
        .await
        .unwrap();
    assert_eq!(restored.new_run_id, repeated.new_run_id);
    assert_eq!(restored.source_after, repeated.source_after);
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn unfinished_original_job_and_timed_out_borrow_cannot_enqueue_more_work() {
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let request = restore_request(&state, &source).await;
    let persistence = state.persistence().unwrap();
    let gate = persistence.block_maintenance_reply_for_test();
    let s = service.clone();
    let r = request.clone();
    let submitted = tokio::spawn(async move { s.restore_managed_checkpoint_and_admit(r).await });
    gate.wait_entered();
    assert_eq!(
        submitted.await.unwrap().unwrap_err().to_string(),
        "managed_submitted_unknown"
    );
    let retry = service
        .restore_managed_checkpoint_and_admit(request.clone())
        .await;
    gate.release();
    assert_eq!(
        retry.unwrap_err().to_string(),
        "managed_submitted_unknown",
        "worker still owns the unfinished original job"
    );
    persistence.run_get(&source.source_run_id).unwrap(); // ordered worker acknowledgement
    let attempt = service
        .inner
        .maintenance_attempts
        .lock()
        .get(&request.request_id)
        .unwrap()
        .clone();
    // A real bounded read timeout retains that same job ownership until worker reply finishes.
    let read_gate = persistence.block_maintenance_reply_for_test();
    let claim = attempt.claim.clone();
    let p = persistence.clone();
    let payload = json!({"workspace_id":request.workspace_id,"receipt_id":request.request_id,"cut":"restore"});
    let wire = payload.clone();
    let reader = tokio::task::spawn_blocking(move || {
        p.maintenance_read(
            &claim,
            &claim.identity,
            &claim.proof,
            "effect.maintenance_receipt",
            &wire,
            &crate::RunCancellation::with_timeout(std::time::Duration::from_millis(100)),
        )
    });
    read_gate.wait_entered();
    assert!(reader.await.unwrap().is_err());
    let before = persistence.executed_storage_commands();
    for _ in 0..3 {
        assert!(
            persistence
                .maintenance_read(
                    &attempt.claim,
                    &attempt.claim.identity,
                    &attempt.claim.proof,
                    "effect.maintenance_receipt",
                    &payload,
                    &crate::RunCancellation::with_timeout(std::time::Duration::from_millis(100))
                )
                .is_err()
        );
    }
    assert_eq!(
        persistence.executed_storage_commands(),
        before,
        "one unfinished borrowed job, no replacement queue entries"
    );
    read_gate.release();
    persistence.run_get(&source.source_run_id).unwrap();
    let restored = service
        .restore_managed_checkpoint_and_admit(request)
        .await
        .unwrap();
    assert!(service.handle(&restored.new_run_id).is_some());
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_rollback_releases_only_confirmed_attempt() {
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let persistence = state.persistence().unwrap();
    persistence.inject_maintenance_transaction_fault(99);
    assert_eq!(
        service
            .create_managed_checkpoint(source.clone())
            .await
            .unwrap_err()
            .to_string(),
        "managed_submitted_unknown"
    );
    assert_eq!(persistence.pending_count_for_test(), 1);
    assert_eq!(
        service
            .create_managed_checkpoint(source.clone())
            .await
            .unwrap_err()
            .to_string(),
        "managed_transaction_rolled_back"
    );
    assert_eq!(persistence.pending_count_for_test(), 0);
    assert!(
        service.create_managed_checkpoint(source).await.is_ok(),
        "confirmed rollback permits a new capture"
    );
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn restore_and_admission_rollback_together() {
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let template = restore_request(&state, &source).await;
    let persistence = state.persistence().unwrap();
    let runtime = service.managed_runtime_for_test().unwrap();
    let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    let original = runtime
        .repository
        .checkpoint_context(&source, &cancel)
        .unwrap();
    let old_session = original.session_id.clone();
    persistence.approval_request(&json!({"id":"rollback-audit-approval","run_id":source.source_run_id,"session_id":old_session,"tool_call_id":"maintenance-write","tool_name":"write_file","arguments_json":"{}","risk_class":"write","decision_scope":"","one_time":1,"requested_at_ms":1,"expires_at_ms":0})).unwrap();
    persistence.approval_resolve(&json!({"id":"rollback-audit-approval","run_id":source.source_run_id,"state":"approved","resolver":"synthetic-history","decision_reason":"retain historical approval","resolved_at_ms":2})).unwrap();
    persistence
        .delivery_set(&old_session, "synthetic-delivery", 7)
        .unwrap();
    let approval = persistence.approval_get("rollback-audit-approval").unwrap();
    let delivery = persistence
        .delivery_get(&old_session, "synthetic-delivery")
        .unwrap();
    let old_messages = persistence.message_list(&old_session, 0).unwrap();
    let old_run = persistence.run_get(&source.source_run_id).unwrap();
    for stage in [4, 6, 10, 12, 17, 99] {
        let mut request = template.clone();
        request.request_id = uuid::Uuid::new_v4().to_string();
        let active = service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"synthetic idle source to be cancelled"}),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        persistence.inject_maintenance_transaction_fault(stage);
        assert_eq!(
            service
                .restore_managed_checkpoint_and_admit(request.clone())
                .await
                .unwrap_err()
                .to_string(),
            "managed_submitted_unknown",
            "actual transaction cut {stage}"
        );
        let attempt = service
            .inner
            .maintenance_attempts
            .lock()
            .get(&request.request_id)
            .unwrap()
            .clone();
        let envelope = attempt.restore.lock().as_ref().unwrap().envelope.clone();
        assert!(
            crate::plugins::PluginControlStore::new(&persistence)
                .pin_requirement_for_run(&envelope.result.new_run_id)
                .unwrap()
                .is_none()
        );
        assert!(attempt.claim.worker_failed());
        assert!(service.handle(&envelope.result.new_run_id).is_none());
        assert!(
            service
                .handle(&active.run_id)
                .unwrap()
                .terminal
                .load(std::sync::atomic::Ordering::Acquire)
        );
        assert_eq!(
            service
                .restore_managed_checkpoint_and_admit(request.clone())
                .await
                .unwrap_err()
                .to_string(),
            "managed_transaction_rolled_back",
            "cut {stage} exact absent receipt and all targets absent"
        );
        assert!(
            runtime
                .repository
                .restore_rollback_confirmed(
                    &attempt.claim,
                    &envelope,
                    &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5))
                )
                .unwrap()
        );
        assert!(
            persistence.run_get(&envelope.result.new_run_id).unwrap()["rows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            runtime
                .repository
                .lookup_restore_receipt(
                    &request,
                    &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5))
                )
                .unwrap()
                .is_none()
        );
        let current = runtime
            .repository
            .checkpoint_context(
                &source,
                &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5)),
            )
            .unwrap();
        assert_eq!(current.head, original.head);
        assert_eq!(
            persistence.run_get(&source.source_run_id).unwrap(),
            old_run,
            "old usage and original run facts remain unchanged"
        );
        assert_eq!(
            persistence.approval_get("rollback-audit-approval").unwrap(),
            approval
        );
        assert_eq!(
            persistence
                .delivery_get(&old_session, "synthetic-delivery")
                .unwrap(),
            delivery
        );
        assert_eq!(
            persistence.message_list(&old_session, 0).unwrap(),
            old_messages
        );
        let cancelled = persistence.run_get(&active.run_id).unwrap();
        let status = cancelled["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|v| v == "status")
            .unwrap();
        assert_eq!(
            cancelled["rows"][0][status], "cancelled",
            "old source never revived"
        );
        drop(attempt);
        assert_eq!(persistence.pending_count_for_test(), 0);
    }
    assert!(
        service
            .restore_managed_checkpoint_and_admit(template)
            .await
            .is_ok(),
        "clean final restore after confirmed rollback"
    );
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn committed_publication_survives_expiry() {
    let (_root, state, source) =
        maintenance_source_timeout(std::time::Duration::from_secs(3)).await;
    let service = state.service();
    let request = restore_request(&state, &source).await;
    let persistence = state.persistence().unwrap();
    persistence.inject_drop_managed_commit_ack();
    assert_eq!(
        service
            .restore_managed_checkpoint_and_admit(request.clone())
            .await
            .unwrap_err()
            .to_string(),
        "managed_submitted_unknown"
    );
    let runtime = service.managed_runtime_for_test().unwrap();
    let durable = runtime
        .repository
        .restore_receipt(
            &request,
            &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5)),
        )
        .unwrap();
    let now = crate::domain::timestamp();
    tokio::time::sleep(std::time::Duration::from_millis(
        durable.new_run_deadline_at_ms.saturating_sub(now) + 30,
    ))
    .await;
    let restored = service
        .restore_managed_checkpoint_and_admit(request.clone())
        .await
        .unwrap();
    assert_eq!(restored.new_run_id, durable.new_run_id);
    assert_eq!(
        restored.new_run_deadline_at_ms,
        durable.new_run_deadline_at_ms
    );
    let handle = service
        .handle(&restored.new_run_id)
        .expect("committed handle must be installed after original deadline");
    assert!(handle.cancel.deadline_passed());
    assert!(service.run_context(&restored.new_run_id).is_some());
    service
        .clone()
        .run_worker(restored.new_run_id.clone(), String::new())
        .await;
    assert!(handle.terminal.load(std::sync::atomic::Ordering::Acquire));
    let effects = persistence
        .managed_effect_list(&crate::effects::ManagedEffectListRequest {
            workspace_id: source.workspace_id.clone(),
            after_effect_id: None,
            limit: 128,
        })
        .unwrap();
    assert!(
        !effects
            .entries
            .iter()
            .any(|effect| effect.run_id == restored.new_run_id),
        "expired restored run starts no effect"
    );
    assert_eq!(
        service
            .restore_managed_checkpoint_and_admit(request)
            .await
            .unwrap()
            .new_run_id,
        restored.new_run_id
    );
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn unknown_reconciliation_reuses_pending_capacity() {
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let request = restore_request(&state, &source).await;
    let persistence = state.persistence().unwrap();
    persistence.inject_drop_managed_commit_ack();
    assert_eq!(
        service
            .restore_managed_checkpoint_and_admit(request.clone())
            .await
            .unwrap_err()
            .to_string(),
        "managed_submitted_unknown"
    );
    assert_eq!(
        persistence.pending_count_for_test(),
        1,
        "settled worker leaves exactly the original slot charged"
    );
    let attempt = service
        .inner
        .maintenance_attempts
        .lock()
        .get(&request.request_id)
        .unwrap()
        .clone();
    let full = persistence.fill_pending_for_test();
    assert_eq!(persistence.pending_count_for_test(), 32);
    let cancel = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    let payload = json!({"workspace_id":request.workspace_id,"receipt_id":request.request_id,"cut":"restore"});
    assert!(
        persistence
            .managed_effect_command_with_cancellation(
                "effect.maintenance_receipt",
                &payload,
                &cancel
            )
            .is_err(),
        "ordinary reads cannot get a 33rd pending slot"
    );
    let claim = &attempt.claim;
    assert!(
        persistence
            .maintenance_read(
                claim,
                &claim.identity,
                "wrong proof",
                "effect.maintenance_receipt",
                &payload,
                &cancel
            )
            .is_err()
    );
    let mut identity = claim.identity.clone();
    identity.branch_id.push_str("-wrong");
    assert!(
        persistence
            .maintenance_read(
                claim,
                &identity,
                &claim.proof,
                "effect.maintenance_receipt",
                &payload,
                &cancel
            )
            .is_err()
    );
    assert!(
        persistence
            .maintenance_read(
                claim,
                &claim.identity,
                &claim.proof,
                "admission.create",
                &payload,
                &cancel
            )
            .is_err(),
        "borrow never admits"
    );
    let (_other_root, other) = fixture();
    assert!(
        other
            .persistence()
            .unwrap()
            .maintenance_read(
                claim,
                &claim.identity,
                &claim.proof,
                "effect.maintenance_receipt",
                &payload,
                &cancel
            )
            .is_err(),
        "persistence instance cannot be replaced"
    );
    other.service().shutdown().await.unwrap();
    let restored = service
        .restore_managed_checkpoint_and_admit(request)
        .await
        .unwrap();
    assert!(service.handle(&restored.new_run_id).is_some());
    assert_eq!(
        persistence.pending_count_for_test(),
        32,
        "borrowed reads did not add capacity"
    );
    drop(attempt);
    assert_eq!(persistence.pending_count_for_test(), 31);
    drop(full);
    assert_eq!(persistence.pending_count_for_test(), 0);
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_unknown_replays_same_frozen_root() {
    let (_root, state, request) =
        maintenance_source_timeout(std::time::Duration::from_secs(3)).await;
    let service = state.service();
    let persistence = state.persistence().unwrap();
    persistence.inject_drop_managed_commit_ack();
    let unknown = service.create_managed_checkpoint(request.clone()).await;
    assert!(
        !persistence.managed_commit_ack_drop_armed(),
        "real COMMIT reply was discarded"
    );
    assert_eq!(
        unknown.unwrap_err().to_string(),
        "managed_submitted_unknown"
    );
    assert_eq!(persistence.pending_count_for_test(), 1);
    assert!(
        service
            .managed_provider_enter(&request.source_run_id)
            .is_err(),
        "same branch remains frozen"
    );
    assert!(
        service
            .admit_external_with_workspace_selector(
                AdmitRunRequest {
                    input: json!({"message":"must not enter frozen checkpoint branch"}),
                    ..Default::default()
                },
                None
            )
            .await
            .is_err()
    );
    let runtime = service.managed_runtime_for_test().unwrap();
    let cancellation = crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5));
    let context = runtime
        .repository
        .checkpoint_context(&request, &cancellation)
        .unwrap();
    let commands = Arc::new(std::sync::Mutex::new(Vec::new()));
    let trace = commands.clone();
    *persistence.managed_request_hook.lock().unwrap() = Some(Arc::new(move |op, _, enqueued| {
        if enqueued {
            trace.lock().unwrap().push(op.to_owned());
        }
    }));
    let receipt = service
        .create_managed_checkpoint(request.clone())
        .await
        .unwrap();
    assert!(receipt.replayed);
    assert_eq!(
        receipt.checkpoint.frozen_root.object_id,
        context.head.head_object_id
    );
    let retry = service
        .create_managed_checkpoint(request.clone())
        .await
        .unwrap();
    assert_eq!(receipt.checkpoint, retry.checkpoint);
    assert!(
        !commands
            .lock()
            .unwrap()
            .iter()
            .any(|op| op == "effect.checkpoint_context" || op == "effect.checkpoint_create"),
        "exact replay never recaptures a live head or resubmits a write"
    );
    *persistence.managed_request_hook.lock().unwrap() = None;
    let mut conflict = request;
    conflict.expected_epoch += 1;
    assert_eq!(
        service
            .create_managed_checkpoint(conflict)
            .await
            .unwrap_err()
            .to_string(),
        "managed_request_conflict"
    );
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_waits_for_whole_tool_batch() {
    let (_root, state) = fixture_config(|config| {
        config.bearer_token = Some("synthetic-maintenance-fixture".into());
        config
            .managed_workspace
            .as_mut()
            .unwrap()
            .maintenance_policy
            .create_checkpoint = true;
    });
    let service = state.service();
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(json!({"text":"", "tool_calls":[
        {"id":"batch-first", "name":"write_file", "arguments":{"path":"first.txt","content":"one"}},
        {"id":"batch-second", "name":"write_file", "arguments":{"path":"second.txt","content":"two"}}
    ],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"tool_calls"}));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"close the full synthetic two-call batch"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let gate = service
        .arm_managed_call_prepare_gate("batch-second")
        .unwrap();
    let worker_service = service.clone();
    let worker_id = run.run_id.clone();
    let worker =
        tokio::spawn(async move { worker_service.run_worker(worker_id, String::new()).await });
    gate.wait_arrived(1).unwrap();
    let first = state
        .persistence()
        .unwrap()
        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: crate::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: run.session_id,
                run_id: run.run_id.clone(),
            },
            call_id: "batch-first".into(),
        })
        .unwrap()
        .unwrap();
    assert!(first.outcome.is_some(), "first output is durably closed");
    let request = crate::effects::ManagedCheckpointCreateRequest {
        source_run_id: run.run_id,
        workspace_id: first.identity.workspace.workspace_id,
        source_branch_id: first.identity.workspace.branch_id,
        expected_epoch: first.identity.epoch,
        request_id: uuid::Uuid::new_v4().to_string(),
        mode: crate::effects::ManagedCheckpointMode::AtClosedBatch,
    };
    let maintenance_service = service.clone();
    let checkpoint =
        tokio::spawn(async move { maintenance_service.create_managed_checkpoint(request).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let prematurely_finished = checkpoint.is_finished();
    gate.release();
    worker.await.unwrap();
    let checkpoint = checkpoint.await.unwrap();
    service.shutdown().await.unwrap();
    assert!(
        !prematurely_finished,
        "checkpoint must wait for the already enumerated batch"
    );
    let checkpoint = checkpoint.expect("full original batch closes under its original tokens");
    let calls = checkpoint
        .checkpoint
        .history
        .closed_output_refs
        .iter()
        .map(|output| output.call_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        calls,
        std::collections::BTreeSet::from(["batch-first", "batch-second"])
    );
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn foreground_intent_persists_lineage_before_native_execution() {
    let (_root, state) = fixture();
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(Some(json!({
        "id": "process-intent",
        "name": "terminal",
        "arguments": {"argv": ["/bin/true"], "timeout_ms": 1000}
    }))));
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message": "synthetic process intent; no child execution"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    runtime.arm_fault(crate::effects::ManagedEffectFault::AfterIntent);
    service
        .clone()
        .run_worker(run.run_id.clone(), "ignored".into())
        .await;
    let persistence = state.persistence().unwrap();
    let record = persistence
        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: crate::effects::ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: run.session_id,
                run_id: run.run_id,
            },
            call_id: "process-intent".into(),
        })
        .unwrap()
        .expect("formal durable foreground intent");
    assert!(
        record.prepared.is_none(),
        "cut must precede Native execution"
    );
    let result = runtime
        .repository
        .command_with_cancellation(
            "effect.head",
            &json!({
                "workspace_id": record.identity.workspace.workspace_id,
                "branch_id": record.identity.workspace.branch_id
            }),
            &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5)),
        )
        .unwrap();
    let head: Value = serde_json::from_str(result["rows"][0][0].as_str().unwrap()).unwrap();
    drop(persistence);
    drop(runtime);
    service.shutdown().await.unwrap();
    assert_eq!(
        head["process_lineage_tainted"], true,
        "the same effect.begin transaction must retain foreground intent independently of process table or prepared result"
    );
}

#[cfg(feature = "workspace-io-fault")]
fn register_native_budget_intent(
    persistence: &crate::GatewayPersistence,
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
            binding
                .seal_call_policy(
                    "read_file",
                    crate::capabilities::CapabilityRisk::Read,
                    r#"{"path":"never-executed.txt"}"#,
                )
                .unwrap(),
            deadline_ms,
        )
        .unwrap();
    let record = call.record();
    let seq = (index % 128) * 2 + 1000;
    let output = json!({"event_id":uuid::Uuid::new_v4().to_string(),"event_type":"tool.requested","seq":seq,"payload_json":"{}","created_at_ms":crate::domain::timestamp()});
    let terminal = json!({"event_id":uuid::Uuid::new_v4().to_string(),"event_type":"tool.started","seq":seq+1,"payload_json":"{}","created_at_ms":crate::domain::timestamp()});
    let projections = json!({"normal":{"output":output,"terminal":terminal}});
    let request = json!({"effect_id":call.effect_id,"run_id":record.identity.owner.run_id,"call_id":record.identity.call_id,"workspace_id":record.identity.workspace.workspace_id,"branch_id":record.identity.workspace.branch_id,"record_json":serde_json::to_string(&record).unwrap(),"commit_id":call.receipt_id,"sealed_class":call.policy.class().as_str(),"projections_json":projections.to_string(),"max_events":max_events});
    if index == 0 {
        let replay_request = json!({"run_id":record.identity.owner.run_id,"after_seq":0,"max_events":128,"max_bytes":1048576});
        let before = persistence.event_replay(&replay_request).unwrap();
        for field in ["output", "terminal"] {
            for malformed in [
                Value::Null,
                json!("11"),
                json!(true),
                json!(1.5),
                json!(-1),
                json!(u64::MAX),
            ] {
                let mut draft = projections.clone();
                if malformed.is_null() {
                    draft["normal"][field]
                        .as_object_mut()
                        .unwrap()
                        .remove("created_at_ms");
                } else {
                    draft["normal"][field]["created_at_ms"] = malformed;
                }
                let mut invalid = request.clone();
                invalid["projections_json"] = json!(draft.to_string());
                let error = binding
                    .runtime
                    .repository
                    .command_with_cancellation("effect.begin", &invalid, &binding.cancel)
                    .unwrap_err();
                assert!(
                    error.contains("NOT NULL"),
                    "actual typed transaction must refuse invalid draft clock: {error}"
                );
                assert_eq!(persistence.event_replay(&replay_request).unwrap(), before);
                assert!(
                    persistence
                        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
                            owner: record.identity.owner.clone(),
                            call_id: record.identity.call_id.clone()
                        })
                        .unwrap()
                        .is_none()
                );
            }
        }
    }
    binding
        .runtime
        .repository
        .command_with_cancellation("effect.begin", &request, &binding.cancel)
        .unwrap();
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
                &persistence,
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
        &persistence,
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
    assert_eq!(service.run_events(&run.run_id), live);
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
    let begin = json!({"effect_id":call.effect_id,"run_id":run.run_id,"call_id":"staged","sealed_class":call.policy.class().as_str(),"record_json":serde_json::to_string(&call.record()).unwrap()});
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

#[cfg(feature = "workspace-io-fault")]
fn slow_deadline_reprepares(service: &Arc<crate::AgentService>) -> Arc<std::sync::Mutex<Vec<u64>>> {
    let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = attempts.clone();
    let weak = Arc::downgrade(service);
    service.inject_prompt_read_entered_observer(Arc::new(move || {
        let mut attempts = seen.lock().unwrap();
        attempts.push(super::super::timestamp());
        let round = attempts.len();
        drop(attempts);
        if round <= 4 {
            // Real preparation delay and relevant config drift, without another
            // admission, capacity permit, cancellation root or fabricated row.
            std::thread::sleep(std::time::Duration::from_millis(100));
            let service = weak.upgrade().unwrap();
            let mut limits = service.inner.run_limits.read().clone();
            limits.max_turns += 1;
            service.set_run_limits(limits).unwrap();
        }
    }));
    attempts
}

#[cfg(feature = "workspace-io-fault")]
fn assert_admission_deadline_payload(payload: &Value, context: &crate::RunContext) -> u64 {
    let saved: Value = serde_json::from_str(payload["input_json"].as_str().unwrap()).unwrap();
    let binding: Value =
        serde_json::from_str(payload["managed_binding_json"].as_str().unwrap()).unwrap();
    let record: Value = serde_json::from_str(binding["record_json"].as_str().unwrap()).unwrap();
    let deadline = context.metadata["deadline_at_ms"].as_u64().unwrap();
    assert_eq!(saved["run_context"]["metadata"]["deadline_at_ms"], deadline);
    assert_eq!(record["original_deadline_ms"], deadline);
    deadline
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn ordinary_managed_slow_reprepare_keeps_initial_context_and_binding_deadline() {
    let (_root, state) = fixture();
    let service = state.service();
    let persistence = state.persistence().unwrap();
    let payload = Arc::new(std::sync::Mutex::new(None));
    let seen = payload.clone();
    persistence
        .inject_admission_precommit_hook(move |value| *seen.lock().unwrap() = Some(value.clone()));
    let attempts = slow_deadline_reprepares(&service);
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"ordinary slow clock"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    *service.inner.prompt_read_entered.lock().unwrap() = None;
    let context = service.run_context(&run.run_id).unwrap();
    let deadline =
        assert_admission_deadline_payload(&payload.lock().unwrap().take().unwrap(), &context);
    let attempts = attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), 5, "four relevant drifts really reprepare");
    assert!(deadline <= attempts[0] + service.inner.config.run_timeout.as_millis() as u64);
    assert!(context.metadata["created_at_ms"].as_u64().unwrap() >= attempts[4]);
    let handle = service.handle(&run.run_id).unwrap();
    let remaining = handle.cancel.remaining_deadline().unwrap();
    assert!(remaining < service.inner.config.run_timeout - std::time::Duration::from_millis(400));
    println!(
        "ordinary initial deadline={deadline}; prompt attempts={attempts:?}; remaining={remaining:?}; context/persisted/binding exact"
    );
    drop(attempts);
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    service.clone().run_worker(run.run_id, String::new()).await;
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn restored_slow_reprepare_keeps_initial_context_binding_envelope_and_receipt_deadline() {
    let (_root, state, source) = maintenance_source().await;
    let service = state.service();
    let request = restore_request(&state, &source).await;
    let persistence = state.persistence().unwrap();
    let payload = Arc::new(std::sync::Mutex::new(None));
    let seen = payload.clone();
    persistence
        .inject_admission_precommit_hook(move |value| *seen.lock().unwrap() = Some(value.clone()));
    let attempts = slow_deadline_reprepares(&service);
    let result = service
        .restore_managed_checkpoint_and_admit(request.clone())
        .await
        .unwrap();
    *service.inner.prompt_read_entered.lock().unwrap() = None;
    let context = service.run_context(&result.new_run_id).unwrap();
    let payload = payload.lock().unwrap().take().unwrap();
    let deadline = assert_admission_deadline_payload(&payload, &context);
    assert_eq!(deadline, result.new_run_deadline_at_ms);
    let envelope: crate::effects::journal::ManagedRestoreExecutionEnvelope =
        serde_json::from_str(payload["restore_json"].as_str().unwrap()).unwrap();
    assert_eq!(envelope.result.new_run_deadline_at_ms, deadline);
    let attempts = attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), 5);
    assert!(deadline <= attempts[0] + service.inner.config.run_timeout.as_millis() as u64);
    let handle = service.handle(&result.new_run_id).unwrap();
    assert!(
        handle.cancel.remaining_deadline().unwrap()
            < service.inner.config.run_timeout - std::time::Duration::from_millis(400)
    );
    let stored = service
        .managed_runtime_for_test()
        .unwrap()
        .repository
        .lookup_restore_receipt(
            &request,
            &crate::RunCancellation::with_timeout(std::time::Duration::from_secs(5)),
        )
        .unwrap()
        .unwrap();
    assert_eq!(stored.new_run_deadline_at_ms, deadline);
    println!(
        "restored initial deadline={deadline}; prompt attempts={attempts:?}; context/persisted/binding/envelope/receipt exact"
    );
    drop(attempts);
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    service
        .clone()
        .run_worker(result.new_run_id, String::new())
        .await;
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn naturally_expired_frozen_handle_has_no_permit_or_managed_codepin_authority() {
    let (_root, state) =
        fixture_config(|config| config.run_timeout = std::time::Duration::from_secs(2));
    let service = state.service();
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"natural original-clock expiry"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let before = service.run_context(&run.run_id).unwrap().metadata;
    let original = service.handle(&run.run_id).unwrap();
    assert!(original.permit.lock().unwrap().is_some());
    assert!(original.pinned_tool.as_ref().unwrap().managed.is_some());
    let native_deadline = original.cancel.deadline_instant().unwrap();
    let workspace_id = original
        .pinned_tool
        .as_ref()
        .unwrap()
        .managed
        .as_ref()
        .unwrap()
        .admitted_branch
        .workspace_id
        .clone();
    tokio::time::sleep(
        original.cancel.remaining_deadline().unwrap() + std::time::Duration::from_millis(2),
    )
    .await;
    assert!(original.cancel.deadline_passed());
    assert!(super::super::timestamp() >= before["deadline_at_ms"].as_u64().unwrap());
    service.evict_run_handle(&run.run_id);
    drop(original);
    let rebuilt = service
        .restore_handle_from_frozen_context(&run.run_id)
        .unwrap()
        .unwrap();
    assert!(rebuilt.permit.lock().unwrap().is_none());
    assert!(rebuilt.workspace_authority.is_none());
    assert!(
        rebuilt.pinned_tool.is_none(),
        "expired reconstruction must prepare no executable pin or Native branch grant"
    );
    assert!(rebuilt.cancel.deadline_passed() || rebuilt.cancel.requested().is_some());
    let provider = Arc::new(crate::ScriptedProvider::new());
    service.inject_provider_host(provider.clone());
    let persistence = state.persistence().unwrap();
    let request = crate::effects::ManagedEffectListRequest {
        workspace_id,
        after_effect_id: None,
        limit: 100,
    };
    let effects = persistence.managed_effect_list(&request).unwrap();
    service
        .clone()
        .run_worker(run.run_id.clone(), String::new())
        .await;
    assert!(provider.requests().is_empty());
    assert_eq!(persistence.managed_effect_list(&request).unwrap(), effects);
    assert_eq!(service.run_context(&run.run_id).unwrap().metadata, before);
    assert!(
        service
            .run_events(&run.run_id)
            .iter()
            .any(|event| event["event"] == "run.cancelled")
    );
    println!(
        "natural Native deadline elapsed={:?}; frozen deadline={} unchanged; permit=None managed=None authority=None provider=0",
        native_deadline.elapsed(),
        before["deadline_at_ms"]
    );
    service.shutdown().await.unwrap();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn ordinary_unmanaged_slow_reprepare_exposes_original_deadline_through_typed_context() {
    let (_root, state) = fixture_config(|config| config.managed_workspace = None);
    let service = state.service();
    let persistence = state.persistence().unwrap();
    let payload = Arc::new(std::sync::Mutex::new(None));
    let seen = payload.clone();
    persistence
        .inject_admission_precommit_hook(move |value| *seen.lock().unwrap() = Some(value.clone()));
    let attempts = slow_deadline_reprepares(&service);
    let run = service
        .admit(AdmitRunRequest {
            input: json!({"message":"ordinary unmanaged slow clock"}),
            ..Default::default()
        })
        .await
        .unwrap();
    *service.inner.prompt_read_entered.lock().unwrap() = None;
    let context = service.run_context(&run.run_id).unwrap();
    let deadline = context.metadata["deadline_at_ms"].as_u64().unwrap();
    let payload = payload.lock().unwrap().take().unwrap();
    let saved: Value = serde_json::from_str(payload["input_json"].as_str().unwrap()).unwrap();
    assert_eq!(saved["run_context"]["metadata"]["deadline_at_ms"], deadline);
    assert!(
        payload.get("restore_json").is_none(),
        "ordinary admission has no restore receipt"
    );
    let attempts = attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), 5);
    assert!(deadline <= attempts[0] + service.inner.config.run_timeout.as_millis() as u64);
    assert!(
        service
            .handle(&run.run_id)
            .unwrap()
            .cancel
            .remaining_deadline()
            .unwrap()
            < service.inner.config.run_timeout - std::time::Duration::from_millis(400)
    );
    println!(
        "ordinary unmanaged initial deadline={deadline}; attempts={attempts:?}; typed context/persisted exact; no restore receipt"
    );
    drop(attempts);
    let provider = Arc::new(crate::ScriptedProvider::new());
    provider.push_ok(response(None));
    service.inject_provider_host(provider);
    service.clone().run_worker(run.run_id, String::new()).await;
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn t14_nonmanaged_persistent_unknown_keeps_original_storage_error() {
    let (_root, state) = fixture_config(|config| {
        config.managed_workspace = None;
        config.max_concurrent_runs = 2;
    });
    let service = state.service();
    let persistence = state.persistence().unwrap();
    assert!(service.inner.managed_effects.read().is_none());
    persistence.inject_admission_ack_loss();
    let committed = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let committed_hook = committed.clone();
    let replay = persistence.clone();
    persistence.inject_admission_postcommit_hook(move |payload| {
        if let Some(id) = payload.get("run_id").and_then(|value| value.as_str()) {
            *committed_hook.lock().expect("run id") = id.to_string();
        }
        replay.arm_admission_replay_read_failures(1);
    });
    let request = AdmitRunRequest {
        input: json!({"message":"plain persistent admission"}),
        idempotency_key: Some("b3-plain-unknown".into()),
        idempotency_hash: Some("fnv64:0000000000000b03".into()),
        graph_id: None,
        workspace_branch: None,
        platform: "b3-plain".into(),
        ..Default::default()
    };
    let admitted = service
        .admit_external_with_workspace_selector(request.clone(), None)
        .await;
    let caller = match &admitted {
        Ok(_) => "published".to_string(),
        Err(crate::AdmitError::Persistence(code)) => code.clone(),
        Err(other) => format!("{other:?}"),
    };
    let run_id = committed.lock().expect("run id").clone();
    let rows = if run_id.is_empty() {
        0
    } else {
        persistence.run_get(&run_id).expect("committed read")["rows"]
            .as_array()
            .expect("rows")
            .len()
    };
    println!(
        "B3_NONMANAGED_OWNER {}",
        json!({"caller":caller,"rows":rows,"permits":service.available_admission_permits(),"handle":!run_id.is_empty() && service.handle(&run_id).is_some()})
    );
    assert!(
        caller.contains("storage_unavailable"),
        "non-managed unknown must keep the original storage error, got {caller}"
    );
    assert!(
        !caller.contains("unpublished_original_admission"),
        "must not install the unresolved classification: {caller}"
    );
    assert_eq!(
        rows, 1,
        "real ack loss already committed the original durable row"
    );
    assert!(service.handle(&run_id).is_none(), "no memory publication");
    assert_eq!(
        service.available_admission_permits(),
        2,
        "this attempt must not leak its permit"
    );
    persistence.arm_admission_replay_read_failures(0);
    let retry = service
        .admit_external_with_workspace_selector(request, None)
        .await;
    assert!(
        retry.is_err(),
        "recovered readback must stay closed, not 202: {retry:?}"
    );
    assert!(
        service.handle(&run_id).is_none(),
        "retry must not publish a handle"
    );
    assert_eq!(
        persistence.run_get(&run_id).expect("row remains")["rows"]
            .as_array()
            .expect("rows")
            .len(),
        1,
        "retry must not erase the committed row"
    );
    assert_eq!(service.available_admission_permits(), 2);
    service
        .shutdown()
        .await
        .expect("no impossible owner remains");
}
