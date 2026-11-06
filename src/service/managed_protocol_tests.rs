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
    validate(&actual, code, &[]).unwrap();
    assert!(actual.manifest.state.is_none());
    assert!(!actual.manifest.effects.entries.is_empty());
    let mut declared = actual.clone();
    let files = crate::runtime::native_tools::embedding_package_files().unwrap();
    let manifest = String::from_utf8(files["manifest.yaml"].clone()).unwrap();
    declared.manifest = crate::plugins::parse_plugin_manifest(
        &(manifest + "\nstate:\n  scope: run\n  schema: 1\n"),
    )
    .unwrap();
    validate(&declared, code, &[]).expect("declared run state is now versioned inventory");
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
        validate(&state_effect, code, &[]).unwrap_err(),
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
            false,
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

// ---------------------------------------------------------------------------
// T07: one stateless caller → Native → callee read transaction.
//
// These cases install two real AcceptedPublisher tool packages, pin the active
// two-package graph through the real admission path, seal the durable parent
// tool call, and then execute the captured caller program through the same
// `agent_runtime::invoke_pinned_tool` boundary a run uses. The caller performs
// its declared direct read and the callee performs its declared delegated read
// in that single parent transaction.
// ---------------------------------------------------------------------------
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const T07_CALLER_ID: &str = "org.rustscript.tools.t07caller";
const T07_CALLEE_ID: &str = "org.rustscript.tools.t07callee";
const T07_ARGUMENTS: &str = r#"{"path":"note.txt"}"#;

fn t07_key() -> (Ed25519KeyPair, crate::plugins::InstallAuthorization) {
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let auth = crate::plugins::InstallAuthorization {
        admin: true,
        accepted_publishers: vec![crate::plugins::PublisherKey {
            publisher: "org.rustscript".into(),
            verifying_key: pair.public_key().as_ref().to_vec(),
        }],
        unsigned_dev_space: None,
    };
    (pair, auth)
}

/// The caller catalog must echo the admitted host descriptor for `read_file`
/// exactly: `seal_call_policy` refuses a captured descriptor that differs from
/// the run's frozen registry snapshot. The callee catalog is its own captured
/// single descriptor (no admitted seal exists for it).
fn t07_catalog_source(tool: &str, schema: &str) -> String {
    format!(
        r#"pub fn managed_authority_catalog(context: map) -> map {{
    {{
        declarations: [{{ tool_name: "{tool}", operation: "workspace_read" }}],
        descriptors: [{{
            name: "{tool}",
            description: "Read bounded text from a workspace file",
            toolset: "coding",
            risk_class: "read",
            schema: {schema}
        }}]
    }}
}}
"#
    )
}

const T07_HOST_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"},offset:{type:"integer",minimum:1},limit:{type:"integer",minimum:1}},required:["path"],additionalProperties:false}"#;
const T07_CALLEE_SCHEMA: &str = r#"{type:"object",properties:{path:{type:"string"}},required:["path"],additionalProperties:false}"#;

fn t07_callee_manifest() -> String {
    format!(
        "format: rustscript.plugin/v1\nid: {T07_CALLEE_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies: []\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated: []\n"
    )
}

fn t07_caller_manifest() -> String {
    format!(
        "format: rustscript.plugin/v1\nid: {T07_CALLER_ID}\nversion: 1.0.0\nkind: tool\nruntime: \">=0.1.0, <0.2.0\"\ncontract: agent.tool/v1\nhost_abi: agent.cap/v1\nentry:\n  path: run.rss\n  export: run\ndependencies:\n  - alias: child\n    id: {T07_CALLEE_ID}\n    version: 1.0.0\ncapabilities:\n  - workspace.read\neffects:\n  contract: agent.effects/v1\n  entries:\n    run:\n      direct:\n        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated:\n        - dependency: child\n          entry: run\n          allow:\n            - kind: workspace.fs.read\n              scope: bound_workspace\n              recovery: none\n"
    )
}

const T07_HELPERS: &str = r#"
fn t07_string(value: map, key: string, fallback: string) -> string {
    let mut result: string = fallback;
    if value.has(key) {
        if type(value[key]) == "string" {
            let coerced: string = value[key];
            result = coerced;
        }
    }
    result
}
fn t07_map(value: map, key: string) -> map {
    let mut result: map = {};
    if value.has(key) {
        if type(value[key]) == "map" {
            let coerced: map = value[key];
            result = coerced;
        }
    }
    result
}
fn t07_int(value: map, key: string, fallback: int) -> int {
    let mut result: int = fallback;
    if value.has(key) {
        if type(value[key]) == "int" {
            let coerced: int = value[key];
            result = coerced;
        }
    }
    result
}
fn t07_bool(value: map, key: string, fallback: bool) -> bool {
    let mut result: bool = fallback;
    if value.has(key) {
        if type(value[key]) == "bool" {
            let coerced: bool = value[key];
            result = coerced;
        }
    }
    result
}
"#;

/// The captured caller: one declared direct read plus one delegated read.
fn t07_caller_source(second_call: bool) -> String {
    let second = if second_call {
        r#"        let again: map = agent_runtime::invoke_pinned_plugin_child({ canonical_arguments: canonical });
        second_code = t07_string(again, "code", "ok");
"#
    } else {
        ""
    };
    format!(
        r#"{T07_HELPERS}
pub fn run(context: map) -> map {{
    let prepare: map = t07_map(context, "prepare");
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if t07_bool(prepared, "ok", false) == false => {{
        prepared
    }} else => {{
        let token: string = t07_string(prepared, "execution_token", "");
        let arguments: map = t07_map(context, "arguments");
        let path: string = t07_string(arguments, "path", "");
        let meta: map = cap::fs_metadata(token, path);
        if t07_bool(meta, "ok", false) == false => {{
            meta
        }} else => {{
            let caller_len: int = t07_int(meta, "len", 0);
            let canonical: string = json::encode(arguments);
            let mut second_code: string = "ok";
            let child: map = agent_runtime::invoke_pinned_plugin_child({{ canonical_arguments: canonical }});
{second}            if t07_bool(child, "ok", false) == false => {{
                let failed: map = {{ ok: false, content: "", data: {{ second: second_code }}, error: {{ code: t07_string(child, "code", "child_failed"), message: t07_string(child, "message", "child failed") }}, truncated: false, artifacts: [] }};
                let _ignored: map = agent_runtime::tool_commit(token, failed);
                failed
            }} else => {{
                let result: map = {{ ok: true, content: "caller:" + t07_int(meta, "len", 0) + ":" + t07_string(child, "canonical_result", ""), data: {{ caller_len: caller_len, second: second_code }}, error: null, truncated: false, artifacts: [] }};
                agent_runtime::tool_commit(token, result)
            }}
        }}
    }}
}}
"#
    )
}

/// A caller that delegates even when its own direct read fails, so a large
/// (and therefore detail-backed) parent identity can reach the delegation.
fn t07_caller_source_without_read_success() -> String {
    format!(
        r#"{T07_HELPERS}
pub fn run(context: map) -> map {{
    let prepare: map = t07_map(context, "prepare");
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if t07_bool(prepared, "ok", false) == false => {{
        prepared
    }} else => {{
        let token: string = t07_string(prepared, "execution_token", "");
        let arguments: map = t07_map(context, "arguments");
        let canonical: string = json::encode(arguments);
        let child: map = agent_runtime::invoke_pinned_plugin_child({{ canonical_arguments: canonical }});
        if t07_bool(child, "ok", false) == false => {{
            let failed: map = {{ ok: false, content: "", data: {{}}, error: {{ code: t07_string(child, "code", "child_failed"), message: t07_string(child, "message", "child failed") }}, truncated: false, artifacts: [] }};
            agent_runtime::tool_commit(token, failed)
        }} else => {{
            let result: map = {{ ok: true, content: t07_string(child, "canonical_result", ""), data: {{}}, error: null, truncated: false, artifacts: [] }};
            agent_runtime::tool_commit(token, result)
        }}
    }}
}}
"#
    )
}

/// A caller that never invokes the delegated child.
fn t07_caller_source_without_child() -> String {
    format!(
        r#"{T07_HELPERS}
pub fn run(context: map) -> map {{
    let prepare: map = t07_map(context, "prepare");
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if t07_bool(prepared, "ok", false) == false => {{
        prepared
    }} else => {{
        let token: string = t07_string(prepared, "execution_token", "");
        let arguments: map = t07_map(context, "arguments");
        let path: string = t07_string(arguments, "path", "");
        let meta: map = cap::fs_metadata(token, path);
        if t07_bool(meta, "ok", false) == false => {{
            meta
        }} else => {{
            let result: map = {{ ok: true, content: "caller-only", data: {{}}, error: null, truncated: false, artifacts: [] }};
            agent_runtime::tool_commit(token, result)
        }}
    }}
}}
"#
    )
}

/// A caller whose delegated request intentionally does not equal the original
/// parent argument object.
fn t07_caller_source_projection_mismatch() -> String {
    format!(
        r#"{T07_HELPERS}
pub fn run(context: map) -> map {{
    let prepare: map = t07_map(context, "prepare");
    let prepared: map = agent_runtime::tool_prepare(prepare);
    if t07_bool(prepared, "ok", false) == false => {{
        prepared
    }} else => {{
        let token: string = t07_string(prepared, "execution_token", "");
        let child: map = agent_runtime::invoke_pinned_plugin_child({{ canonical_arguments: "{{\"path\":\"other.txt\"}}" }});
        let result: map = {{ ok: false, content: "", data: {{ child_code: t07_string(child, "code", "") }}, error: {{ code: t07_string(child, "code", "child_failed"), message: t07_string(child, "message", "") }}, truncated: false, artifacts: [] }};
        agent_runtime::tool_commit(token, result)
    }}
}}
"#
    )
}

/// The captured callee: metadata plus range read through the empty sentinel.
fn t07_callee_source(token_sentinel: &str) -> String {
    format!(
        r#"{T07_HELPERS}
pub fn run(context: map) -> map {{
    let arguments: map = t07_map(context, "arguments");
    let path: string = t07_string(arguments, "path", "");
    let meta: map = cap::fs_metadata("{token_sentinel}", path);
    if t07_bool(meta, "ok", false) == false => {{
        meta
    }} else => {{
        let len: int = t07_int(meta, "len", 0);
        let read: map = cap::fs_read_range("{token_sentinel}", path, 0, len);
        if t07_bool(read, "ok", false) == false => {{
            read
        }} else => {{
            let text: string = bytes::to_utf8(read.bytes);
            {{ ok: true, content: text, data: {{ callee: true }}, error: null, truncated: false, artifacts: [] }}
        }}
    }}
}}
"#
    )
}

/// A callee that returns its read text twice, so the canonical child result
/// exceeds a budget the read itself still fits.
fn t07_callee_source_doubled() -> String {
    format!(
        r#"{T07_HELPERS}
pub fn run(context: map) -> map {{
    let arguments: map = t07_map(context, "arguments");
    let path: string = t07_string(arguments, "path", "");
    let meta: map = cap::fs_metadata("", path);
    if t07_bool(meta, "ok", false) == false => {{
        meta
    }} else => {{
        let len: int = t07_int(meta, "len", 0);
        let read: map = cap::fs_read_range("", path, 0, len);
        if t07_bool(read, "ok", false) == false => {{
            read
        }} else => {{
            let text: string = bytes::to_utf8(read.bytes);
            {{ ok: true, content: text + text, data: {{ callee: true }}, error: null, truncated: false, artifacts: [] }}
        }}
    }}
}}
"#
    )
}

fn t07_write_package(
    store: &crate::plugins::PackageStore,
    key: &Ed25519KeyPair,
    dir: &std::path::Path,
    manifest: &str,
    run: &str,
    catalog: &str,
) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("manifest.yaml"), manifest).unwrap();
    std::fs::write(dir.join("run.rss"), run).unwrap();
    std::fs::write(dir.join("catalog.rss"), catalog).unwrap();
    let signature = key.sign(&store.signature_payload(dir).unwrap());
    std::fs::write(dir.join("signature.ed25519"), signature.as_ref()).unwrap();
}

/// Installs the two captured packages, activates the graph and admits a run
/// that pins it. Returns the live service state pieces the probe needs.
struct T07Case {
    root: PathBuf,
    state: AgentGatewayState,
    auth: crate::plugins::InstallAuthorization,
    run_id: String,
    registry_identity: String,
    tool_name: String,
    pinned: Arc<crate::effects::broker::ManagedRunBinding>,
}

async fn t07_open(
    caller_source: &str,
    callee_source: &str,
    bind: impl FnOnce(&mut AgentGatewayConfig),
) -> T07Case {
    t07_open_case(
        caller_source,
        callee_source,
        bind,
        T07_ARGUMENTS,
        |workspace| {
            std::fs::write(workspace.join("note.txt"), b"t07-child-content").unwrap();
        },
    )
    .await
}

/// Same fixture with an explicit parent argument object and workspace seed, so
/// a case can control the confined file and the argument identity.
async fn t07_open_case(
    caller_source: &str,
    callee_source: &str,
    bind: impl FnOnce(&mut AgentGatewayConfig),
    arguments: &str,
    seed: impl FnOnce(&std::path::Path),
) -> T07Case {
    let (root, state) = fixture_config(bind);
    let database = root.join("gateway.sqlite");
    let source_root = root.join("sources");
    std::fs::create_dir_all(&source_root).unwrap();
    let (key, auth) = t07_key();
    let store =
        crate::plugins::PackageStore::open(crate::plugins::trusted_tool_package_root(&database))
            .unwrap();
    t07_write_package(
        &store,
        &key,
        &source_root.join("callee"),
        &t07_callee_manifest(),
        callee_source,
        &t07_catalog_source("read_file", T07_CALLEE_SCHEMA),
    );
    t07_write_package(
        &store,
        &key,
        &source_root.join("caller"),
        &t07_caller_manifest(),
        caller_source,
        &t07_catalog_source("read_file", T07_HOST_SCHEMA),
    );
    let state = state
        .with_plugin_control(auth.clone(), source_root.clone(), "t07-space")
        .unwrap();
    let service = state.service();
    for package in ["callee", "caller"] {
        service
            .install_controlled_plugin(&json!({
                "package": package,
                "deployment_space": "t07-space",
            }))
            .unwrap_or_else(|error| panic!("install {package}: {error}"));
    }
    // Resolve and activate the installed two-package graph through the formal
    // captured-lock path the host uses.
    let store =
        crate::plugins::PackageStore::open(crate::plugins::trusted_tool_package_root(&database))
            .unwrap();
    store.bind_policy(&auth);
    let lock = store
        .resolve(&crate::plugins::ResolveRequest {
            harness_selection: crate::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: T07_CALLER_ID.into(),
            },
            roots: vec![crate::plugins::PackageRequirement {
                id: T07_CALLER_ID.into(),
                version: "1.0.0".into(),
            }],
            host_runtime: crate::plugins::HOST_RUNTIME.into(),
        })
        .unwrap();
    store.prepare(&lock).unwrap();
    seed(&root.join("workspace"));
    let persistence = state.persistence().unwrap();
    let control = crate::plugins::PluginControlStore::new(&persistence);
    control.store_lock(&lock).unwrap();
    let refs = lock
        .packages
        .iter()
        .map(|package| crate::plugins::PackageArtifactRef {
            package_id: package.id.clone(),
            version: package.version.clone(),
            kind: package.kind.clone(),
            artifact_id: package.artifact_id.clone(),
        })
        .collect::<Vec<_>>();
    control.activate(&lock.graph_id, 0, &refs).unwrap();
    let run = service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"t07 stateless delegation"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let handle = service.handle(&run.run_id).unwrap();
    let pinned = handle
        .pinned_tool
        .as_ref()
        .and_then(|program| program.managed.clone())
        .expect("the admitted two-package graph must seal a managed binding");
    // The durable parent tool call, exactly as the agent loop holds it for the
    // tool phase: one assistant message on this run carrying the tool_call
    // block the retained entry re-validates against.
    {
        let mut store = service.inner.store.write();
        let session = store
            .sessions
            .get_mut(&run.session_id)
            .expect("the admitted session must stay live");
        session
            .messages
            .push(crate::gateway::store::SessionMessage {
                id: "t07-assistant".into(),
                session_id: run.session_id.clone(),
                role: "assistant".into(),
                content: json!([{
                    "type": "tool_call",
                    "tool_call_id": "t07-call",
                    "name": "read_file",
                    "arguments_json": arguments,
                }]),
                created_at: crate::domain::timestamp(),
                run_id: Some(run.run_id.clone()),
                finish_reason: Some("tool_calls".into()),
                name: None,
                tool_call_id: None,
                parent_message_id: None,
                token_estimate: Some(1),
                metadata: json!({}),
                ordinal: Some(session.messages.len() as i64 + 1),
            });
    }
    T07Case {
        root,
        state,
        auth,
        run_id: run.run_id,
        registry_identity: pinned.code.registry_identity.clone(),
        tool_name: "read_file".into(),
        pinned,
    }
}

impl T07Case {
    fn probe(&self, call_id: &str, canonical: &str) -> Value {
        let service = self.state.service();
        let mut host = service
            .capability_host_bridges(&self.run_id)
            .unwrap()
            .unwrap();
        host.pinned_tool = service.handle(&self.run_id).unwrap().pinned_tool.clone();
        let source = r#"fn t07_field(context: map, key: string) -> string {
    let mut result: string = "";
    if context.has(key) {
        if type(context[key]) == "string" {
            let coerced: string = context[key];
            result = coerced;
        }
    }
    result
}
pub fn run(context: map) -> map {
    agent_runtime::invoke_pinned_tool({
        tool_name: t07_field(context, "tool_name"),
        call_id: t07_field(context, "call_id"),
        canonical_arguments: t07_field(context, "canonical_arguments"),
        canonical_input: "",
        run_id: t07_field(context, "run_id"),
        registry_identity: t07_field(context, "registry"),
        argument_digest: t07_field(context, "canonical_arguments"),
        risk_class: "read",
        summary: "t07",
        untrusted_graph_id: ""
    })
}
"#
        .to_string();
        let input = rustscript_vm::Value::map(vec![
            (
                rustscript_vm::Value::string("tool_name"),
                rustscript_vm::Value::string(self.tool_name.as_str()),
            ),
            (
                rustscript_vm::Value::string("call_id"),
                rustscript_vm::Value::string(call_id),
            ),
            (
                rustscript_vm::Value::string("canonical_arguments"),
                rustscript_vm::Value::string(canonical),
            ),
            (
                rustscript_vm::Value::string("run_id"),
                rustscript_vm::Value::string(self.run_id.as_str()),
            ),
            (
                rustscript_vm::Value::string("registry"),
                rustscript_vm::Value::string(self.registry_identity.as_str()),
            ),
        ]);
        let runner = crate::AgentRunner::from_source(&source, crate::AgentConfig::default())
            .expect("the t07 probe must compile against the sealed boundary")
            .with_host(host);
        native_json(&runner.run_with_context(input).unwrap())
    }
    /// The current sealed pin, exactly as the runner holds it.
    fn pin(&self) -> crate::runtime::agent_host::PinnedToolProgram {
        self.state
            .service()
            .handle(&self.run_id)
            .expect("the admitted run must stay live")
            .pinned_tool
            .clone()
            .expect("the admitted run must carry the sealed pin")
    }
    fn effect(&self) -> Option<crate::effects::ManagedEffectRecord> {
        self.state
            .persistence()
            .unwrap()
            .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
                owner: self.pinned.owner.clone(),
                call_id: "t07-call".into(),
            })
            .unwrap()
    }
    fn close(self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn t07_complete(
    record: &crate::effects::ManagedEffectRecord,
) -> (
    &crate::effects::journal::ManagedDelegationIntent,
    &crate::effects::ManagedObjectRef,
) {
    match record
        .delegation
        .as_ref()
        .expect("delegation proof missing")
    {
        crate::effects::journal::ManagedDelegationRecord::Complete {
            proof,
            child_result,
        } => (proof, child_result),
        other => panic!("expected a Complete delegation, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn t07_stateless_caller_callee_completes_one_parent_read_transaction() {
    let case = t07_open(&t07_caller_source(false), &t07_callee_source(""), |_| {}).await;
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], true, "{output}");
    assert_eq!(
        output["managed_publication"]["status"], "read_only",
        "{output}"
    );
    assert!(
        output["managed_publication"]["effect_id"]
            .as_str()
            .is_some(),
        "{output}"
    );
    let pinned_program = case
        .state
        .service()
        .handle(&case.run_id)
        .unwrap()
        .pinned_tool
        .clone()
        .unwrap();
    assert!(
        pinned_program.child_template().is_some(),
        "the admitted pin must carry the captured child template"
    );
    let record = case
        .effect()
        .expect("the single parent effect row must exist");
    assert!(!record.effect_id.is_empty());
    let (proof, child_result) = t07_complete(&record);
    assert_eq!(proof.parent_call_id, "t07-call");
    assert_eq!(proof.parent_effect_id, record.effect_id);
    assert_eq!(proof.callee_code.package_id, T07_CALLEE_ID);
    assert_eq!(proof.callee_tool, "read_file");
    assert_eq!(proof.edge_alias, "child");
    assert_eq!(proof.effect.kind, "workspace.fs.read");
    assert_eq!(proof.child_arguments, record.identity.argument_identity);
    assert_eq!(
        child_result.object_kind,
        crate::effects::ManagedObjectKind::CanonicalResult
    );
    assert_eq!(child_result.store_id, record.identity.workspace.store_id);
    // The child read really happened in the parent's confined view.
    let runtime = case.state.service().managed_runtime_for_test().unwrap();
    let child_view = runtime.read_result(child_result).unwrap();
    assert_eq!(child_view["ok"], true, "{child_view}");
    assert_eq!(child_view["content"], "t07-child-content", "{child_view}");
    assert_eq!(child_view["data"]["callee"], true, "{child_view}");
    let prepared = record
        .prepared
        .as_ref()
        .expect("the parent prepared record must exist");
    assert_eq!(
        prepared.operation_class,
        crate::effects::ManagedOperationClass::ReadOnly
    );
    assert!(
        record.outcome.is_some(),
        "the parent must own a final outcome"
    );
    assert_eq!(
        record.state,
        crate::effects::ManagedPublicationStatus::ReadOnly
    );
    // One shared aggregate meter for caller and child representations.
    let call = case
        .pinned
        .call("t07-call")
        .expect("the parent call must stay retained");
    let limit = call.meter().limit();
    let remaining = call.meter().remaining();
    assert!(limit > 0);
    assert!(
        remaining < limit,
        "the aggregate meter must charge the delegation"
    );
    assert!(call.original().contains("note.txt"));
    case.close();
}

#[tokio::test(flavor = "multi_thread")]
async fn t07_replay_returns_the_stored_outer_result_without_a_second_transaction() {
    let case = t07_open(&t07_caller_source(false), &t07_callee_source(""), |_| {}).await;
    let first = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(first["kind"], "", "{first}");
    let before = case.effect().expect("the effect row must exist");
    let replayed = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(replayed["ok"], true, "{replayed}");
    assert_eq!(replayed["kind"], "replay", "{replayed}");
    let after = case.effect().expect("the effect row must exist");
    assert_eq!(before, after, "replay must not write a new transaction");
    let (_, first_child) = t07_complete(&before);
    let (_, replayed_child) = t07_complete(&after);
    assert_eq!(first_child.object_id, replayed_child.object_id);
    case.close();
}

#[tokio::test(flavor = "multi_thread")]
async fn t07_second_bridge_call_is_refused_and_runs_no_second_child() {
    let case = t07_open(&t07_caller_source(true), &t07_callee_source(""), |_| {}).await;
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], true, "{output}");
    let record = case.effect().expect("the effect row must exist");
    let (_, child_result) = t07_complete(&record);
    assert_eq!(
        child_result.object_kind,
        crate::effects::ManagedObjectKind::CanonicalResult
    );
    let committed = record.outcome.as_ref().unwrap();
    let result = case
        .state
        .service()
        .managed_runtime_for_test()
        .unwrap()
        .read_result(&committed.canonical_result_ref)
        .unwrap();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(
        result["data"]["second"], "pinned_child_already_claimed",
        "{result}"
    );
    // The losing second contender for the same captured call never reaches the
    // callee: one real child VM entry and one child Native read set only.
    let call = case
        .pinned
        .call("t07-call")
        .expect("the parent call must stay retained");
    assert_eq!(
        call.child_invocations(),
        1,
        "the refused second bridge call may not run a second child VM"
    );
    assert_eq!(
        call.native_reads(),
        3,
        "the caller read plus one child metadata/range pair only"
    );
    // Exactly one durable intent, and it is the proof re-derived from the
    // current pin: the loser wrote nothing.
    let proof = case
        .pin()
        .derive_child_proof(
            &call.identity.code,
            "t07-call",
            "read_file",
            call.original(),
            &call.effect_id,
            call.identity.epoch,
            &call.identity.expected_head,
            call.identity.expected_head_version,
            call.identity.argument_identity.clone(),
        )
        .expect("the current pin must derive the captured child proof");
    match record.delegation.as_ref() {
        Some(crate::effects::journal::ManagedDelegationRecord::Complete {
            proof: stored, ..
        }) => {
            assert_eq!(stored, &proof, "the winner's bridge wrote the only intent");
        }
        other => panic!("one complete delegation must remain: {other:?}"),
    }
    case.close();
}

/// A real caller bridge that arrives while another contender owns the
/// `Persisting` or `Invoking` window is refused by the claim itself: it may not
/// abort the owner, write a second durable intent, or launch a second callee
/// VM. The window is held through the gate the host hands over before the
/// caller VM starts; the loser is the actual caller→bridge path.
#[tokio::test(flavor = "multi_thread")]
async fn t07_bridge_contender_is_refused_inside_the_claim_windows() {
    for window in ["persisting", "invoking"] {
        let case = t07_open(&t07_caller_source(false), &t07_callee_source(""), |_| {}).await;
        let runtime = case.state.service().managed_runtime_for_test().unwrap();
        let held: Arc<std::sync::Mutex<Option<Arc<crate::runtime::agent_host::ChildCallGate>>>> =
            Arc::new(std::sync::Mutex::new(None));
        runtime.inject_child_gate_observer(Arc::new({
            let held = Arc::clone(&held);
            move |gate: Arc<crate::runtime::agent_host::ChildCallGate>| {
                let claim = gate
                    .claim()
                    .expect("the first contender must own the claim");
                if window == "invoking" {
                    assert!(
                        gate.invoke(claim),
                        "the acknowledged first contender must reach Invoking"
                    );
                }
                *held.lock().unwrap() = Some(gate);
            }
        }));
        let output = case.probe("t07-call", T07_ARGUMENTS);
        assert_eq!(output["ok"], false, "{window}: {output}");
        assert_eq!(
            output["code"], "pinned_child_already_claimed",
            "{window}: the real bridge must be refused by the owned claim: {output}"
        );
        let gate = held
            .lock()
            .unwrap()
            .clone()
            .expect("the caller VM must have observed the per-call child gate");
        assert_eq!(
            gate.state(),
            if window == "invoking" {
                crate::runtime::agent_host::ChildGateState::Invoking(1)
            } else {
                crate::runtime::agent_host::ChildGateState::Persisting(1)
            },
            "{window}: the loser may not change the owner's gate state"
        );
        assert_eq!(
            gate.refused_claims(),
            1,
            "{window}: the real bridge must be refused by the owned claim"
        );
        let call = case
            .pinned
            .call("t07-call")
            .expect("the parent call must stay retained");
        assert_eq!(
            call.child_invocations(),
            0,
            "{window}: a refused contender runs no callee VM"
        );
        assert_eq!(
            call.native_reads(),
            1,
            "{window}: only the caller's own direct read may reach the filesystem"
        );
        let record = case.effect().expect("the durable intent row must exist");
        assert!(
            record.delegation.is_none(),
            "{window}: the loser may not write a durable intent proof"
        );
        assert!(
            record.prepared.is_none(),
            "{window}: the parent may not prepare"
        );
        assert_eq!(
            record.state,
            crate::effects::ManagedPublicationStatus::Indeterminate,
            "{window}"
        );
        case.close();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn t07_skipped_child_refuses_the_parent_prepare() {
    let case = t07_open(
        &t07_caller_source_without_child(),
        &t07_callee_source(""),
        |_| {},
    )
    .await;
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(output["code"], "managed_delegation_incomplete", "{output}");
    let record = case.effect().expect("the durable intent row must exist");
    assert!(
        record.prepared.is_none(),
        "no prepared record may be written"
    );
    assert!(
        record.delegation.is_none(),
        "no delegation proof may be written"
    );
    assert_eq!(
        record.state,
        crate::effects::ManagedPublicationStatus::Indeterminate
    );
    case.close();
}

#[tokio::test(flavor = "multi_thread")]
async fn t07_projection_mismatch_is_refused_before_any_intent() {
    let case = t07_open(
        &t07_caller_source_projection_mismatch(),
        &t07_callee_source(""),
        |_| {},
    )
    .await;
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], false, "{output}");
    // The refused child call can never complete, so the parent prepare itself
    // is refused; nothing was written before the projection check.
    assert_eq!(output["code"], "managed_delegation_incomplete", "{output}");
    let record = case.effect().expect("the durable intent row must exist");
    assert!(
        record.delegation.is_none(),
        "no intent may precede a rejected projection"
    );
    assert!(record.prepared.is_none());
    assert_eq!(
        record.state,
        crate::effects::ManagedPublicationStatus::Indeterminate
    );
    case.close();
}

#[tokio::test(flavor = "multi_thread")]
async fn t07_child_nonempty_token_is_refused_and_only_an_error_envelope_completes() {
    let case = t07_open(
        &t07_caller_source(false),
        &t07_callee_source("leaked-token"),
        |_| {},
    )
    .await;
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], false, "{output}");
    let record = case.effect().expect("the effect row must exist");
    let (_, child_result) = t07_complete(&record);
    let child_view = case
        .state
        .service()
        .managed_runtime_for_test()
        .unwrap()
        .read_result(child_result)
        .unwrap();
    assert_eq!(child_view["ok"], false, "{child_view}");
    assert_eq!(
        child_view["error"]["code"], "invalid_metadata",
        "{child_view}"
    );
    assert_eq!(
        record.state,
        crate::effects::ManagedPublicationStatus::NotPublished
    );
    case.close();
}

#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn t07_unknown_intent_write_aborts_without_child_io_and_never_retries() {
    let case = t07_open(&t07_caller_source(false), &t07_callee_source(""), |_| {}).await;
    case.state
        .persistence()
        .unwrap()
        .inject_drop_managed_commit_ack();
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(
        output["code"], "managed_delegation_intent_unknown",
        "{output}"
    );
    let record = case.effect().expect("the durable intent row must exist");
    match record.delegation.as_ref() {
        Some(crate::effects::journal::ManagedDelegationRecord::Intent { .. }) => {}
        other => panic!("the durable write must have landed as an Intent: {other:?}"),
    }
    assert!(
        record.prepared.is_none(),
        "an unknown write must never prepare"
    );
    let call = case.pinned.call("t07-call").unwrap();
    assert_eq!(
        call.native_reads(),
        1,
        "an unknown intent may not run the child"
    );
    assert_eq!(
        call.child_invocations(),
        0,
        "an unknown intent may not launch the child VM either"
    );
    // Same call replay sees the indeterminate row and fails closed.
    let replayed = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(replayed["ok"], false, "{replayed}");
    assert_eq!(replayed["code"], "managed_effect_denied", "{replayed}");
    let after = case.effect().unwrap();
    assert_eq!(record, after, "the replay must not write again");
    case.close();
}

#[tokio::test(flavor = "multi_thread")]
async fn t07_topology_and_callee_role_rejections_happen_at_prepare() {
    // A callee that imports the caller lifecycle surface is refused.
    let lifecycle_callee = format!(
        "{T07_HELPERS}pub fn run(context: map) -> map {{ agent_runtime::tool_prepare({{}}) }}\n"
    );
    let (root, state) = fixture_config(|_| {});
    let database = root.join("gateway.sqlite");
    let store =
        crate::plugins::PackageStore::open(crate::plugins::trusted_tool_package_root(&database))
            .unwrap();
    let (key, auth) = t07_key();
    t07_write_package(
        &store,
        &key,
        &root.join("callee"),
        &t07_callee_manifest(),
        &lifecycle_callee,
        &t07_catalog_source("read_file", T07_HOST_SCHEMA),
    );
    t07_write_package(
        &store,
        &key,
        &root.join("caller"),
        &t07_caller_manifest(),
        &t07_caller_source(false),
        &t07_catalog_source("read_file", T07_HOST_SCHEMA),
    );
    store.install(&root.join("callee"), &auth).unwrap();
    store.install(&root.join("caller"), &auth).unwrap();
    let lock = store
        .resolve(&crate::plugins::ResolveRequest {
            harness_selection: crate::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: T07_CALLER_ID.into(),
            },
            roots: vec![crate::plugins::PackageRequirement {
                id: T07_CALLER_ID.into(),
                version: "1.0.0".into(),
            }],
            host_runtime: crate::plugins::HOST_RUNTIME.into(),
        })
        .unwrap();
    let error = store.prepare(&lock).unwrap_err();
    assert!(
        error.to_string().contains("unauthorized") || error.to_string().contains("agent_runtime"),
        "callee lifecycle import must be refused at prepare: {error}"
    );
    drop(state);
    let _ = std::fs::remove_dir_all(&root);
}

/// Every unsupported two-package shape is refused by the managed admission
/// (prepare or pin), never executed.
#[tokio::test(flavor = "multi_thread")]
async fn t07_unsupported_two_package_shapes_are_refused_by_managed_admission() {
    // (label, caller manifest, callee manifest, callee catalog)
    let callee_two = r#"pub fn managed_authority_catalog(context: map) -> map {
    {
        declarations: [
            { tool_name: "read_file", operation: "workspace_read" },
            { tool_name: "search_files", operation: "workspace_read" }
        ],
        descriptors: [
            { name: "read_file", description: "d1", toolset: "coding", risk_class: "read", schema: T07_CALLEE_SCHEMA },
            { name: "search_files", description: "d2", toolset: "coding", risk_class: "read", schema: T07_CALLEE_SCHEMA }
        ]
    }
}
"#
    .replace("T07_CALLEE_SCHEMA", T07_CALLEE_SCHEMA);
    let mut cases: Vec<(&str, String, String, String)> = Vec::new();
    cases.push((
        "callee-state",
        t07_caller_manifest(),
        t07_callee_manifest().replace(
            "dependencies: []",
            "dependencies: []\nstate:\n  scope: run\n  schema: 1",
        ),
        t07_catalog_source("read_file", T07_CALLEE_SCHEMA),
    ));
    cases.push((
        "callee-no-direct-effect",
        t07_caller_manifest(),
        t07_callee_manifest().replace(
            "        - kind: workspace.fs.read\n          scope: bound_workspace\n          recovery: none\n      delegated: []",
            "      delegated: []",
        ),
        t07_catalog_source("read_file", T07_CALLEE_SCHEMA),
    ));
    cases.push((
        "callee-two-descriptors",
        t07_caller_manifest(),
        t07_callee_manifest(),
        callee_two,
    ));
    let extra_dependency = t07_caller_manifest().replace(
        "  - alias: child\n    id: org.rustscript.tools.t07callee\n    version: 1.0.0\n",
        "  - alias: child\n    id: org.rustscript.tools.t07callee\n    version: 1.0.0\n  - alias: other\n    id: org.rustscript.tools.t07callee\n    version: 1.0.0\n",
    );
    cases.push((
        "caller-extra-dependency",
        extra_dependency,
        t07_callee_manifest(),
        t07_catalog_source("read_file", T07_CALLEE_SCHEMA),
    ));
    for (label, caller, callee, callee_catalog) in cases {
        let (root, state) = fixture_config(|_| {});
        let database = root.join("gateway.sqlite");
        let source_root = root.join("sources");
        std::fs::create_dir_all(&source_root).unwrap();
        let (key, auth) = t07_key();
        let store = crate::plugins::PackageStore::open(crate::plugins::trusted_tool_package_root(
            &database,
        ))
        .unwrap();
        t07_write_package(
            &store,
            &key,
            &source_root.join("callee"),
            &callee,
            &t07_callee_source(""),
            &callee_catalog,
        );
        t07_write_package(
            &store,
            &key,
            &source_root.join("caller"),
            &caller,
            &t07_caller_source(false),
            &t07_catalog_source("read_file", T07_HOST_SCHEMA),
        );
        let state = state
            .with_plugin_control(auth.clone(), source_root.clone(), "t07-space")
            .unwrap();
        let service = state.service();
        for package in ["callee", "caller"] {
            let _ = service.install_controlled_plugin(&json!({
                "package": package,
                "deployment_space": "t07-space",
            }));
        }
        let store = crate::plugins::PackageStore::open(crate::plugins::trusted_tool_package_root(
            &database,
        ))
        .unwrap();
        store.bind_policy(&auth);
        let resolved = store.resolve(&crate::plugins::ResolveRequest {
            harness_selection: crate::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: T07_CALLER_ID.into(),
            },
            roots: vec![crate::plugins::PackageRequirement {
                id: T07_CALLER_ID.into(),
                version: "1.0.0".into(),
            }],
            host_runtime: crate::plugins::HOST_RUNTIME.into(),
        });
        let refused = match resolved {
            Err(_) => true,
            Ok(lock) => {
                if store.prepare(&lock).is_err() {
                    true
                } else {
                    let persistence = state.persistence().unwrap();
                    let control = crate::plugins::PluginControlStore::new(&persistence);
                    if control.store_lock(&lock).is_err() {
                        true
                    } else {
                        let refs = lock
                            .packages
                            .iter()
                            .map(|package| crate::plugins::PackageArtifactRef {
                                package_id: package.id.clone(),
                                version: package.version.clone(),
                                kind: package.kind.clone(),
                                artifact_id: package.artifact_id.clone(),
                            })
                            .collect::<Vec<_>>();
                        if control.activate(&lock.graph_id, 0, &refs).is_err() {
                            true
                        } else {
                            service
                                .admit_external_with_workspace_selector(
                                    AdmitRunRequest {
                                        input: json!({"message":"t07 unsupported shape"}),
                                        ..Default::default()
                                    },
                                    None,
                                )
                                .await
                                .is_err()
                        }
                    }
                }
            }
        };
        assert!(
            refused,
            "{label}: unsupported two-package shape must be refused"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// The original graph is revoked after the parent is executing and before the
/// child's first real read: the child adapter refuses with the exact typed
/// code, so no child Native operation performs IO.
#[tokio::test(flavor = "multi_thread")]
async fn t07_revoked_graph_refuses_the_first_child_read_without_io() {
    let case = t07_open(&t07_caller_source(false), &t07_callee_source(""), |_| {}).await;
    let persistence = case.state.persistence().unwrap();
    let packages = Arc::new(
        crate::plugins::PackageStore::open(crate::plugins::trusted_tool_package_root(
            &case.root.join("gateway.sqlite"),
        ))
        .unwrap(),
    );
    packages.bind_policy(&case.auth);
    let graph_id = case.pinned.code.graph_id.clone();
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let runtime = case.state.service().managed_runtime_for_test().unwrap();
    runtime.inject_before_operation_observer(Arc::new({
        let persistence = Arc::clone(&persistence);
        let packages = Arc::clone(&packages);
        let graph_id = graph_id.clone();
        let fired = Arc::clone(&fired);
        move |_call| {
            if fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let control = crate::plugins::PluginControlStore::new(&persistence);
            control
                .revoke_graph(&packages, &graph_id)
                .expect("the fixture must revoke the original pinned graph");
        }
    }));
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert!(
        fired.load(std::sync::atomic::Ordering::SeqCst),
        "the fixture must have revoked the graph"
    );
    assert_eq!(output["ok"], false, "{output}");
    let record = case.effect().expect("the effect row must exist");
    let (_, child_result) = t07_complete(&record);
    let child_view = case
        .state
        .service()
        .managed_runtime_for_test()
        .unwrap()
        .read_result(child_result)
        .unwrap();
    assert_eq!(child_view["ok"], false, "{child_view}");
    assert_eq!(
        child_view["error"]["code"], "plugin_graph_revoked",
        "{child_view}"
    );
    assert_eq!(
        record.state,
        crate::effects::ManagedPublicationStatus::NotPublished
    );
    case.close();
}

/// The tombstone lands after the child adapter's own authority check and inside
/// the child filesystem admission itself. The re-read inside that admission must
/// refuse the read, so the child performs no Native IO at all.
#[tokio::test(flavor = "multi_thread")]
async fn t07_revoked_graph_inside_child_admission_performs_no_native_read() {
    let case = t07_open(&t07_caller_source(false), &t07_callee_source(""), |_| {}).await;
    let persistence = case.state.persistence().unwrap();
    let packages = Arc::new(
        crate::plugins::PackageStore::open(crate::plugins::trusted_tool_package_root(
            &case.root.join("gateway.sqlite"),
        ))
        .unwrap(),
    );
    packages.bind_policy(&case.auth);
    let graph_id = case.pinned.code.graph_id.clone();
    // The first observed operation is the caller's own direct read; the second
    // is the child's first filesystem admission.
    let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let runtime = case.state.service().managed_runtime_for_test().unwrap();
    runtime.inject_before_operation_observer(Arc::new({
        let persistence = Arc::clone(&persistence);
        let packages = Arc::clone(&packages);
        let graph_id = graph_id.clone();
        let observed = Arc::clone(&observed);
        move |_call| {
            if observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) != 1 {
                return;
            }
            crate::plugins::PluginControlStore::new(&persistence)
                .revoke_graph(&packages, &graph_id)
                .expect("the fixture must revoke the original pinned graph");
        }
    }));
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(
        observed.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the child admission must be the second observed operation"
    );
    assert_eq!(output["ok"], false, "{output}");
    let record = case.effect().expect("the effect row must exist");
    let (_, child_result) = t07_complete(&record);
    let child_view = runtime.read_result(child_result).unwrap();
    assert_eq!(child_view["ok"], false, "{child_view}");
    assert_eq!(
        child_view["error"]["code"], "plugin_graph_revoked",
        "{child_view}"
    );
    let call = case
        .pinned
        .call("t07-call")
        .expect("the parent call must stay retained");
    assert_eq!(
        call.native_reads(),
        1,
        "only the caller's direct read may reach the confined filesystem"
    );
    case.close();
}

/// Which exact closure of the admitted run's own original clock the child-path
/// fixture applies at the child's first Native admission boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum T07OriginalClockClose {
    Requested,
    Elapsed,
}

impl T07OriginalClockClose {
    fn label(self) -> &'static str {
        match self {
            Self::Requested => "original cancellation",
            Self::Elapsed => "elapsed original deadline",
        }
    }
    /// The exact parent-visible reason the typed refusal carries for this clock.
    fn expected_reason(self) -> &'static str {
        match self {
            Self::Requested => "run cancelled (requested)",
            Self::Elapsed => "run cancelled (deadline)",
        }
    }
    /// Closes the run's own cancellation root. `requested` closes the original
    /// request; `elapsed` waits on the original finite deadline that the single
    /// admission already installed. No fresh root, budget or extended deadline
    /// is created on either path.
    fn close(self, original: &crate::RunCancellation) {
        match self {
            Self::Requested => original.request(crate::CancellationReason::Requested),
            Self::Elapsed => std::thread::sleep(
                original.remaining_deadline().unwrap_or_default()
                    + std::time::Duration::from_millis(100),
            ),
        }
    }
}

/// The run's own original clock closes after the real callee VM has been
/// admitted and is already inside the child, at the exact boundary that precedes
/// the child's first confined read. The callee then continues to attempt that
/// read: the admission refuses it and no Native read/stat reaches the confined
/// filesystem. The original cancellation root is reused as admitted, and the
/// original deadline is never reset, rebuilt or extended.
async fn t07_child_native_read_denies_closed_original_clock(close: T07OriginalClockClose) {
    let case = t07_open(
        &t07_caller_source(false),
        &t07_callee_source(""),
        move |config| {
            if close == T07OriginalClockClose::Elapsed {
                config.run_timeout = std::time::Duration::from_secs(2);
            }
        },
    )
    .await;
    let original = case
        .state
        .service()
        .handle(&case.run_id)
        .expect("the admitted run must keep its handle")
        .cancel
        .clone();
    let deadline = original
        .deadline_instant()
        .expect("the admitted run must carry a finite original deadline");
    assert!(
        case.pinned.cancel.shares_original_clock(&original),
        "the managed binding must share the run's original clock, not a fresh one"
    );
    let runtime = case.state.service().managed_runtime_for_test().unwrap();
    // The first observed managed operation is the caller's own direct metadata
    // read; the second is the child's first filesystem admission. Closing the
    // clock on the second one is what makes this a child-path case: the callee
    // VM has already entered and its adapter check has already passed.
    let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    runtime.inject_before_operation_observer(Arc::new({
        let original = original.clone();
        let observed = Arc::clone(&observed);
        move |call| {
            if observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) != 1 {
                return;
            }
            assert_eq!(
                call.child_invocations(),
                1,
                "the real child VM must already be admitted before the clock closes"
            );
            assert!(
                call.check_child_operable().is_ok(),
                "the original clock must still be open at the child admission boundary"
            );
            assert!(
                original.requested().is_none() && !original.deadline_passed(),
                "the fixture must not close an already closed original clock"
            );
            close.close(&original);
            // The clock is closed before the callee is released: the read the
            // child is about to attempt already faces a closed original clock.
            match close {
                T07OriginalClockClose::Requested => assert!(original.requested().is_some()),
                T07OriginalClockClose::Elapsed => assert!(
                    original.deadline_passed(),
                    "the original deadline must be elapsed before the callee resumes"
                ),
            }
        }
    }));
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(
        observed.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the child admission must be the second observed managed operation"
    );
    assert_eq!(output["ok"], false, "{output}");
    // The parent call observes the exact typed refusal of this clock: the child
    // invocation terminates with the original reason instead of a generic
    // failure, and the two clocks stay distinguishable.
    assert_eq!(
        output["code"], "pinned_tool_failed",
        "the refusal must keep the pinned-tool envelope: {output}"
    );
    assert_eq!(
        output["message"],
        close.expected_reason(),
        "the refusal must name the original clock that closed: {output}"
    );
    // The same original clock, closed in place: the deadline is unchanged and no
    // fresh budget was allocated for this attempt.
    assert_eq!(
        original.deadline_instant(),
        Some(deadline),
        "the fixture must not reset, rebuild or extend the original deadline"
    );
    match close {
        T07OriginalClockClose::Requested => assert!(original.requested().is_some()),
        T07OriginalClockClose::Elapsed => assert!(
            original.deadline_passed(),
            "the original deadline must be genuinely elapsed"
        ),
    }
    let call = case
        .pinned
        .call("t07-call")
        .expect("the parent call must stay retained");
    assert_eq!(
        call.child_invocations(),
        1,
        "exactly one real callee VM may run, and it ran"
    );
    assert_eq!(
        call.native_reads(),
        1,
        "only the caller's own metadata read may reach the confined filesystem; the child performs no read or stat"
    );
    let record = case.effect().expect("the durable intent row must exist");
    assert!(
        record.outcome.is_none(),
        "no outcome may be committed after the original clock closed: {record:?}"
    );
    assert_eq!(
        record.state,
        crate::effects::ManagedPublicationStatus::Indeterminate,
        "a refused child read must not publish a committed or read-only state: {record:?}"
    );
    assert!(
        matches!(
            record.delegation,
            Some(crate::effects::journal::ManagedDelegationRecord::Intent { .. })
        ),
        "the child must not complete a delegation after its first read was refused: {record:?}"
    );
    assert!(
        call.publication().is_none(),
        "the refused call must publish no managed outcome"
    );
    let events = case.state.service().run_events(&case.run_id);
    assert!(
        !events.iter().any(|event| event["event"] == "tool.output"),
        "a refused call must publish no tool.output: {events:?}"
    );
    println!(
        "{}: observed=2 child_invocations={} native_reads={} state={:?} output={output}",
        close.label(),
        call.child_invocations(),
        call.native_reads(),
        record.state
    );
    case.close();
}

/// The original run is cancelled after the real child VM has been admitted and
/// before the child's first Native read, so that read is refused with its typed
/// envelope and performs no confined IO.
#[tokio::test(flavor = "multi_thread")]
async fn t07_child_native_read_denies_original_cancellation_after_child_admission() {
    t07_child_native_read_denies_closed_original_clock(T07OriginalClockClose::Requested).await;
}

/// The admitted run's own finite deadline elapses after the real child VM has
/// been admitted and before the child's first Native read, so that read is
/// refused with its typed envelope and performs no confined IO.
#[tokio::test(flavor = "multi_thread")]
async fn t07_child_native_read_denies_elapsed_original_deadline_after_child_admission() {
    t07_child_native_read_denies_closed_original_clock(T07OriginalClockClose::Elapsed).await;
}

/// An ambiguous intent write that did not land at all: the diagnostic read-back
/// is unequal, the attempt aborts, and no child VM or Native read follows.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn t07_unknown_intent_write_with_unequal_readback_aborts_without_child_io() {
    let case = t07_open(&t07_caller_source(false), &t07_callee_source(""), |_| {}).await;
    case.state
        .persistence()
        .unwrap()
        .inject_drop_managed_intent_without_apply();
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(
        output["code"], "managed_delegation_intent_unknown",
        "{output}"
    );
    let record = case.effect().expect("the durable intent row must exist");
    assert!(
        record.delegation.is_none(),
        "an unapplied write must leave no proof"
    );
    assert!(record.prepared.is_none(), "no prepare may follow");
    assert_eq!(
        record.state,
        crate::effects::ManagedPublicationStatus::Indeterminate
    );
    let call = case.pinned.call("t07-call").unwrap();
    assert_eq!(
        call.native_reads(),
        1,
        "an unknown intent may not run the child"
    );
    assert_eq!(
        call.child_invocations(),
        0,
        "an unknown intent may not launch the child VM either"
    );
    let replayed = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(replayed["ok"], false, "{replayed}");
    assert_eq!(replayed["code"], "managed_effect_denied", "{replayed}");
    assert_eq!(
        case.effect().unwrap(),
        record,
        "the replay must not write again"
    );
    // A delegate pin requires the full child proof on the row. This row has no
    // proof at all, so the current pin refuses it instead of replaying a Final.
    let call = case.pinned.call("t07-call").unwrap();
    let proof = case
        .pin()
        .derive_child_proof(
            &call.identity.code,
            "t07-call",
            "read_file",
            call.original(),
            &call.effect_id,
            call.identity.epoch,
            &call.identity.expected_head,
            call.identity.expected_head_version,
            call.identity.argument_identity.clone(),
        )
        .expect("the current pin must accept the original parent arguments");
    let error = match case.pinned.replay_live(
        "t07-call",
        "read_file",
        None,
        None,
        crate::effects::broker::ExpectedDelegation::Required(Box::new(proof)),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a row without a child proof must not replay"),
    };
    assert_eq!(error, "managed_effect_indeterminate");
    assert!(case.effect().unwrap().delegation.is_none());
    case.close();
}

/// Two contenders for one captured call: exactly one durable CAS acknowledges
/// this attempt's intent on the same parent row, the loser persists nothing,
/// and neither contender launches the callee. The row is the discriminator: a
/// payload whose parent identity differs is refused even though the
/// effect/run/call/workspace/branch tuple matches.
#[tokio::test(flavor = "multi_thread")]
async fn t07_two_contenders_share_one_claim_and_one_durable_intent() {
    let case = t07_open(
        &t07_caller_source_without_child(),
        &t07_callee_source(""),
        |_| {},
    )
    .await;
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["code"], "managed_delegation_incomplete", "{output}");
    let record = case.effect().expect("the durable intent row must exist");
    assert!(record.delegation.is_none());

    let call = case
        .pinned
        .call("t07-call")
        .expect("the parent call must stay retained");
    let proof = case
        .pin()
        .derive_child_proof(
            &call.identity.code,
            "t07-call",
            "read_file",
            call.original(),
            &call.effect_id,
            call.identity.epoch,
            &call.identity.expected_head,
            call.identity.expected_head_version,
            call.identity.argument_identity.clone(),
        )
        .expect("the current pin must accept the original parent arguments");
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let call = Arc::clone(&call);
        let proof = proof.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            call.delegate_intent(proof)
        }));
    }
    barrier.wait();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    let written = outcomes
        .iter()
        .filter(|outcome| {
            matches!(
                outcome,
                Ok(crate::effects::journal::IntentCasOutcome::WrittenByThisAttempt)
            )
        })
        .count();
    let refused = outcomes
        .iter()
        .filter(|outcome| {
            matches!(
                outcome,
                Ok(crate::effects::journal::IntentCasOutcome::Refused)
            )
        })
        .count();
    assert_eq!((written, refused), (1, 1), "{outcomes:?}");
    let after = case.effect().unwrap();
    match after.delegation.as_ref() {
        Some(crate::effects::journal::ManagedDelegationRecord::Intent { proof: stored }) => {
            assert_eq!(stored, &proof)
        }
        other => panic!("exactly one intent proof must be stored: {other:?}"),
    }
    assert_eq!(
        call.child_invocations(),
        0,
        "a contender that only owns the durable intent never runs the callee"
    );
    assert_eq!(
        call.native_reads(),
        1,
        "a contender race runs no child Native read"
    );
    // The losing contender cannot rewrite the acknowledged row, and the row is
    // unchanged byte for byte after that attempt.
    assert_eq!(
        call.delegate_intent(proof.clone()),
        Ok(crate::effects::journal::IntentCasOutcome::Refused)
    );
    assert_eq!(case.effect().unwrap(), after);

    // A proof for a different parent effect id is refused by the parent-identity
    // guard, not accepted because the call id matches.
    let mut mismatched = proof;
    mismatched.parent_effect_id = "effect-somewhere-else".into();
    assert_eq!(
        call.delegate_intent(mismatched).unwrap_err(),
        "managed delegation proof identity mismatch"
    );
    assert_eq!(
        case.effect().unwrap(),
        after,
        "a mismatched parent identity writes nothing"
    );
    case.close();
}

/// The durable intent CAS compares the complete parent identity. A payload
/// whose identity claims a different head version is refused on the stored row
/// even though the effect/run/call/workspace/branch tuple and the proof phase
/// both match, and the row read back still carries no delegation.
#[tokio::test(flavor = "multi_thread")]
async fn t07_intent_cas_refuses_a_mismatched_parent_identity_row() {
    let case = t07_open(
        &t07_caller_source_without_child(),
        &t07_callee_source(""),
        |_| {},
    )
    .await;
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["code"], "managed_delegation_incomplete", "{output}");
    let record = case.effect().expect("the durable intent row must exist");
    let call = case
        .pinned
        .call("t07-call")
        .expect("the parent call must stay retained");
    let proof = case
        .pin()
        .derive_child_proof(
            &call.identity.code,
            "t07-call",
            "read_file",
            call.original(),
            &call.effect_id,
            call.identity.epoch,
            &call.identity.expected_head,
            call.identity.expected_head_version,
            call.identity.argument_identity.clone(),
        )
        .expect("the current pin must accept the original parent arguments");
    let write = |record: &crate::effects::ManagedEffectRecord| {
        case.pinned
            .runtime
            .repository
            .delegate_intent(
                &record.effect_id,
                &case.run_id,
                "t07-call",
                &record.identity.workspace.workspace_id,
                &record.identity.workspace.branch_id,
                &serde_json::to_string(record).unwrap(),
                &case.pinned.cancel,
            )
            .unwrap()
    };
    let mut forged = record.clone();
    forged.delegation = Some(crate::effects::journal::ManagedDelegationRecord::Intent {
        proof: proof.clone(),
    });
    forged.identity.expected_head_version += 1;
    assert_eq!(
        write(&forged),
        crate::effects::journal::IntentCasOutcome::Refused,
        "a row whose parent identity differs must refuse the intent CAS"
    );
    let after = case.effect().unwrap();
    assert!(
        after.delegation.is_none(),
        "the refused row must carry no proof"
    );
    assert_eq!(after, record, "the refused attempt changed no row bytes");
    assert_eq!(
        call.child_invocations(),
        0,
        "a refused intent row runs no callee"
    );
    assert_eq!(call.native_reads(), 1);
    // The exact same shape with the stored parent identity is acknowledged, so
    // the identity comparison - not the tuple - was the discriminator.
    let mut exact = record.clone();
    exact.delegation = Some(crate::effects::journal::ManagedDelegationRecord::Intent {
        proof: proof.clone(),
    });
    assert_eq!(
        write(&exact),
        crate::effects::journal::IntentCasOutcome::WrittenByThisAttempt
    );
    match case.effect().unwrap().delegation.as_ref() {
        Some(crate::effects::journal::ManagedDelegationRecord::Intent { proof: stored }) => {
            assert_eq!(stored, &proof)
        }
        other => panic!("the exact parent identity must store the proof: {other:?}"),
    }
    case.close();
}

/// Replay expectation is derived from the current pin, never from the record.
#[tokio::test(flavor = "multi_thread")]
async fn t07_replay_expectation_is_exact_for_the_current_pin() {
    use crate::effects::broker::ExpectedDelegation;
    let case = t07_open(&t07_caller_source(false), &t07_callee_source(""), |_| {}).await;
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], true, "{output}");
    let call = case.pinned.call("t07-call").unwrap();
    let exact = case
        .pin()
        .derive_child_proof(
            &call.identity.code,
            "t07-call",
            "read_file",
            call.original(),
            &call.effect_id,
            call.identity.epoch,
            &call.identity.expected_head,
            call.identity.expected_head_version,
            call.identity.argument_identity.clone(),
        )
        .unwrap();
    let replayed = case
        .pinned
        .replay_live(
            "t07-call",
            "read_file",
            None,
            None,
            ExpectedDelegation::Required(Box::new(exact.clone())),
        )
        .expect("the exact proof must replay");
    assert!(replayed.is_some(), "the stored final result must replay");
    let error = match case.pinned.replay_live(
        "t07-call",
        "read_file",
        None,
        None,
        ExpectedDelegation::Absent,
    ) {
        Err(error) => error,
        Ok(_) => panic!("a caller-only pin may not replay a child-bearing row"),
    };
    assert_eq!(error, "managed replay delegation unexpected");
    let mut wrong = exact.clone();
    wrong.callee_tool = "search_files".into();
    let error = match case.pinned.replay_live(
        "t07-call",
        "read_file",
        None,
        None,
        ExpectedDelegation::Required(Box::new(wrong)),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a mismatched proof must be refused"),
    };
    assert_eq!(error, "managed replay delegation mismatch");
    // An "absent" and an explicit "null" delegation are the same
    // pre-delegation durable shape. Each is written as a real final row
    // through the formal storage command and then replayed by the delegate
    // pin, so the refusal comes from the live delegation gate rather than
    // from decoding alone.
    let record = case.effect().expect("the effect row must exist");
    assert!(matches!(
        record.delegation,
        Some(crate::effects::journal::ManagedDelegationRecord::Complete { .. })
    ));
    let outcome = record
        .outcome
        .clone()
        .expect("the committed outcome must exist");
    let persistence = case.state.persistence().unwrap();
    for (index, (label, null_field)) in [("absent", false), ("null", true)].into_iter().enumerate()
    {
        let replay_call = format!("t07-{label}");
        let mut seed = record.clone();
        seed.effect_id = format!("effect-{:032x}", 0x7000 + index);
        seed.identity.call_id = replay_call.clone();
        seed.outcome = Some(outcome.clone());
        seed.prepared = None;
        let mut row = serde_json::to_value(&seed).unwrap();
        row.as_object_mut().unwrap().remove("delegation");
        if null_field {
            row["delegation"] = serde_json::Value::Null;
        }
        let event = |suffix: &str, seq: u64| {
            json!({
                "event_id": format!("{replay_call}-{suffix}"),
                "event_type": format!("tool.{suffix}"),
                "seq": seq,
                "payload_json": "{}",
                "created_at_ms": crate::domain::timestamp(),
            })
        };
        let projections = json!({
            "normal": {
                "output": event("requested", 900_000 + index as u64 * 2),
                "terminal": event("started", 900_001 + index as u64 * 2),
            }
        });
        persistence
            .managed_effect_command(
                "effect.begin",
                &json!({
                    "effect_id": seed.effect_id,
                    "run_id": case.run_id,
                    "call_id": replay_call,
                    "workspace_id": seed.identity.workspace.workspace_id,
                    "branch_id": seed.identity.workspace.branch_id,
                    "record_json": row.to_string(),
                    "commit_id": format!("receipt-{:032x}", 0x7100 + index),
                    "sealed_class": "workspace_read",
                    "projections_json": projections.to_string(),
                }),
            )
            .expect("the pre-delegation row must be writable through the formal storage command");
        let decoded = persistence
            .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
                owner: case.pinned.owner.clone(),
                call_id: replay_call.clone(),
            })
            .unwrap()
            .expect("the seeded row must read back");
        assert!(
            decoded.delegation.is_none(),
            "{label}: a missing or null delegation carries no child proof"
        );
        let error = match case.pinned.replay_live(
            &replay_call,
            "read_file",
            None,
            None,
            ExpectedDelegation::Required(Box::new(exact.clone())),
        ) {
            Err(error) => error,
            Ok(_) => panic!("{label}: a delegate pin may not replay a row with no child proof"),
        };
        assert_eq!(error, "managed replay delegation missing", "{label}");
    }
    // The pin-less replay entry point cannot reproduce a child-bearing row: it
    // is refused with a typed code instead of being returned as a Final.
    let service = case.state.service();
    let request = crate::effects::ManagedEffectGetRequest {
        owner: case.pinned.owner.clone(),
        call_id: "t07-call".into(),
    };
    match service.replay_managed_call(request).unwrap() {
        crate::effects::ManagedCallReplay::Unavailable { code } => {
            assert_eq!(code, "managed_effect_pin_required")
        }
        crate::effects::ManagedCallReplay::Final { .. } => {
            panic!("a child-bearing row must not replay as a Final without a pin")
        }
        other => panic!("unexpected replay result: {other:?}"),
    }
    // The pin-visible durable recovery still restores it.
    match crate::service::managed_effects::replay_durable(
        service.as_ref(),
        &case.run_id,
        "t07-call",
        "read_file",
    )
    .expect("the sealed pin must restore the stored result")
    {
        crate::service::managed_effects::ManagedDurableReplay::Final(result) => {
            assert!(
                result.replayed,
                "the restored result must be marked replayed"
            )
        }
        crate::service::managed_effects::ManagedDurableReplay::Unmanaged => {
            panic!("the sealed pin must see the durable row")
        }
    }
    case.close();
}

/// The prepare cut after the object registry rolls the whole transaction back:
/// the intent row and its proof survive, no receipt or prepared state does.
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn t07_prepare_rollback_after_object_registry_keeps_the_intent_row() {
    let case = t07_open(&t07_caller_source(false), &t07_callee_source(""), |_| {}).await;
    let runtime = case.state.service().managed_runtime_for_test().unwrap();
    runtime.arm_fault(crate::effects::broker::ManagedEffectFault::PrepareAfterObjectRegistry);
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], false, "{output}");
    let record = case.effect().expect("the durable intent row must exist");
    match record.delegation.as_ref() {
        Some(crate::effects::journal::ManagedDelegationRecord::Intent { .. }) => {}
        other => panic!("the intent row must survive the rollback: {other:?}"),
    }
    assert!(
        record.prepared.is_none(),
        "the prepare receipt must roll back with the row"
    );
    assert_eq!(
        record.state,
        crate::effects::ManagedPublicationStatus::Indeterminate
    );
    let call = case.pinned.call("t07-call").unwrap();
    assert_eq!(
        call.native_reads(),
        3,
        "the caller read and both child reads really ran before the cut"
    );
    // Read the aborted transaction back from storage through a fresh handle: the
    // row keeps its intent phase, no prepare receipt and no outcome survive, and
    // nothing the prepare wrote is registered as a retained object.
    let persistence = case.state.persistence().unwrap();
    let durable = persistence
        .managed_effect_get(&crate::effects::ManagedEffectGetRequest {
            owner: case.pinned.owner.clone(),
            call_id: "t07-call".into(),
        })
        .unwrap()
        .expect("the durable row must stay readable after the cut");
    assert_eq!(durable, record, "the abort must not rewrite the row");
    assert!(
        durable.prepared.is_none(),
        "the prepare receipt must roll back with the row"
    );
    assert!(durable.outcome.is_none(), "no commit outcome may survive");
    let census = persistence.managed_object_census().unwrap();
    assert!(
        census
            .iter()
            .all(|object| object.object_kind != crate::effects::ManagedObjectKind::CanonicalResult),
        "the aborted prepare may not register a canonical result: {census:?}"
    );
    assert!(
        census
            .iter()
            .all(|object| object.object_kind != crate::effects::ManagedObjectKind::IntentDetails),
        "no intent detail object survives this inline-argument row: {census:?}"
    );
    // Every object that does exist still resolves through the same reference
    // query the collector uses, so the rollback left no dangling reference.
    for object in &census {
        let references = persistence
            .managed_object_references(&crate::effects::ManagedObjectReferencesRequest {
                store_id: object.store_id.clone(),
                object_id: object.object_id.clone(),
            })
            .unwrap();
        assert!(
            references.iter().any(|reference| reference.reference_kind
                == crate::effects::ManagedObjectReferenceKind::RegisteredObject),
            "{} must resolve as a registered object",
            object.object_id
        );
        assert!(
            references.iter().all(|reference| !matches!(
                reference.reference_kind,
                crate::effects::ManagedObjectReferenceKind::PreparedResult
                    | crate::effects::ManagedObjectReferenceKind::DelegatedChildResult
            )),
            "{} must not carry a rolled-back prepare reference",
            object.object_id
        );
    }
    // The surviving row carries only the Intent phase, so the sealed delegate
    // pin cannot restore it as a Final result.
    let proof = case
        .pin()
        .derive_child_proof(
            &call.identity.code,
            "t07-call",
            "read_file",
            call.original(),
            &call.effect_id,
            call.identity.epoch,
            &call.identity.expected_head,
            call.identity.expected_head_version,
            call.identity.argument_identity.clone(),
        )
        .expect("the current pin must accept the original parent arguments");
    let error = match case.pinned.replay_live(
        "t07-call",
        "read_file",
        None,
        None,
        crate::effects::broker::ExpectedDelegation::Required(Box::new(proof)),
    ) {
        Err(error) => error,
        Ok(_) => panic!("an intent-only row must not replay as a Final"),
    };
    assert_eq!(error, "managed_effect_indeterminate");
    match case.effect().unwrap().delegation.as_ref() {
        Some(crate::effects::journal::ManagedDelegationRecord::Intent { .. }) => {}
        other => panic!("the intent phase must survive the rollback: {other:?}"),
    }
    case.close();
}

/// Both delegation references stay retained across a storage reopen: the
/// argument detail object and the child canonical result are enumerated by the
/// existing reference query, not by memory.
#[tokio::test(flavor = "multi_thread")]
async fn t07_delegation_references_survive_reopen() {
    // A parent identity over the inline threshold carries a real detail object.
    let large = format!(r#"{{"path":"{}"}}"#, "missing-".repeat(700));
    let case = t07_open_case(
        &t07_caller_source_without_read_success(),
        &t07_callee_source(""),
        |_| {},
        &large,
        |_| {},
    )
    .await;
    let output = case.probe("t07-call", &large);
    assert_eq!(output["ok"], false, "{output}");
    let record = case.effect().expect("the effect row must exist");
    let (proof, child_result) = t07_complete(&record);
    let details = match &proof.child_arguments {
        crate::effects::journal::ManagedArgumentIdentity::Object { details } => details.clone(),
        other => panic!("a large parent identity must use a detail object: {other:?}"),
    };
    let persistence = case.state.persistence().unwrap();
    let references = |persistence: &crate::GatewayPersistence,
                      reference: &crate::effects::ManagedObjectRef| {
        persistence
            .managed_object_references(&crate::effects::ManagedObjectReferencesRequest {
                store_id: reference.store_id.clone(),
                object_id: reference.object_id.clone(),
            })
            .unwrap()
    };
    let kinds = |references: Vec<crate::effects::ManagedObjectReference>| {
        references
            .into_iter()
            .map(|reference| reference.reference_kind)
            .collect::<Vec<_>>()
    };
    let live_details = kinds(references(&persistence, &details));
    let live_child = kinds(references(&persistence, child_result));
    assert!(
        live_details.contains(&crate::effects::ManagedObjectReferenceKind::DelegatedArguments),
        "{live_details:?}"
    );
    assert!(
        live_child.contains(&crate::effects::ManagedObjectReferenceKind::DelegatedChildResult),
        "{live_child:?}"
    );
    // A fresh storage handle sees the same durable references.
    let service = case.state.service();
    service.shutdown().await.unwrap();
    persistence.shutdown();
    drop(persistence);
    let reopened = crate::GatewayPersistence::open(
        &AgentGatewayConfig::default(),
        &case.root.join("gateway.sqlite"),
    )
    .unwrap();
    let reopened_details = kinds(references(&reopened, &details));
    let reopened_child = kinds(references(&reopened, child_result));
    assert!(
        reopened_details.contains(&crate::effects::ManagedObjectReferenceKind::DelegatedArguments),
        "{reopened_details:?}"
    );
    assert!(
        reopened_child.contains(&crate::effects::ManagedObjectReferenceKind::DelegatedChildResult),
        "{reopened_child:?}"
    );
    // The formal collector runs on the reopened store: the run's graph is still
    // referenced, so the sweep reclaims nothing, and both delegation references
    // stay registered afterwards.
    let collector = crate::plugins::PluginControlStore::new(&reopened);
    let collected = collector
        .collect_unreferenced()
        .expect("the formal collector must run against the reopened store");
    assert!(
        !collected.contains(&case.pinned.code.graph_id),
        "a referenced graph must survive the sweep: {collected:?}"
    );
    assert!(
        collector.load_lock(&case.pinned.code.graph_id).is_ok(),
        "the referenced graph lock must still load after the sweep"
    );
    let swept_details = kinds(references(&reopened, &details));
    let swept_child = kinds(references(&reopened, child_result));
    assert!(
        swept_details.contains(&crate::effects::ManagedObjectReferenceKind::DelegatedArguments),
        "{swept_details:?}"
    );
    assert!(
        swept_child.contains(&crate::effects::ManagedObjectReferenceKind::DelegatedChildResult),
        "{swept_child:?}"
    );
    // The referenced objects themselves still resolve through the metadata query.
    for reference in [&details, child_result] {
        let metadata = reopened
            .managed_object_metadata(&crate::effects::ManagedObjectReferencesRequest {
                store_id: reference.store_id.clone(),
                object_id: reference.object_id.clone(),
            })
            .unwrap();
        assert_eq!(
            metadata.as_ref(),
            Some(reference),
            "{} must stay registered after the sweep",
            reference.object_id
        );
    }
    reopened.shutdown();
    let _ = std::fs::remove_dir_all(&case.root);
}

/// The outer guest result is bounded and charged from the borrowed VM value
/// before it is copied into JSON. A result that cannot fit the remaining shared
/// budget is refused at the commit boundary, before any prepare, receipt or
/// retained-object registration.
#[tokio::test(flavor = "multi_thread")]
async fn t07_outer_guest_result_is_charged_before_conversion() {
    let case = t07_open_case(
        &t07_caller_source(false),
        &t07_callee_source_doubled(),
        |_| {},
        T07_ARGUMENTS,
        |workspace| {
            std::fs::write(workspace.join("note.txt"), vec![b'z'; 300 * 1024]).unwrap();
        },
    )
    .await;
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(output["code"], "managed_output_budget_exceeded", "{output}");
    let record = case.effect().expect("the durable intent row must exist");
    assert!(
        record.prepared.is_none(),
        "the outer result must be refused before the parent prepares"
    );
    assert!(record.outcome.is_none(), "no final outcome may be written");
    // The callee really ran (its intent landed and its VM was entered); only the
    // outer commit result was refused.
    match record.delegation.as_ref() {
        Some(crate::effects::journal::ManagedDelegationRecord::Intent { .. }) => {}
        other => panic!("the bridge intent must remain: {other:?}"),
    }
    let call = case
        .pinned
        .call("t07-call")
        .expect("the parent call must stay retained");
    assert_eq!(call.child_invocations(), 1);
    case.close();
}

/// A delegated read whose child result is over budget is refused before the
/// child-result object is registered.
#[tokio::test(flavor = "multi_thread")]
async fn t07_child_result_over_budget_is_refused_before_object_registration() {
    let case = t07_open_case(
        &t07_caller_source(false),
        &t07_callee_source_doubled(),
        |_| {},
        T07_ARGUMENTS,
        |workspace| {
            std::fs::write(workspace.join("note.txt"), vec![b'x'; 600 * 1024]).unwrap();
        },
    )
    .await;
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(output["code"], "managed_output_budget_exceeded", "{output}");
    let record = case.effect().expect("the durable intent row must exist");
    match record.delegation.as_ref() {
        Some(crate::effects::journal::ManagedDelegationRecord::Intent { .. }) => {}
        other => panic!("no child result may be registered: {other:?}"),
    }
    assert!(record.prepared.is_none(), "the parent may not prepare");
    case.close();
}

/// A callee that returns the raw read buffer inside its canonical data, so the
/// child-result conversion sees a real `Value::Bytes` rather than a UTF-8
/// string.
fn t07_callee_source_raw_bytes() -> String {
    format!(
        r#"{T07_HELPERS}
pub fn run(context: map) -> map {{
    let arguments: map = t07_map(context, "arguments");
    let path: string = t07_string(arguments, "path", "");
    let meta: map = cap::fs_metadata("", path);
    if t07_bool(meta, "ok", false) == false => {{
        meta
    }} else => {{
        let len: int = t07_int(meta, "len", 0);
        let read: map = cap::fs_read_range("", path, 0, len);
        if t07_bool(read, "ok", false) == false => {{
            read
        }} else => {{
            {{ ok: true, content: "", data: {{ raw: read.bytes }}, error: null, truncated: false, artifacts: [] }}
        }}
    }}
}}
"#
    )
}

/// A child result carrying bytes that are not valid UTF-8 is refused before
/// any JSON tree or canonical string exists: the canonical envelope has no
/// byte type, so a lossy replacement would silently corrupt the delegated
/// result.
#[tokio::test(flavor = "multi_thread")]
async fn t07_child_result_with_invalid_utf8_bytes_is_refused() {
    let case = t07_open_case(
        &t07_caller_source(false),
        &t07_callee_source_raw_bytes(),
        |_| {},
        T07_ARGUMENTS,
        |workspace| {
            std::fs::write(workspace.join("note.txt"), [0xffu8, 0xfe, 0x80]).unwrap();
        },
    )
    .await;
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(
        output["code"], "pinned_child_result_unrepresentable",
        "{output}"
    );
    let record = case.effect().expect("the durable intent row must exist");
    match record.delegation.as_ref() {
        Some(crate::effects::journal::ManagedDelegationRecord::Intent { .. }) => {}
        other => panic!("invalid bytes may not register a child result: {other:?}"),
    }
    assert!(record.prepared.is_none(), "the parent may not prepare");
    let census = case
        .state
        .persistence()
        .unwrap()
        .managed_object_census()
        .unwrap();
    assert!(
        census
            .iter()
            .all(|object| object.object_kind != crate::effects::ManagedObjectKind::CanonicalResult),
        "no lossy canonical result may be registered: {census:?}"
    );
    case.close();
}

/// The same raw-byte child result is preserved exactly when the buffer is
/// valid UTF-8: byte buffers count their raw payload and become the same
/// string, never a replaced or truncated view.
#[tokio::test(flavor = "multi_thread")]
async fn t07_child_result_with_valid_utf8_bytes_is_preserved() {
    let case = t07_open_case(
        &t07_caller_source(false),
        &t07_callee_source_raw_bytes(),
        |_| {},
        T07_ARGUMENTS,
        |workspace| {
            std::fs::write(workspace.join("note.txt"), b"raw-bytes-preserved").unwrap();
        },
    )
    .await;
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], true, "{output}");
    let record = case.effect().expect("the effect row must exist");
    let (_, child_result) = t07_complete(&record);
    let child_view = case
        .state
        .service()
        .managed_runtime_for_test()
        .unwrap()
        .read_result(child_result)
        .unwrap();
    assert_eq!(
        child_view["data"]["raw"], "raw-bytes-preserved",
        "{child_view}"
    );
    case.close();
}

/// A Native read whose requested range plus frame cannot fit the remaining
/// budget is refused before the file is read; the child error envelope still
/// completes the delegation.
#[tokio::test(flavor = "multi_thread")]
async fn t07_native_read_over_budget_is_refused_before_io() {
    let case = t07_open_case(
        &t07_caller_source(false),
        &t07_callee_source(""),
        |_| {},
        T07_ARGUMENTS,
        |workspace| {
            std::fs::write(workspace.join("note.txt"), vec![b'y'; 1024 * 1024]).unwrap();
        },
    )
    .await;
    let output = case.probe("t07-call", T07_ARGUMENTS);
    assert_eq!(output["ok"], false, "{output}");
    let record = case.effect().expect("the effect row must exist");
    let (_, child_result) = t07_complete(&record);
    let child_view = case
        .state
        .service()
        .managed_runtime_for_test()
        .unwrap()
        .read_result(child_result)
        .unwrap();
    assert_eq!(child_view["ok"], false, "{child_view}");
    assert_eq!(
        child_view["error"]["code"], "managed_output_budget_exceeded",
        "{child_view}"
    );
    let call = case.pinned.call("t07-call").unwrap();
    assert_eq!(
        call.native_reads(),
        2,
        "the refused range read must not touch the filesystem"
    );
    case.close();
}

/// The delegated caller contract admits only the metadata/range descriptors, so
/// a `cap::fs_list` import is refused at prepare, before any intent or IO.
#[tokio::test(flavor = "multi_thread")]
async fn t07_delegated_caller_cannot_import_directory_listing() {
    let caller = format!(
        "{T07_HELPERS}pub fn run(context: map) -> map {{\n    let arguments: map = t07_map(context, \"arguments\");\n    let path: string = t07_string(arguments, \"path\", \"\");\n    cap::fs_list(\"\", path, 0, 8)\n}}\n"
    );
    let (root, state) = fixture_config(|_| {});
    let database = root.join("gateway.sqlite");
    let store =
        crate::plugins::PackageStore::open(crate::plugins::trusted_tool_package_root(&database))
            .unwrap();
    let (key, auth) = t07_key();
    t07_write_package(
        &store,
        &key,
        &root.join("callee"),
        &t07_callee_manifest(),
        &t07_callee_source(""),
        &t07_catalog_source("read_file", T07_CALLEE_SCHEMA),
    );
    t07_write_package(
        &store,
        &key,
        &root.join("caller"),
        &t07_caller_manifest(),
        &caller,
        &t07_catalog_source("read_file", T07_HOST_SCHEMA),
    );
    store.install(&root.join("callee"), &auth).unwrap();
    store.install(&root.join("caller"), &auth).unwrap();
    let lock = store
        .resolve(&crate::plugins::ResolveRequest {
            harness_selection: crate::plugins::HarnessSelectionRequest::ToolOnly {
                tool_package: T07_CALLER_ID.into(),
            },
            roots: vec![crate::plugins::PackageRequirement {
                id: T07_CALLER_ID.into(),
                version: "1.0.0".into(),
            }],
            host_runtime: crate::plugins::HOST_RUNTIME.into(),
        })
        .unwrap();
    let error = store.prepare(&lock).unwrap_err();
    assert!(
        error.to_string().contains("cap::fs_list"),
        "the delegated caller must not import a directory listing: {error}"
    );
    drop(state);
    let _ = std::fs::remove_dir_all(&root);
}
