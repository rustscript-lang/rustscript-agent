//! Real managed Native owners at restore boundaries; no public-ID authority.
use super::*;
use crate::{AdmitRunRequest, AgentGatewayState, ScriptedProvider};
use std::time::Duration;

fn fixture(timeout: Duration) -> (PathBuf, AgentGatewayState) {
    super::managed_authority_tests::native_fixture_config(|config| {
        config.run_timeout = timeout;
        config.bearer_token = Some("synthetic-maintenance-fixture".into());
        let policy = &mut config
            .managed_workspace
            .as_mut()
            .unwrap()
            .maintenance_policy;
        policy.create_checkpoint = true;
        policy.restore = true;
    })
}
async fn admit(service: &Arc<crate::AgentService>, id: &str) -> crate::AdmittedRun {
    admit_call(
        service,
        json!({"id":id,"name":"write_file","arguments":{"path":"value.txt","content":"A"}}),
    )
    .await
}
/// A live reader holds a Native view without reserving the branch writer. The
/// branch writer gate is single-writer across runs, so two simultaneously
/// live *writers* on one branch are refused by design; live runs that must
/// coexist on the same branch are admitted as reads.
async fn admit_read(service: &Arc<crate::AgentService>, id: &str) -> crate::AdmittedRun {
    admit_call(
        service,
        json!({"id":id,"name":"read_file","arguments":{"path":"value.txt"}}),
    )
    .await
}
async fn admit_call(service: &Arc<crate::AgentService>, call: Value) -> crate::AdmittedRun {
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({"text":"","tool_calls":[call],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"tool_calls"}));
    provider.push_ok(json!({"text":"done","tool_calls":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"}));
    service.inject_provider_host(provider);
    service
        .admit_external_with_workspace_selector(
            AdmitRunRequest {
                input: json!({"message":"Native restore boundary"}),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap()
}
fn cas(head: &ManagedWorkspaceHead) -> ManagedSourceCas {
    ManagedSourceCas {
        store_id: head.store_id.clone(),
        workspace_id: head.workspace_id.clone(),
        branch_id: head.branch_id.clone(),
        epoch: head.epoch,
        head_object_id: head.head_object_id.clone(),
        head_version: head.head_version,
    }
}

// This gate is inside the actual Native write, after operation RAII acquisition.
// Always release it and join the owned worker before propagating assertions.
#[tokio::test(flavor = "multi_thread")]
async fn restore_drain_obeys_original_source_owner_deadline() {
    let (_root, state) = fixture(Duration::from_secs(4));
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let (entered, received) = std::sync::mpsc::sync_channel(1);
    let (release, waiting) = std::sync::mpsc::sync_channel(1);
    let waiting = Mutex::new(waiting);
    *runtime.native_write_observer.lock() = Some(Arc::new(move |call| {
        assert_eq!(call.active_native_operations(), 1);
        entered.send(call).unwrap();
        waiting
            .lock()
            .recv_timeout(Duration::from_secs(12))
            .unwrap();
    }));
    let run = admit(&service, "entered-deadline").await;
    let worker = tokio::spawn(
        service
            .clone()
            .run_worker(run.run_id.clone(), String::new()),
    );
    let call = received.recv_timeout(Duration::from_secs(3)).unwrap();
    let binding = call.binding().unwrap();
    let head = runtime
        .repository
        .head(&binding.admitted_branch, &binding.cancel)
        .unwrap();
    let source = cas(&head);
    let frozen = runtime
        .repository
        .object_metadata(
            &ManagedObjectReferencesRequest {
                store_id: source.store_id.clone(),
                object_id: source.head_object_id.clone(),
            },
            &binding.cancel,
        )
        .unwrap()
        .unwrap();
    let prepared = runtime
        .prepare_restore_branch(
            &binding.authority,
            &binding.admitted_branch,
            &source,
            &frozen,
        )
        .unwrap();
    let original = binding.cancel.deadline_instant().unwrap();
    let management = RunCancellation::with_timeout(Duration::from_secs(9));
    let rt = runtime.clone();
    let mut drain =
        tokio::task::spawn_blocking(move || rt.settle_restore_source(&prepared, &management));
    let result = tokio::time::timeout_at(
        tokio::time::Instant::from_std(original + Duration::from_millis(400)),
        &mut drain,
    )
    .await;
    release.send(()).unwrap();
    worker.await.unwrap();
    if result.is_err() {
        let _ = drain.await.unwrap();
    }
    *runtime.native_write_observer.lock() = None;
    service.shutdown().await.unwrap();
    assert!(
        result.is_ok(),
        "restore drain extended an already-entered source owner's original deadline with the management clock"
    );
    assert!(result.unwrap().unwrap().is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn late_copy_cannot_install_adapter_after_restore_closes_source() {
    let (_root, state) = fixture(Duration::from_secs(60));
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let (entered, received) = std::sync::mpsc::sync_channel(1);
    let (release, waiting) = std::sync::mpsc::sync_channel(1);
    let waiting = Mutex::new(waiting);
    *runtime.before_adapter_install.lock() = Some(Arc::new(move |call| {
        assert!(call.adapters.lock().is_none());
        entered.send(call).unwrap();
        waiting
            .lock()
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
    }));
    let run = admit(&service, "late-copy").await;
    let worker = tokio::spawn(
        service
            .clone()
            .run_worker(run.run_id.clone(), String::new()),
    );
    let call = received.recv_timeout(Duration::from_secs(4)).unwrap();
    let binding = call.binding().unwrap();
    let head = runtime
        .repository
        .head(&binding.admitted_branch, &binding.cancel)
        .unwrap();
    let frozen = runtime
        .repository
        .object_metadata(
            &ManagedObjectReferencesRequest {
                store_id: head.store_id.clone(),
                object_id: head.head_object_id.clone(),
            },
            &binding.cancel,
        )
        .unwrap()
        .unwrap();
    let prepared = runtime
        .prepare_restore_branch(
            &binding.authority,
            &binding.admitted_branch,
            &cas(&head),
            &frozen,
        )
        .unwrap();
    assert_eq!(
        binding.branch.state.lock().active,
        1,
        "actual copy preparation RAII remains held"
    );
    release.send(()).unwrap();
    worker.await.unwrap();
    let installed = call.adapters.lock().is_some();
    drop(prepared);
    *runtime.before_adapter_install.lock() = None;
    service.shutdown().await.unwrap();
    assert!(
        !installed,
        "a view copied before restore closure installed its adapter after closure"
    );
}

fn checkpoint_request(
    run: &crate::AdmittedRun,
    binding: &ManagedRunBinding,
) -> ManagedCheckpointCreateRequest {
    ManagedCheckpointCreateRequest {
        source_run_id: run.run_id.clone(),
        workspace_id: binding.admitted_branch.workspace_id.clone(),
        source_branch_id: binding.admitted_branch.branch_id.clone(),
        expected_epoch: binding.admitted_epoch(),
        request_id: uuid::Uuid::new_v4().to_string(),
        mode: ManagedCheckpointMode::AtClosedBatch,
    }
}
async fn checkpoint_source(
    service: &Arc<crate::AgentService>,
) -> (
    crate::AdmittedRun,
    ManagedCheckpointCreateRequest,
    ManagedCheckpointRef,
) {
    let run = admit(service, "checkpoint-base").await;
    let binding = service
        .retained_tool_for_test(&run.run_id)
        .unwrap()
        .managed
        .clone()
        .unwrap();
    service
        .clone()
        .run_worker(run.run_id.clone(), String::new())
        .await;
    let request = checkpoint_request(&run, &binding);
    let checkpoint = service
        .create_managed_checkpoint(request.clone())
        .await
        .unwrap()
        .checkpoint;
    (run, request, checkpoint)
}
fn restore_request(
    runtime: &ManagedEffectRuntime,
    checkpoint: &ManagedCheckpointRef,
) -> ManagedRestoreAndAdmitRequest {
    let read = RunCancellation::with_timeout(Duration::from_secs(5));
    let context = runtime
        .repository
        .checkpoint_context(
            &ManagedCheckpointCreateRequest {
                source_run_id: checkpoint.parent_run_id.clone(),
                workspace_id: checkpoint.workspace_id.clone(),
                source_branch_id: checkpoint.source_branch_id.clone(),
                expected_epoch: checkpoint.source_epoch,
                request_id: uuid::Uuid::new_v4().to_string(),
                mode: ManagedCheckpointMode::AtClosedBatch,
            },
            &read,
        )
        .unwrap();
    ManagedRestoreAndAdmitRequest {
        workspace_id: checkpoint.workspace_id.clone(),
        source_branch_id: checkpoint.source_branch_id.clone(),
        checkpoint_id: checkpoint.checkpoint_id.clone(),
        expected_source: cas(&context.head),
        request_id: uuid::Uuid::new_v4().to_string(),
        input: ManagedRestoreRunInput {
            text: "new branch read A and write C".into(),
        },
        cancel_active_source: true,
        graph_selection: ManagedRestoreGraphSelection::CheckpointExact,
    }
}
struct ReleaseGate {
    released: Mutex<bool>,
    changed: parking_lot::Condvar,
}
impl ReleaseGate {
    fn wait(&self) {
        let mut state = self.released.lock();
        let end = std::time::Instant::now() + Duration::from_secs(12);
        while !*state {
            assert!(
                !self.changed.wait_until(&mut state, end).timed_out(),
                "owned barrier deadline"
            );
        }
    }
    fn release(&self) {
        *self.released.lock() = true;
        self.changed.notify_all();
    }
}
struct HeldOwner {
    call: Arc<ManagedCallContext>,
    binding: Arc<ManagedRunBinding>,
    adapter: Arc<ManagedAdapters>,
    _lease: ManagedObjectLease,
}
fn held(call: Arc<ManagedCallContext>) -> HeldOwner {
    let binding = call.binding().unwrap();
    let adapter = call.adapters.lock().clone().unwrap();
    let lease = binding
        .runtime
        .leases
        .lease_existing_for_test(&adapter.view_id)
        .unwrap();
    HeldOwner {
        call,
        binding,
        adapter,
        _lease: lease,
    }
}
fn reject_old_native(
    owner: &HeldOwner,
    runtime: &ManagedEffectRuntime,
    identity: &ManagedWorkspaceIdentity,
    new_branch: Option<&ManagedWorkspaceIdentity>,
) {
    let read = RunCancellation::with_timeout(Duration::from_secs(5));
    let head = runtime.repository.head(identity, &read).unwrap();
    let new_head = new_branch.map(|identity| runtime.repository.head(identity, &read).unwrap());
    let before = fs::read(owner.adapter.work.path().join("value.txt")).ok();
    let check = |denied: bool| {
        assert!(denied);
        assert_eq!(owner.call.active_native_operations(), 0);
        assert_eq!(
            fs::read(owner.adapter.work.path().join("value.txt")).ok(),
            before
        );
        assert!(!owner.adapter.work.path().join("denied.txt").exists());
        assert_eq!(runtime.repository.head(identity, &read).unwrap(), head);
        assert_eq!(
            new_branch.map(|identity| runtime.repository.head(identity, &read).unwrap()),
            new_head
        );
    };
    let token = &owner.adapter.token;
    check(
        owner
            .adapter
            .filesystem
            .metadata(token, "value.txt")
            .is_err(),
    );
    check(
        owner
            .adapter
            .filesystem
            .read_range(token, "value.txt", 0, 64)
            .is_err(),
    );
    check(owner.adapter.filesystem.list(token, "", 0, 16).is_err());
    check(
        owner
            .adapter
            .filesystem
            .write_atomic(token, "denied.txt", "*", b"denied")
            .is_err(),
    );
    check(
        owner
            .adapter
            .processes
            .spawn(
                token,
                &["/bin/true".into()],
                ".",
                &[],
                ProcessLimits::default(),
            )
            .is_err(),
    );
    // No process exists in a restorable lineage. Existing-object control is
    // covered by the explicit process-lineage rejection tests, not this handle.
    let handle = "unissued-handle";
    check(owner.adapter.processes.poll(token, handle, 0, 64).is_err());
    check(
        owner
            .adapter
            .processes
            .wait(token, handle, Some(1))
            .is_err(),
    );
    check(owner.adapter.processes.log(token, handle, 0, 64).is_err());
    check(
        owner
            .adapter
            .processes
            .write_stdin(token, handle, b"denied", Some(1))
            .is_err(),
    );
    check(owner.adapter.processes.close_stdin(token, handle).is_err());
    check(owner.adapter.processes.kill(token, handle).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_closes_two_live_runs_and_evicted_issued_owner_then_new_branch_performs_io() {
    let (_root, state) = fixture(Duration::from_secs(90));
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let (_source, _request, checkpoint) = checkpoint_source(&service).await;
    // A separate real run issues a view, finishes, then leaves the live handle table.
    let (sent, received) = std::sync::mpsc::channel();
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        sent.send(held(call)).unwrap();
    }));
    let evicted = admit(&service, "issued-evicted").await;
    service
        .clone()
        .run_worker(evicted.run_id.clone(), String::new())
        .await;
    let evicted_owner = received.recv_timeout(Duration::from_secs(2)).unwrap();
    service.evict_run_handle(&evicted.run_id);
    let gate = Arc::new(ReleaseGate {
        released: Mutex::new(false),
        changed: parking_lot::Condvar::new(),
    });
    let blocked = gate.clone();
    let (sent, received) = std::sync::mpsc::channel();
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        sent.send(held(call)).unwrap();
        blocked.wait();
    }));
    let first = admit_read(&service, "before-enter-one").await;
    let first_worker = tokio::spawn(
        service
            .clone()
            .run_worker(first.run_id.clone(), String::new()),
    );
    let one = received.recv_timeout(Duration::from_secs(3)).unwrap();
    let second = admit_read(&service, "before-enter-two").await;
    let second_worker = tokio::spawn(
        service
            .clone()
            .run_worker(second.run_id.clone(), String::new()),
    );
    let two = received.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(Arc::ptr_eq(&one.binding.branch, &two.binding.branch));
    assert!(Arc::ptr_eq(
        &one.binding.branch,
        &evicted_owner.binding.branch
    ));
    let request = restore_request(&runtime, &checkpoint);
    let (sent, closed) = std::sync::mpsc::sync_channel(1);
    *runtime.restore_closed_observer.lock() = Some(Arc::new(move |stage| {
        sent.send(stage.to_string()).unwrap();
    }));
    let task = tokio::spawn({
        let service = service.clone();
        async move { service.restore_managed_checkpoint_and_admit(request).await }
    });
    // The exact gate precedes Native enter, so no old effect can start.
    let checks = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(
            closed.recv_timeout(Duration::from_secs(3)).unwrap(),
            "closed"
        );
        assert_eq!(
            closed.recv_timeout(Duration::from_secs(3)).unwrap(),
            "cancelled"
        );
        for owner in [&one, &two, &evicted_owner] {
            reject_old_native(owner, &runtime, &one.binding.admitted_branch, None);
        }
        assert!(
            !task.is_finished(),
            "restore must wait for original workers to exit"
        );
    }));
    gate.release();
    first_worker.await.unwrap();
    second_worker.await.unwrap();
    let result = task.await.unwrap();
    *runtime.native_ready_observer.lock() = None;
    *runtime.restore_closed_observer.lock() = None;
    if let Err(error) = checks {
        service.shutdown().await.unwrap();
        std::panic::resume_unwind(error);
    }
    if result.is_err() {
        for owner in [&one, &two, &evicted_owner] {
            let phase = *owner.call.phase.lock();
            eprintln!(
                "owner {}: final={} unknown={} prepared={} event_names={:?}",
                owner.call.identity.call_id,
                phase == CallPhase::Final,
                phase == CallPhase::Unknown,
                owner.call.prepared.lock().is_some(),
                service
                    .run_events(&owner.call.identity.owner.run_id)
                    .iter()
                    .map(|event| event["event"].clone())
                    .collect::<Vec<_>>()
            );
        }
    }
    let result = result.unwrap();
    assert!(one.binding.branch.state.lock().phase == ManagedBranchPhase::Retired);
    let new_binding = service
        .retained_tool_for_test(&result.new_run_id)
        .unwrap()
        .managed
        .clone()
        .unwrap();
    for owner in [&one, &two, &evicted_owner] {
        reject_old_native(
            owner,
            &runtime,
            &one.binding.admitted_branch,
            Some(&new_binding.admitted_branch),
        );
    }
    let witness = evicted_owner.call.witness().unwrap();
    let old_owner = CapabilityOwner::new(
        "gateway",
        &evicted_owner.call.identity.owner.session_id,
        &evicted_owner.call.identity.owner.run_id,
    )
    .unwrap();
    assert!(
        evicted_owner
            .adapter
            .lifecycle
            .commit(
                &old_owner,
                &evicted_owner.adapter.token,
                witness.original.clone()
            )
            .is_err()
    );
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_ok(json!({"text":"","tool_calls":[{"id":"new-read","name":"read_file","arguments":{"path":"value.txt"}},{"id":"new-write","name":"write_file","arguments":{"path":"value.txt","content":"C"}}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"tool_calls"}));
    provider.push_ok(json!({"text":"done","tool_calls":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"reasoning":"","stop_reason":"stop"}));
    service.inject_provider_host(provider);
    service
        .clone()
        .run_worker(result.new_run_id.clone(), String::new())
        .await;
    let get = |call_id: &str| {
        state
            .persistence()
            .unwrap()
            .managed_effect_get(&ManagedEffectGetRequest {
                owner: ManagedOwnerScope {
                    profile: "gateway".into(),
                    session_id: result.new_session_id.clone(),
                    run_id: result.new_run_id.clone(),
                },
                call_id: call_id.into(),
            })
            .unwrap()
            .unwrap()
    };
    let read = get("new-read");
    let write = get("new-write");
    assert_eq!(
        read.outcome.as_ref().unwrap().disposition,
        ManagedPublicationStatus::ReadOnly
    );
    let canonical = runtime
        .read_result(&read.outcome.unwrap().canonical_result_ref)
        .unwrap();
    assert_eq!(canonical["content"], "A");
    assert_eq!(
        write.outcome.as_ref().unwrap().disposition,
        ManagedPublicationStatus::Committed
    );
    assert_ne!(
        write.identity.workspace.branch_id,
        one.binding.admitted_branch.branch_id
    );
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn foreground_intent_before_native_taints_lineage_and_denies_both_maintenance_entries() {
    process_lineage_case(true).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn settled_foreground_with_empty_owned_table_still_denies_checkpoint_and_restore() {
    process_lineage_case(false).await;
}
async fn process_lineage_case(after_intent: bool) {
    let (_root, state) = fixture(Duration::from_secs(90));
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let (_base, mut checkpoint_request, checkpoint) = checkpoint_source(&service).await;
    let restore = restore_request(&runtime, &checkpoint);
    let (sent, received) = std::sync::mpsc::channel();
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        sent.send(held(call)).unwrap();
    }));
    if after_intent {
        runtime.arm_fault(ManagedEffectFault::AfterIntent);
    }
    let run=admit_call(&service,json!({"id":"foreground-lineage","name":"terminal","arguments":{"argv":["/bin/true"],"timeout_ms":1000}})).await;
    service
        .clone()
        .run_worker(run.run_id.clone(), String::new())
        .await;
    let read = RunCancellation::with_timeout(Duration::from_secs(5));
    let record = runtime
        .repository
        .get(
            &ManagedEffectGetRequest {
                owner: ManagedOwnerScope {
                    profile: "gateway".into(),
                    session_id: run.session_id,
                    run_id: run.run_id,
                },
                call_id: "foreground-lineage".into(),
            },
            &read,
        )
        .unwrap()
        .expect("formal started intent exists");
    if after_intent {
        assert!(record.prepared.is_none());
        assert!(
            received.try_recv().is_err(),
            "AfterIntent precedes Native view construction"
        );
    } else {
        let owner = received.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(owner.adapter.processes.table_len(), 0);
        assert_eq!(owner.adapter.processes.active_stdin_workers(), 0);
        assert_eq!(
            record.prepared.as_ref().unwrap().writer_state,
            ManagedWriterState::Settled
        );
        assert_eq!(
            record.outcome.as_ref().unwrap().disposition,
            ManagedPublicationStatus::Committed
        );
    }
    let context = runtime
        .repository
        .checkpoint_context(&checkpoint_request, &read)
        .unwrap();
    assert!(context.head.process_lineage_tainted);
    checkpoint_request.request_id = uuid::Uuid::new_v4().to_string();
    let denied_checkpoint = service
        .create_managed_checkpoint(checkpoint_request.clone())
        .await;
    let denied_restore = service
        .restore_managed_checkpoint_and_admit(restore.clone())
        .await;
    assert!(
        matches!(denied_checkpoint,Err(ManagedMaintenanceFailure::Rejected {code}) if code=="managed_process_lineage_unsupported")
    );
    assert!(
        matches!(denied_restore,Err(ManagedMaintenanceFailure::Rejected {code}) if code=="managed_process_lineage_unsupported")
    );
    assert_eq!(
        runtime
            .repository
            .head(&context.workspace.identity, &read)
            .unwrap(),
        context.head
    );
    assert!(
        runtime
            .repository
            .lookup_restore_receipt(&restore, &read)
            .unwrap()
            .is_none()
    );
    assert!(
        runtime
            .repository
            .checkpoint_receipt(&checkpoint_request, &read, None)
            .unwrap()
            .is_none()
    );
    *runtime.native_ready_observer.lock() = None;
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn closure_between_authorization_and_operation_raii_denies_actual_direct_write() {
    let (_root, state) = fixture(Duration::from_secs(60));
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let ready = Arc::new(ReleaseGate {
        released: Mutex::new(false),
        changed: parking_lot::Condvar::new(),
    });
    let wait = ready.clone();
    let (sent, received) = std::sync::mpsc::channel();
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        sent.send(held(call)).unwrap();
        wait.wait();
    }));
    let run = admit(&service, "atomic-enter").await;
    let worker = tokio::spawn(
        service
            .clone()
            .run_worker(run.run_id.clone(), String::new()),
    );
    let owner = received.recv_timeout(Duration::from_secs(3)).unwrap();
    let gate = Arc::new(ReleaseGate {
        released: Mutex::new(false),
        changed: parking_lot::Condvar::new(),
    });
    let wait = gate.clone();
    let (sent, received) = std::sync::mpsc::channel();
    *runtime.before_operation_count.lock() = Some(Arc::new(move |call| {
        assert_eq!(call.active_native_operations(), 0);
        sent.send(()).unwrap();
        wait.wait();
    }));
    let adapter = owner.adapter.clone();
    let direct = tokio::task::spawn_blocking(move || {
        adapter
            .filesystem
            .write_atomic(&adapter.token, "must-not-start.txt", "*", b"forbidden")
    });
    received.recv_timeout(Duration::from_secs(3)).unwrap();
    let head = runtime
        .repository
        .head(&owner.binding.admitted_branch, &owner.binding.cancel)
        .unwrap();
    let frozen = runtime
        .repository
        .object_metadata(
            &ManagedObjectReferencesRequest {
                store_id: head.store_id.clone(),
                object_id: head.head_object_id.clone(),
            },
            &owner.binding.cancel,
        )
        .unwrap()
        .unwrap();
    let prepared = runtime
        .prepare_restore_branch(
            &owner.binding.authority,
            &owner.binding.admitted_branch,
            &cas(&head),
            &frozen,
        )
        .unwrap();
    gate.release();
    let outcome = direct.await.unwrap();
    *runtime.before_operation_count.lock() = None;
    let changed = owner
        .adapter
        .work
        .path()
        .join("must-not-start.txt")
        .exists();
    drop(prepared);
    ready.release();
    worker.await.unwrap();
    *runtime.native_ready_observer.lock() = None;
    service.shutdown().await.unwrap();
    assert!(
        outcome.is_err(),
        "old direct Native write obtained operation evidence after source closure"
    );
    assert!(!changed);
}

#[tokio::test(flavor = "multi_thread")]
async fn entered_write_drains_before_restore_outcome_and_never_publishes_old_candidate() {
    let (_root, state) = fixture(Duration::from_secs(90));
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let (_base, _request, checkpoint) = checkpoint_source(&service).await;
    let gate = Arc::new(ReleaseGate {
        released: Mutex::new(false),
        changed: parking_lot::Condvar::new(),
    });
    let wait = gate.clone();
    let (sent, received) = std::sync::mpsc::channel();
    *runtime.native_write_observer.lock() = Some(Arc::new(move |call| {
        assert_eq!(call.active_native_operations(), 1);
        sent.send(held(call)).unwrap();
        wait.wait();
    }));
    let run=admit_call(&service,json!({"id":"entered-source-write","name":"write_file","arguments":{"path":"entered.txt","content":"B"}})).await;
    let worker = tokio::spawn(
        service
            .clone()
            .run_worker(run.run_id.clone(), String::new()),
    );
    let owner = received.recv_timeout(Duration::from_secs(3)).unwrap();
    let request = restore_request(&runtime, &checkpoint);
    let original = request.clone();
    let (sent, closed) = std::sync::mpsc::channel();
    *runtime.restore_closed_observer.lock() = Some(Arc::new(move |stage| {
        sent.send(stage.to_string()).unwrap();
    }));
    let task = tokio::spawn({
        let service = service.clone();
        async move { service.restore_managed_checkpoint_and_admit(request).await }
    });
    let checks = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(
            closed.recv_timeout(Duration::from_secs(3)).unwrap(),
            "closed"
        );
        assert_eq!(owner.call.active_native_operations(), 1);
        assert!(!task.is_finished());
        assert!(
            !owner.adapter.work.path().join("entered.txt").exists(),
            "actual write is after the acquired RAII barrier"
        );
        assert!(
            runtime
                .repository
                .lookup_restore_receipt(
                    &original,
                    &RunCancellation::with_timeout(Duration::from_secs(5))
                )
                .unwrap()
                .is_none()
        );
    }));
    gate.release();
    worker.await.unwrap();
    let outcome = task.await.unwrap();
    *runtime.native_write_observer.lock() = None;
    *runtime.restore_closed_observer.lock() = None;
    let read = RunCancellation::with_timeout(Duration::from_secs(5));
    let head = runtime
        .repository
        .head(&owner.binding.admitted_branch, &read)
        .unwrap();
    assert_eq!(
        head.head_object_id, original.expected_source.head_object_id,
        "private old write cannot publish its candidate after closure"
    );
    if let Ok(result) = outcome {
        assert_eq!(result.source_before, original.expected_source);
        assert!(
            !runtime
                .path
                .join("trees")
                .join(result.new_branch.head_object_id)
                .join("entered.txt")
                .exists()
        );
    } else {
        assert!(
            runtime
                .repository
                .lookup_restore_receipt(&original, &read)
                .unwrap()
                .is_none()
        );
        assert!(owner.binding.branch.state.lock().phase == ManagedBranchPhase::Active);
    }
    assert_eq!(owner.call.active_native_operations(), 0);
    service.shutdown().await.unwrap();
    if let Err(error) = checks {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn prepared_and_readonly_witnesses_cannot_commit_across_source_closure() {
    for readonly in [false, true] {
        let (_root, state) = fixture(Duration::from_secs(90));
        let service = state.service();
        let runtime = service.managed_runtime_for_test().unwrap();
        let (_base, _request, checkpoint) = checkpoint_source(&service).await;
        let (sent, received) = std::sync::mpsc::channel();
        *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
            sent.send(held(call)).unwrap();
        }));
        let gate = runtime.arm_prepare_gate(Some("prepared-source"));
        let tool = if readonly {
            json!({"id":"prepared-source","name":"read_file","arguments":{"path":"value.txt"}})
        } else {
            json!({"id":"prepared-source","name":"write_file","arguments":{"path":"prepared-only.txt","content":"B"}})
        };
        let run = admit_call(&service, tool).await;
        let worker = tokio::spawn(
            service
                .clone()
                .run_worker(run.run_id.clone(), String::new()),
        );
        let owner = received.recv_timeout(Duration::from_secs(3)).unwrap();
        gate.wait_arrived(1).unwrap();
        let witness = owner.call.witness().unwrap();
        assert!(owner.call.outcome.lock().is_none());
        assert_eq!(
            witness.record.operation_class,
            if readonly {
                ManagedOperationClass::ReadOnly
            } else {
                ManagedOperationClass::TreeWrite
            }
        );
        let request = restore_request(&runtime, &checkpoint);
        let original = request.clone();
        let (sent, closed) = std::sync::mpsc::channel();
        *runtime.restore_closed_observer.lock() = Some(Arc::new(move |stage| {
            sent.send(stage.to_string()).unwrap();
        }));
        let task = tokio::spawn({
            let service = service.clone();
            async move { service.restore_managed_checkpoint_and_admit(request).await }
        });
        let checks = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(
                closed.recv_timeout(Duration::from_secs(3)).unwrap(),
                "closed"
            );
            assert!(!task.is_finished(), "prepared RAII must drain");
            assert!(owner.binding.check().is_err());
        }));
        gate.release();
        worker.await.unwrap();
        let outcome = task.await.unwrap();
        *runtime.native_ready_observer.lock() = None;
        *runtime.restore_closed_observer.lock() = None;
        let read = RunCancellation::with_timeout(Duration::from_secs(5));
        let head = runtime
            .repository
            .head(&owner.binding.admitted_branch, &read)
            .unwrap();
        assert_eq!(head.head_object_id, original.expected_source.head_object_id);
        assert!(
            owner.call.outcome.lock().is_none(),
            "neither read-only nor tree-write late commit may become a durable outcome"
        );
        let owner_facts = CapabilityOwner::new(
            "gateway",
            &owner.call.identity.owner.session_id,
            &owner.call.identity.owner.run_id,
        )
        .unwrap();
        assert!(
            owner
                .adapter
                .lifecycle
                .commit(&owner_facts, &owner.adapter.token, witness.original.clone())
                .is_err()
        );
        if outcome.is_err() {
            assert!(
                runtime
                    .repository
                    .lookup_restore_receipt(&original, &read)
                    .unwrap()
                    .is_none()
            );
        }
        service.shutdown().await.unwrap();
        if let Err(error) = checks {
            std::panic::resume_unwind(error);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn identity_rejections_leave_source_and_receipts_unchanged_with_same_owner_positive_control()
{
    let (root, state) = fixture(Duration::from_secs(90));
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let (_base, create, checkpoint) = checkpoint_source(&service).await;
    let original = restore_request(&runtime, &checkpoint);
    let (_other_root, other_state) = fixture(Duration::from_secs(90));
    let other = other_state.service();
    let (other_run, _other_create, other_checkpoint) = checkpoint_source(&other).await;
    let foreign = admit(&other, "foreign-authority").await;
    let foreign_binding = other
        .retained_tool_for_test(&foreign.run_id)
        .unwrap()
        .managed
        .clone()
        .unwrap();
    assert!(
        runtime
            .authorize_query(&foreign_binding.authority, &foreign_binding.admitted_branch)
            .is_err()
    );
    assert!(
        runtime
            .prepare_restore_branch(
                &foreign_binding.authority,
                &foreign_binding.admitted_branch,
                &original.expected_source,
                &checkpoint.frozen_root
            )
            .is_err()
    );
    let local = admit(&service, "local-authority").await;
    let binding = service
        .retained_tool_for_test(&local.run_id)
        .unwrap()
        .managed
        .clone()
        .unwrap();
    assert!(
        runtime
            .authorize_workspace_query(
                &binding.authority,
                "other-profile",
                &original.workspace_id,
                &binding.cancel
            )
            .is_err()
    );
    assert!(
        runtime
            .authorize_query(&binding.authority, &foreign_binding.admitted_branch)
            .is_err()
    );
    let mut variants = Vec::new();
    let mut wrong = original.clone();
    wrong.workspace_id = other_checkpoint.workspace_id.clone();
    wrong.expected_source.workspace_id = wrong.workspace_id.clone();
    variants.push(wrong);
    let mut wrong = original.clone();
    wrong.source_branch_id = other_checkpoint.source_branch_id.clone();
    wrong.expected_source.branch_id = wrong.source_branch_id.clone();
    variants.push(wrong);
    let mut wrong = original.clone();
    wrong.expected_source.store_id = foreign_binding.admitted_branch.store_id.clone();
    variants.push(wrong);
    let mut wrong = original.clone();
    wrong.checkpoint_id = other_checkpoint.checkpoint_id;
    variants.push(wrong);
    for mut wrong in variants {
        wrong.request_id = uuid::Uuid::new_v4().to_string();
        assert!(
            service
                .restore_managed_checkpoint_and_admit(wrong.clone())
                .await
                .is_err()
        );
        let read = RunCancellation::with_timeout(Duration::from_secs(5));
        assert!(
            runtime
                .repository
                .lookup_restore_receipt(&wrong, &read)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            cas(&runtime
                .repository
                .head(&binding.admitted_branch, &read)
                .unwrap()),
            original.expected_source
        );
    }
    // The actual Native grant can be revoked independently of matching public facts.
    binding.authority.revoke();
    assert!(
        runtime
            .prepare_restore_branch(
                &binding.authority,
                &binding.admitted_branch,
                &original.expected_source,
                &checkpoint.frozen_root
            )
            .is_err()
    );
    service
        .clone()
        .run_worker(local.run_id, String::new())
        .await;
    other
        .clone()
        .run_worker(foreign.run_id, String::new())
        .await;
    // Both operations use the ordinary restricted admission producer again.
    let result = service
        .restore_managed_checkpoint_and_admit(original.clone())
        .await
        .unwrap();
    assert_ne!(result.new_branch.branch_id, original.source_branch_id);
    let read = RunCancellation::with_timeout(Duration::from_secs(5));
    assert!(
        runtime
            .repository
            .lookup_restore_receipt(&original, &read)
            .unwrap()
            .is_some()
    );
    // The other real store/branch still admits and executes a new Native write.
    let independent = admit(&other, "unrelated-positive").await;
    other
        .clone()
        .run_worker(independent.run_id.clone(), String::new())
        .await;
    let effect = other_state
        .persistence()
        .unwrap()
        .managed_effect_get(&ManagedEffectGetRequest {
            owner: ManagedOwnerScope {
                profile: "gateway".into(),
                session_id: independent.session_id,
                run_id: independent.run_id,
            },
            call_id: "unrelated-positive".into(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        effect.outcome.unwrap().disposition,
        ManagedPublicationStatus::Committed
    );
    assert_eq!(
        effect.identity.workspace.branch_id,
        foreign_binding.admitted_branch.branch_id
    );
    assert_ne!(other_run.run_id, checkpoint.parent_run_id);
    // Replacement changes directory identity despite an unchanged configured path.
    fs::rename(root.join("workspace"), root.join("old-workspace")).unwrap();
    fs::create_dir(root.join("workspace")).unwrap();
    let mut replaced = create;
    replaced.request_id = uuid::Uuid::new_v4().to_string();
    assert!(service.create_managed_checkpoint(replaced).await.is_err());
    let mut replaced = original;
    replaced.request_id = uuid::Uuid::new_v4().to_string();
    assert!(
        service
            .restore_managed_checkpoint_and_admit(replaced)
            .await
            .is_err()
    );
    service.shutdown().await.unwrap();
    other.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn prepared_copy_cannot_install_witness_after_restore_source_closes() {
    let (_root, state) = fixture(Duration::from_secs(90));
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let gate = Arc::new(ReleaseGate {
        released: Mutex::new(false),
        changed: parking_lot::Condvar::new(),
    });
    let wait = gate.clone();
    let (sent, received) = std::sync::mpsc::channel();
    *runtime.before_prepared_install.lock() = Some(Arc::new(move |call| {
        assert!(call.prepared.lock().is_none());
        sent.send(held(call)).unwrap();
        wait.wait();
    }));
    let run = admit(&service, "late-prepared").await;
    let worker = tokio::spawn(
        service
            .clone()
            .run_worker(run.run_id.clone(), String::new()),
    );
    let owner = received.recv_timeout(Duration::from_secs(4)).unwrap();
    let read = RunCancellation::with_timeout(Duration::from_secs(5));
    let head = runtime
        .repository
        .head(&owner.binding.admitted_branch, &read)
        .unwrap();
    let frozen = runtime
        .repository
        .object_metadata(
            &ManagedObjectReferencesRequest {
                store_id: head.store_id.clone(),
                object_id: head.head_object_id.clone(),
            },
            &read,
        )
        .unwrap()
        .unwrap();
    let prepared = runtime
        .prepare_restore_branch(
            &owner.binding.authority,
            &owner.binding.admitted_branch,
            &cas(&head),
            &frozen,
        )
        .unwrap();
    gate.release();
    worker.await.unwrap();
    let installed = owner.call.prepared.lock().is_some();
    drop(prepared);
    *runtime.before_prepared_install.lock() = None;
    assert!(owner.call.outcome.lock().is_none());
    assert_eq!(
        runtime
            .repository
            .head(&owner.binding.admitted_branch, &read)
            .unwrap(),
        head
    );
    service.shutdown().await.unwrap();
    assert!(
        !installed,
        "late preparation installed a new witness after source closure"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn uncooperative_source_cleanup_timeout_rejects_publication_and_releases_memory_fence() {
    let (_root, state) = fixture(Duration::from_secs(90));
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let (_base, _create, checkpoint) = checkpoint_source(&service).await;
    let original = restore_request(&runtime, &checkpoint);
    service.inject_uncooperative_dispatch();
    let run = admit(&service, "cleanup-timeout").await;
    let binding = service
        .retained_tool_for_test(&run.run_id)
        .unwrap()
        .managed
        .clone()
        .unwrap();
    let host = service
        .capability_host_bridges(&run.run_id)
        .unwrap()
        .unwrap();
    assert!(host.lifecycle.is_some());
    let result = service
        .restore_managed_checkpoint_and_admit(original.clone())
        .await;
    service.release_uncooperative_dispatch();
    let read = RunCancellation::with_timeout(Duration::from_secs(5));
    assert!(
        matches!(result,Err(ManagedMaintenanceFailure::Rejected {code}) if code=="managed_restore_busy")
    );
    assert!(
        runtime
            .repository
            .lookup_restore_receipt(&original, &read)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        cas(&runtime
            .repository
            .head(&binding.admitted_branch, &read)
            .unwrap()),
        original.expected_source
    );
    assert!(binding.branch.state.lock().phase == ManagedBranchPhase::Active);
    assert!(binding.cancel.requested().is_some());
    assert!(
        binding.check().is_err(),
        "cancelled source owner cannot revive when memory fence is released"
    );
    assert!(
        service
            .run_events(&run.run_id)
            .iter()
            .any(|event| event["event"] == "run.cancelled")
    );
    let fresh = admit(&service, "after-known-cleanup-failure").await;
    assert_ne!(fresh.run_id, run.run_id);
    service
        .clone()
        .run_worker(fresh.run_id, String::new())
        .await;
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn filesystem_started_intent_without_adapter_stays_old_evidence_after_restore() {
    let (_root, state) = fixture(Duration::from_secs(90));
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let (_base, _create, checkpoint) = checkpoint_source(&service).await;
    runtime.arm_fault(ManagedEffectFault::AfterIntent);
    let run=admit_call(&service,json!({"id":"started-no-io","name":"write_file","arguments":{"path":"must-not-start.txt","content":"B"}})).await;
    let binding = service
        .retained_tool_for_test(&run.run_id)
        .unwrap()
        .managed
        .clone()
        .unwrap();
    service
        .clone()
        .run_worker(run.run_id.clone(), String::new())
        .await;
    let call = binding.call("started-no-io").unwrap();
    assert!(call.adapters.lock().is_none());
    assert!(call.prepared.lock().is_none());
    let read = RunCancellation::with_timeout(Duration::from_secs(5));
    let before = runtime
        .repository
        .get(
            &ManagedEffectGetRequest {
                owner: binding.owner.clone(),
                call_id: call.identity.call_id.clone(),
            },
            &read,
        )
        .unwrap()
        .unwrap();
    assert!(before.outcome.is_none());
    let original = restore_request(&runtime, &checkpoint);
    let result = service
        .restore_managed_checkpoint_and_admit(original.clone())
        .await;
    assert!(binding.check().is_err());
    let after = runtime
        .repository
        .get(
            &ManagedEffectGetRequest {
                owner: binding.owner.clone(),
                call_id: call.identity.call_id.clone(),
            },
            &read,
        )
        .unwrap()
        .unwrap();
    assert_eq!(before, after);
    assert!(
        !runtime
            .path
            .join("trees")
            .join(&original.expected_source.head_object_id)
            .join("must-not-start.txt")
            .exists()
    );
    if result.is_err() {
        assert!(
            runtime
                .repository
                .lookup_restore_receipt(&original, &read)
                .unwrap()
                .is_none()
        );
    }
    service.shutdown().await.unwrap();
}

struct PausedProvider {
    gate: Arc<ReleaseGate>,
    entered: std::sync::mpsc::Sender<()>,
}
impl crate::AgentProviderHost for PausedProvider {
    fn call(&self, _: &Value, _: &RunCancellation) -> Value {
        self.entered.send(()).unwrap();
        self.gate.wait();
        json!({"ok":false,"error":{"code":"cancelled","message":"owned barrier released","retryable":false}})
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn provider_worker_drain_cannot_borrow_later_management_deadline() {
    let (_root, state) = fixture(Duration::from_secs(4));
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let (_base, _create, checkpoint) = checkpoint_source(&service).await;
    let gate = Arc::new(ReleaseGate {
        released: Mutex::new(false),
        changed: parking_lot::Condvar::new(),
    });
    let (sent, received) = std::sync::mpsc::channel();
    let run = admit(&service, "unused-provider-call").await;
    let binding = service
        .retained_tool_for_test(&run.run_id)
        .unwrap()
        .managed
        .clone()
        .unwrap();
    service.inject_provider_host(Arc::new(PausedProvider {
        gate: gate.clone(),
        entered: sent,
    }));
    let worker = tokio::spawn(
        service
            .clone()
            .run_worker(run.run_id.clone(), String::new()),
    );
    received.recv_timeout(Duration::from_secs(3)).unwrap();
    let request = restore_request(&runtime, &checkpoint);
    let original = request.clone();
    let mut task = tokio::spawn({
        let service = service.clone();
        async move { service.restore_managed_checkpoint_and_admit(request).await }
    });
    let limit = binding.cancel.deadline_instant().unwrap() + Duration::from_millis(400);
    let bounded = tokio::time::timeout_at(tokio::time::Instant::from_std(limit), &mut task).await;
    let within_original = bounded.is_ok();
    gate.release();
    worker.await.unwrap();
    let outcome = match bounded {
        Ok(result) => result.unwrap(),
        Err(_) => task.await.unwrap(),
    };
    let read = RunCancellation::with_timeout(Duration::from_secs(5));
    let receipt = runtime
        .repository
        .lookup_restore_receipt(&original, &read)
        .unwrap();
    service.shutdown().await.unwrap();
    assert!(
        within_original,
        "restore extended source worker drain past its original deadline"
    );
    assert!(outcome.is_err());
    assert!(receipt.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn already_entered_direct_write_finishes_before_successful_restore_publication() {
    let (_root, state) = fixture(Duration::from_secs(90));
    let service = state.service();
    let runtime = service.managed_runtime_for_test().unwrap();
    let (_base, _create, checkpoint) = checkpoint_source(&service).await;
    let ready = Arc::new(ReleaseGate {
        released: Mutex::new(false),
        changed: parking_lot::Condvar::new(),
    });
    let entered_gate = Arc::new(ReleaseGate {
        released: Mutex::new(false),
        changed: parking_lot::Condvar::new(),
    });
    let wait = ready.clone();
    let (sent, received) = std::sync::mpsc::channel();
    *runtime.native_ready_observer.lock() = Some(Arc::new(move |call| {
        sent.send(held(call)).unwrap();
        wait.wait();
    }));
    let wait = entered_gate.clone();
    let (sent, entered) = std::sync::mpsc::channel();
    *runtime.native_write_observer.lock() = Some(Arc::new(move |call| {
        assert_eq!(call.active_native_operations(), 1);
        sent.send(()).unwrap();
        wait.wait();
    }));
    let run = admit(&service, "entered-success").await;
    let worker = tokio::spawn(
        service
            .clone()
            .run_worker(run.run_id.clone(), String::new()),
    );
    let owner = received.recv_timeout(Duration::from_secs(3)).unwrap();
    let adapter = owner.adapter.clone();
    let direct = tokio::task::spawn_blocking(move || {
        adapter
            .filesystem
            .write_atomic(&adapter.token, "entered-direct.txt", "*", b"B")
    });
    entered.recv_timeout(Duration::from_secs(3)).unwrap();
    let original = restore_request(&runtime, &checkpoint);
    let request = original.clone();
    let (sent, closed) = std::sync::mpsc::channel();
    *runtime.restore_closed_observer.lock() = Some(Arc::new(move |stage| {
        sent.send(stage.to_string()).unwrap();
    }));
    let task = tokio::spawn({
        let service = service.clone();
        async move { service.restore_managed_checkpoint_and_admit(request).await }
    });
    let before = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(
            closed.recv_timeout(Duration::from_secs(3)).unwrap(),
            "closed"
        );
        assert!(!task.is_finished());
        assert_eq!(owner.call.active_native_operations(), 1);
        assert!(
            !owner
                .adapter
                .work
                .path()
                .join("entered-direct.txt")
                .exists()
        );
        assert!(
            runtime
                .repository
                .lookup_restore_receipt(
                    &original,
                    &RunCancellation::with_timeout(Duration::from_secs(5))
                )
                .unwrap()
                .is_none()
        );
    }));
    entered_gate.release();
    let written = direct.await.unwrap();
    let drained = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(
            closed.recv_timeout(Duration::from_secs(3)).unwrap(),
            "cancelled"
        );
        assert!(written.is_ok());
        assert_eq!(owner.call.active_native_operations(), 0);
        assert_eq!(
            fs::read(owner.adapter.work.path().join("entered-direct.txt")).unwrap(),
            b"B"
        );
        assert!(
            !task.is_finished(),
            "old worker must still exit before publication"
        );
    }));
    ready.release();
    worker.await.unwrap();
    let result = task.await.unwrap();
    *runtime.native_ready_observer.lock() = None;
    *runtime.native_write_observer.lock() = None;
    *runtime.restore_closed_observer.lock() = None;
    if let Err(error) = before.and(drained) {
        service.shutdown().await.unwrap();
        std::panic::resume_unwind(error);
    }
    let result = result.unwrap();
    assert_eq!(result.source_before, original.expected_source);
    assert!(
        !runtime
            .path
            .join("trees")
            .join(&result.new_branch.head_object_id)
            .join("entered-direct.txt")
            .exists()
    );
    let new_binding = service
        .retained_tool_for_test(&result.new_run_id)
        .unwrap()
        .managed
        .clone()
        .unwrap();
    reject_old_native(
        &owner,
        &runtime,
        &owner.binding.admitted_branch,
        Some(&new_binding.admitted_branch),
    );
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn ready_prepared_tree_and_readonly_receipts_are_not_committed_after_successful_restore() {
    for readonly in [false, true] {
        let (_root, state) = fixture(Duration::from_secs(90));
        let service = state.service();
        let runtime = service.managed_runtime_for_test().unwrap();
        let (_base, _create, checkpoint) = checkpoint_source(&service).await;
        let gate = Arc::new(ReleaseGate {
            released: Mutex::new(false),
            changed: parking_lot::Condvar::new(),
        });
        let wait = gate.clone();
        let (sent, received) = std::sync::mpsc::channel();
        *runtime.before_final_commit.lock() = Some(Arc::new(move |call| {
            sent.send(held(call)).unwrap();
            wait.wait();
        }));
        let tool = if readonly {
            json!({"id":"ready-before-commit","name":"read_file","arguments":{"path":"value.txt"}})
        } else {
            json!({"id":"ready-before-commit","name":"write_file","arguments":{"path":"candidate-only.txt","content":"B"}})
        };
        let run = admit_call(&service, tool).await;
        let worker = tokio::spawn(
            service
                .clone()
                .run_worker(run.run_id.clone(), String::new()),
        );
        let owner = received.recv_timeout(Duration::from_secs(4)).unwrap();
        let witness = owner.call.witness().unwrap();
        assert_eq!(
            owner.binding.branch.state.lock().active,
            0,
            "preparation RAII has left before this real final-commit barrier"
        );
        let original = restore_request(&runtime, &checkpoint);
        let request = original.clone();
        let (sent, closed) = std::sync::mpsc::channel();
        *runtime.restore_closed_observer.lock() = Some(Arc::new(move |stage| {
            sent.send(stage.to_string()).unwrap();
        }));
        let task = tokio::spawn({
            let service = service.clone();
            async move { service.restore_managed_checkpoint_and_admit(request).await }
        });
        let checks = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(
                closed.recv_timeout(Duration::from_secs(3)).unwrap(),
                "closed"
            );
            assert_eq!(
                closed.recv_timeout(Duration::from_secs(3)).unwrap(),
                "cancelled"
            );
            assert!(!task.is_finished());
            assert!(owner.call.outcome.lock().is_none());
        }));
        gate.release();
        worker.await.unwrap();
        let result = task.await.unwrap();
        *runtime.before_final_commit.lock() = None;
        *runtime.restore_closed_observer.lock() = None;
        if let Err(error) = checks {
            service.shutdown().await.unwrap();
            std::panic::resume_unwind(error);
        }
        let result = result.unwrap();
        assert_eq!(result.source_before, original.expected_source);
        assert!(owner.call.outcome.lock().is_none());
        let owner_facts = CapabilityOwner::new(
            "gateway",
            &owner.call.identity.owner.session_id,
            &owner.call.identity.owner.run_id,
        )
        .unwrap();
        assert!(
            owner
                .adapter
                .lifecycle
                .commit(&owner_facts, &owner.adapter.token, witness.original.clone())
                .is_err()
        );
        let read = RunCancellation::with_timeout(Duration::from_secs(5));
        let record = runtime
            .repository
            .get(
                &ManagedEffectGetRequest {
                    owner: owner.binding.owner.clone(),
                    call_id: owner.call.identity.call_id.clone(),
                },
                &read,
            )
            .unwrap()
            .unwrap();
        assert!(record.prepared.is_some());
        assert!(record.outcome.is_none());
        assert!(
            !runtime
                .path
                .join("trees")
                .join(result.new_branch.head_object_id)
                .join("candidate-only.txt")
                .exists()
        );
        service.shutdown().await.unwrap();
    }
}
