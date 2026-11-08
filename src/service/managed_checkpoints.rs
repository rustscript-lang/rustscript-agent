//! Managed checkpoint coordination; public records never carry Native authority.

use super::*;
use crate::effects::journal::*;

fn failure(code: &'static str) -> String {
    code.into()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenSummary {
    count: u64,
    source_start_ordinal: u64,
    source_end_ordinal: u64,
    retained_tail_ordinal: u64,
    text: String,
    truncated: bool,
}

fn validate_frozen_compaction(
    messages: &[ManagedFrozenMessage],
    compaction: Option<&ManagedFrozenCompaction>,
    generation: u64,
) -> Result<(), String> {
    let boundary = if let Some(compaction) = compaction {
        let summary: FrozenSummary = serde_json::from_str(&compaction.summary_json)
            .map_err(|_| "managed_history_incomplete")?;
        if compaction.generation != generation
            || compaction.source_start_ordinal == 0
            || compaction.source_start_ordinal > compaction.source_end_ordinal
            || compaction.source_end_ordinal != compaction.retained_tail_ordinal
            || summary.source_start_ordinal != compaction.source_start_ordinal
            || summary.source_end_ordinal != compaction.source_end_ordinal
            || summary.retained_tail_ordinal != compaction.retained_tail_ordinal
            || summary.count == 0
            || summary.text.is_empty()
            || compaction.source_end_ordinal > messages.last().map_or(0, |m| m.ordinal)
        {
            return Err("managed_history_incomplete".into());
        }
        // A committed extractive summary may already record its producer's truncation.
        // Checkpoint capture never truncates either that summary or its retained tail.
        let _producer_truncated = summary.truncated;
        compaction.retained_tail_ordinal
    } else {
        if generation != 1 {
            return Err("managed_history_incomplete".into());
        }
        0
    };
    for (index, message) in messages.iter().enumerate() {
        if message.ordinal != index as u64 + 1
            || message.compacted != (message.ordinal <= boundary)
            || message.parent_message_id.as_ref().is_some_and(|parent| {
                !parent.is_empty()
                    && !messages.iter().any(|candidate| {
                        candidate.id == *parent && candidate.ordinal < message.ordinal
                    })
            })
        {
            return Err("managed_history_incomplete".into());
        }
    }
    Ok(())
}

/// A package with library dependencies is a supported inventory only when those
/// dependencies are exactly the pure leaves the retained lock already linked.
/// The lock orders its edges by package id, not by the manifest's declaration
/// order, so the match is by identity rather than by position. A dependency's
/// `version` is a semver requirement, not the leaf's resolved version, so it is
/// matched the way graph validation does: `requirement.matches(resolved)`. The
/// edgeless inventory keeps the empty list and its previous behavior.
fn dependencies_match_captured_leaves(
    installed: &crate::plugins::InstalledPackage,
    leaves: &[crate::plugins::InstalledPackage],
) -> bool {
    let dependencies = &installed.manifest.dependencies;
    if dependencies.len() != leaves.len() {
        return false;
    }
    let mut unmatched: Vec<&crate::plugins::InstalledPackage> = leaves.iter().collect();
    for dependency in dependencies {
        let Ok(requirement) = semver::VersionReq::parse(&dependency.version) else {
            return false;
        };
        let Some(index) = unmatched.iter().position(|leaf| {
            leaf.manifest.id == dependency.id
                && leaf.manifest.kind == "library"
                && semver::Version::parse(&leaf.manifest.version)
                    .is_ok_and(|resolved| requirement.matches(&resolved))
        }) else {
            return false;
        };
        unmatched.remove(index);
    }
    unmatched.is_empty()
}

pub(super) fn validate_captured_inventory(
    installed: &crate::plugins::InstalledPackage,
    code: &ManagedCodeIdentity,
    leaves: &[crate::plugins::InstalledPackage],
) -> Result<(), String> {
    let embedding = code.package_id == crate::runtime::native_tools::EMBEDDING_PACKAGE_ID;
    let trust_ok = match installed.trust {
        crate::plugins::PackageTrust::EmbeddingOwnedBuiltin => embedding,
        crate::plugins::PackageTrust::AcceptedPublisher => {
            !embedding && !code.package_id.is_empty()
        }
        crate::plugins::PackageTrust::DevUnsigned => false,
    };
    if installed.manifest.id != code.package_id
        || !trust_ok
        || !dependencies_match_captured_leaves(installed, leaves)
        || installed.manifest.effects.entries.values().any(|entry| {
            !entry.delegated.is_empty()
                || entry.direct.iter().any(|effect| {
                    !matches!(
                        effect.kind.as_str(),
                        "clock.read" | "process.spawn" | "workspace.fs.read" | "workspace.fs.write"
                    )
                })
        })
    {
        return Err(failure("managed_state_unsupported"));
    }
    Ok(())
}

/// The S2 inventory proof: the captured harness caller keeps its identity and
/// trust, and the lock's single captured callee is the run-scoped package whose
/// root the checkpoint names. Pure-leaf and edgeless tools keep
/// `validate_captured_inventory`; this never widens either of them.
pub(super) fn validate_stateful_captured_inventory(
    caller: &crate::plugins::InstalledPackage,
    code: &ManagedCodeIdentity,
    link: &crate::plugins::SupportedDelegation,
    callee: &crate::plugins::InstalledPackage,
) -> Result<(), String> {
    let embedding = code.package_id == crate::runtime::native_tools::EMBEDDING_PACKAGE_ID;
    if caller.manifest.id != code.package_id
        || embedding
        || caller.trust != crate::plugins::PackageTrust::AcceptedPublisher
        || link.callee_package != callee.manifest.id
        || link.callee_artifact != callee.artifact_id
        || link.callee_state.as_ref() != callee.manifest.state.as_ref()
        || callee
            .manifest
            .state
            .as_ref()
            .is_none_or(|state| state.scope != "run")
    {
        return Err(failure("managed_state_unsupported"));
    }
    Ok(())
}

/// The S1 inventory proof: the captured harness caller keeps its identity,
/// trust and its single dependency requirement, and the locked callee is the
/// stateless read package the checkpoint lock captured. The S1 shape owns no
/// state root, so this never claims state coverage: the checkpoint keeps the
/// shared `StatelessBuiltin` coverage with its exact meaning.
pub(super) fn validate_stateless_captured_inventory(
    caller: &crate::plugins::InstalledPackage,
    code: &ManagedCodeIdentity,
    link: &crate::plugins::SupportedDelegation,
    callee: &crate::plugins::InstalledPackage,
) -> Result<(), String> {
    let embedding = code.package_id == crate::runtime::native_tools::EMBEDDING_PACKAGE_ID;
    let dependency_matches = caller
        .manifest
        .dependencies
        .first()
        .filter(|_| caller.manifest.dependencies.len() == 1)
        .is_some_and(|dependency| {
            dependency.id == link.callee_package
                && semver::Version::parse(&callee.manifest.version).is_ok_and(|version| {
                    semver::VersionReq::parse(&dependency.version)
                        .is_ok_and(|requirement| requirement.matches(&version))
                })
        });
    if caller.manifest.id != code.package_id
        || embedding
        || caller.trust != crate::plugins::PackageTrust::AcceptedPublisher
        || link.callee_state.is_some()
        || link.callee_package != callee.manifest.id
        || link.callee_artifact != callee.artifact_id
        || callee.trust != crate::plugins::PackageTrust::AcceptedPublisher
        || callee.manifest.state.is_some()
        || !callee.manifest.dependencies.is_empty()
        || callee.manifest.capabilities != ["workspace.read".to_string()]
        || !dependency_matches
    {
        return Err(failure("managed_state_unsupported"));
    }
    Ok(())
}

pub(super) struct ManagedMaintenanceAttempt {
    pub(super) claim: Arc<crate::gateway::store::ManagedMaintenanceClaim>,
    _authority: Arc<crate::runtime::rss_runner::WorkspaceAuthority>,
    _original_cancellation: RunCancellation,
    checkpoint: ParkingMutex<
        Option<(
            crate::effects::broker::ManagedBranchFreeze,
            ManagedCheckpointCommitInput,
        )>,
    >,
    pub(super) restore: ParkingMutex<Option<ManagedRestorePublication>>,
    pub(super) envelope: ParkingMutex<Option<ManagedRestoreExecutionEnvelope>>,
    pub(super) published: AtomicBool,
    branch: ParkingMutex<Option<Arc<crate::effects::broker::ManagedRestoreBranch>>>,
}
pub(super) struct ManagedRestorePublication {
    pub(super) envelope: ManagedRestoreExecutionEnvelope,
    pub(super) branch: Arc<crate::effects::broker::ManagedRestoreBranch>,
    pub(super) publish: Box<dyn FnOnce(JsonValue) -> Result<AdmittedRun, AdmitError> + Send>,
}
fn public_failure(code: String, request_id: String) -> ManagedMaintenanceFailure {
    if code == "managed_submitted_unknown" {
        ManagedMaintenanceFailure::SubmittedUnknown {
            receipt_lookup_id: request_id.clone(),
            request_id,
        }
    } else {
        ManagedMaintenanceFailure::Rejected { code }
    }
}

pub(super) struct ManagedRestoreAdmission {
    pub(super) request: ManagedRestoreAndAdmitRequest,
    pub(super) checkpoint: ManagedCheckpointRef,
    pub(super) session_id: String,
    pub(super) messages: Vec<SessionMessage>,
    pub(super) compaction: Option<ManagedFrozenCompaction>,
    pub(super) execution_config: ManagedFrozenExecutionConfig,
    pub(super) registry: ToolRegistrySnapshot,
    pub(super) branch: Arc<crate::effects::broker::ManagedRestoreBranch>,
    pub(super) attempt: Arc<ManagedMaintenanceAttempt>,
    pub(super) authority: Arc<crate::runtime::rss_runner::WorkspaceAuthority>,
    pub(super) management_cancel: RunCancellation,
}

impl ManagedRestoreAdmission {
    pub(super) fn envelope(
        &self,
        run_id: &str,
        deadline_ms: u64,
        admission_pin: ManagedAdmissionPin,
    ) -> Result<ManagedRestoreExecutionEnvelope, AdmitError> {
        let mut after = self.request.expected_source.clone();
        after.epoch = after
            .epoch
            .checked_add(1)
            .ok_or_else(|| AdmitError::Invalid("managed_source_conflict".into()))?;
        after.head_version = after
            .head_version
            .checked_add(1)
            .filter(|version| *version <= i64::MAX as u64)
            .ok_or_else(|| AdmitError::Invalid("managed_source_conflict".into()))?;
        Ok(ManagedRestoreExecutionEnvelope {
            admission_pin,
            request: self.request.clone(),
            original_request_proof: serde_json::to_string(&self.request)
                .map_err(|_| AdmitError::Invalid("managed_metadata_budget_exceeded".into()))?,
            history_root_id: self.checkpoint.history.history_root_id.clone(),
            result: ManagedRestoreAndAdmitResult {
                disposition: ManagedRestoreDisposition::RestoredAndAdmitted,
                receipt_id: self.request.request_id.clone(),
                checkpoint_id: self.checkpoint.checkpoint_id.clone(),
                source_before: self.request.expected_source.clone(),
                source_after: after,
                new_branch: self.branch.target.clone(),
                new_session_id: self.session_id.clone(),
                new_run_id: run_id.into(),
                new_run_deadline_at_ms: deadline_ms,
                graph: self.checkpoint.graph.clone(),
                publication: ManagedCheckpointPublication::ManagedOnly,
                external_effects_not_reverted: self
                    .checkpoint
                    .external_boundary
                    .not_reverted
                    .clone(),
                replayed: false,
            },
        })
    }
    pub(super) fn check(&self) -> Result<(), AdmitError> {
        self.authority
            .check()
            .map_err(|_| AdmitError::Invalid("managed_authority_required".into()))?;
        if self.management_cancel.deadline_passed() || self.management_cancel.requested().is_some()
        {
            return Err(AdmitError::Invalid("managed_deadline_elapsed".into()));
        }
        Ok(())
    }
}

impl AgentService {
    pub(crate) fn start_managed_restore_worker(self: &Arc<Self>, run_id: &str) -> bool {
        let Some(handle) = self.handle(run_id) else {
            return false;
        };
        if handle.terminal.load(Ordering::Acquire) {
            return false;
        }
        let Some(started) = handle.restore_worker_started.as_ref() else {
            return false;
        };
        if started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let service = self.clone();
        let run_id = run_id.to_owned();
        tokio::spawn(async move {
            service.run_worker(run_id, String::new()).await;
        });
        true
    }
    pub(crate) fn managed_provider_enter(
        &self,
        run_id: &str,
    ) -> Result<Option<crate::effects::broker::ManagedProviderEntry>, String> {
        self.handle(run_id)
            .and_then(|handle| {
                handle
                    .pinned_tool
                    .as_ref()
                    .and_then(|pin| pin.managed.clone())
            })
            .map(|binding| binding.provider_enter())
            .transpose()
    }
    pub async fn restore_managed_checkpoint_and_admit(
        &self,
        request: ManagedRestoreAndAdmitRequest,
    ) -> Result<ManagedRestoreAndAdmitResult, ManagedMaintenanceFailure> {
        let service = self.clone();
        let request_id = request.request_id.clone();
        tokio::task::spawn_blocking(move || service.restore_managed_checkpoint_blocking(request))
            .await
            .map_err(|_| {
                public_failure(failure("managed_storage_unavailable"), request_id.clone())
            })?
            .map_err(|code| public_failure(code, request_id))
    }

    fn restore_managed_checkpoint_blocking(
        &self,
        request: ManagedRestoreAndAdmitRequest,
    ) -> Result<ManagedRestoreAndAdmitResult, String> {
        validate_maintenance_value::<ManagedRestoreAndAdmitRequest>(
            &serde_json::to_value(&request).map_err(|_| "managed_metadata_budget_exceeded")?,
        )?;
        let config = self
            .inner
            .config
            .managed_workspace
            .as_ref()
            .ok_or("managed_authority_required")?;
        if self.inner.config.bearer_token.is_none() || !config.maintenance_policy.restore {
            return Err(failure("managed_management_denied"));
        }
        if !request.cancel_active_source
            || request.input.text.len() > 65536
            || request.expected_source.workspace_id != request.workspace_id
            || request.expected_source.branch_id != request.source_branch_id
            || Uuid::parse_str(&request.request_id).is_err()
            || Uuid::parse_str(&request.checkpoint_id).is_err()
        {
            return Err(failure("managed_source_conflict"));
        }
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(5));
        let (_, authority) = self
            .resolve_workspace_admission(config.source_root.to_str(), None, &cancellation, false)
            .map_err(|_| failure("managed_authority_required"))?;
        let authority = authority.ok_or("managed_authority_required")?;
        let runtime = self
            .inner
            .managed_effects
            .read()
            .clone()
            .ok_or("managed_authority_required")?;
        let attempt = self
            .inner
            .maintenance_attempts
            .lock()
            .get(&request.request_id)
            .cloned();
        if let Some(attempt) = attempt {
            let proof =
                serde_json::to_string(&request).map_err(|_| "managed_metadata_budget_exceeded")?;
            if attempt.claim.action != "restore" || attempt.claim.proof != proof {
                return Err("managed_request_conflict".into());
            }
            runtime
                .authorize_query(&authority, &attempt.claim.identity)
                .map_err(|_| "managed_authority_required")?;
            let _gate = self.inner.commit_gate.lock();
            let mut publication = attempt.restore.lock();
            let Some(pending) = publication.as_ref() else {
                if attempt.published.load(Ordering::Acquire) {
                    let envelope = attempt
                        .envelope
                        .lock()
                        .clone()
                        .ok_or("managed_restore_reconciliation_required")?;
                    let mut receipt = runtime
                        .repository
                        .lookup_restore_receipt_claim(
                            &request,
                            &cancellation,
                            Some(&attempt.claim),
                        )?
                        .ok_or("managed_restore_reconciliation_required")?;
                    if receipt != envelope.result {
                        return Err("managed_restore_reconciliation_required".into());
                    }
                    runtime.repository.branch_publication_history(
                        &attempt.claim,
                        &envelope,
                        &cancellation,
                    )?;
                    attempt
                        .branch
                        .lock()
                        .as_ref()
                        .ok_or("managed_restore_reconciliation_required")?
                        .publish()
                        .map_err(|_| "managed_restore_reconciliation_required")?;
                    self.inner
                        .maintenance_attempts
                        .lock()
                        .remove(&request.request_id);
                    receipt.replayed = true;
                    return Ok(receipt);
                }
                return Err("managed_submitted_unknown".into());
            };
            let Some(mut receipt) = runtime.repository.lookup_restore_receipt_claim(
                &request,
                &cancellation,
                Some(&attempt.claim),
            )?
            else {
                if runtime.repository.restore_rollback_confirmed(
                    &attempt.claim,
                    &pending.envelope,
                    &cancellation,
                )? {
                    pending.branch.confirmed_rollback();
                    publication.take();
                    self.inner
                        .maintenance_attempts
                        .lock()
                        .remove(&request.request_id);
                    return Err("managed_transaction_rolled_back".into());
                }
                return Err("managed_submitted_unknown".into());
            };
            if receipt != pending.envelope.result {
                return Err("managed_restore_reconciliation_required".into());
            }
            let page = runtime.repository.branch_publication_history(
                &attempt.claim,
                &pending.envelope,
                &cancellation,
            )?;
            let pending = publication.take().expect("exact pending publication");
            (pending.publish)(json!({"pin":page.admission_pin,"replayed":false}))
                .map_err(|_| "managed_restore_reconciliation_required")?;
            pending
                .branch
                .publish()
                .map_err(|_| "managed_restore_reconciliation_required")?;
            self.inner
                .maintenance_attempts
                .lock()
                .remove(&request.request_id);
            // This retry publishes the first and only run. Transport must start its worker once.
            receipt.replayed = false;
            return Ok(receipt);
        }
        runtime
            .authorize_workspace_query(
                &authority,
                ADMISSION_SESSION_PROFILE,
                &request.workspace_id,
                &cancellation,
            )
            .map_err(|_| failure("managed_authority_required"))?;
        if let Some(mut receipt) = runtime
            .repository
            .lookup_restore_receipt(&request, &cancellation)?
        {
            receipt.replayed = true;
            return Ok(receipt);
        }
        let lookup = runtime.repository.checkpoint_get(
            &request.workspace_id,
            &request.checkpoint_id,
            &cancellation,
        )?;
        let checkpoint = lookup.checkpoint;
        if checkpoint.source_branch_id != request.source_branch_id
            || checkpoint.source_epoch != request.expected_source.epoch
            || lookup.messages.len() != checkpoint.history.message_count
        {
            return Err(failure("managed_source_conflict"));
        }
        let context = runtime.repository.checkpoint_context(
            &ManagedCheckpointCreateRequest {
                source_run_id: checkpoint.parent_run_id.clone(),
                workspace_id: request.workspace_id.clone(),
                source_branch_id: request.source_branch_id.clone(),
                expected_epoch: request.expected_source.epoch,
                request_id: request.request_id.clone(),
                mode: ManagedCheckpointMode::AtClosedBatch,
            },
            &cancellation,
        )?;
        if context.head.process_lineage_tainted {
            return Err(failure("managed_process_lineage_unsupported"));
        }
        if context.pending_compactions != 0 {
            return Err(failure("managed_history_incomplete"));
        }
        let current = ManagedSourceCas {
            store_id: context.head.store_id.clone(),
            workspace_id: context.head.workspace_id.clone(),
            branch_id: context.head.branch_id.clone(),
            epoch: context.head.epoch,
            head_object_id: context.head.head_object_id.clone(),
            head_version: context.head.head_version,
        };
        if current != request.expected_source {
            return Err(failure("managed_source_conflict"));
        }
        let handle = self
            .handle(&checkpoint.parent_run_id)
            .ok_or("managed_state_unsupported")?;
        let binding = handle
            .pinned_tool
            .as_ref()
            .and_then(|pin| pin.managed.as_ref())
            .ok_or("managed_state_unsupported")?;
        let registry = binding.captured_registry();
        if registry.identity() != checkpoint.graph.registry_identity {
            return Err(failure("managed_graph_unsupported"));
        }
        let session_id = Uuid::new_v4().to_string();
        validate_frozen_compaction(
            &lookup.messages,
            lookup.compaction.as_ref(),
            checkpoint.history.session_generation,
        )?;
        let mut messages = Vec::new();
        for message in &lookup.messages {
            let parent = message
                .parent_message_id
                .as_ref()
                .filter(|parent| !parent.is_empty())
                .map(|parent| {
                    lookup
                        .messages
                        .iter()
                        .find(|candidate| &candidate.id == parent)
                        .map(|candidate| format!("restored-{session_id}-{}", candidate.ordinal))
                        .ok_or("managed_history_incomplete")
                })
                .transpose()?;
            messages.push(SessionMessage {
                id: format!("restored-{session_id}-{}", message.ordinal), session_id: session_id.clone(),
                role: message.role.clone(), content: serde_json::from_str(&message.content_json).map_err(|_| "managed_history_incomplete")?,
                created_at: message.created_at_ms, run_id: None, finish_reason: message.finish_reason.clone(),
                name: message.name.clone(), tool_call_id: message.tool_call_id.clone(), parent_message_id: parent,
                token_estimate: message.token_estimate,
                metadata: json!({"origin":{"checkpoint_id":checkpoint.checkpoint_id,"source_message_id":message.id}}),
                ordinal: Some(message.ordinal as i64),
            });
        }
        let branch = {
            let _gate = self.inner.commit_gate.lock();
            let source_runs: Vec<String> = context
                .source_runs
                .iter()
                .map(|source| source.run_id.clone())
                .collect();
            runtime.prepare_restore_branch_for_runs(
                &authority,
                &context.workspace.identity,
                &request.expected_source,
                &checkpoint.frozen_root,
                &source_runs,
            )?
        };
        if context.source_runs.len() > 128 {
            return Err(failure("managed_restore_busy"));
        }
        // Close Native resources before cancelling the original owners.
        runtime.settle_restore_source(&branch, &cancellation)?;
        let mut source_handles = Vec::new();
        for source_run in &context.source_runs {
            if !matches!(
                source_run.status.as_str(),
                "completed" | "failed" | "cancelled"
            ) {
                let handle = self
                    .handle(&source_run.run_id)
                    .ok_or("managed_restore_busy")?;
                source_handles.push((source_run.run_id.clone(), handle));
            }
        }
        for (_, handle) in &source_handles {
            handle.request_user_stop();
        }
        #[cfg(test)]
        runtime.observe_restore_cancelled();
        let mut deadline = cancellation
            .deadline_instant()
            .ok_or("managed_deadline_elapsed")?;
        for (_, handle) in &source_handles {
            deadline = deadline.min(
                handle
                    .cancel
                    .deadline_instant()
                    .ok_or("managed_deadline_elapsed")?,
            );
        }
        for (run_id, handle) in &source_handles {
            if !handle.occupancy.load(Ordering::Acquire) && !handle.terminal.load(Ordering::Acquire)
            {
                tokio::runtime::Handle::current()
                    .block_on(self.finish_cancelled(run_id, "requested"));
            }
            while handle.occupancy.load(Ordering::Acquire) {
                if Instant::now() >= deadline {
                    return Err(failure("managed_restore_busy"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            if !handle.terminal.load(Ordering::Acquire)
                || *handle.cleanup_outcome.lock().expect("cleanup outcome lock")
                    != Some(CleanupOutcome::Clean)
            {
                return Err(failure("managed_restore_busy"));
            }
            // Restore consumes the managed cleanup owner itself, after the
            // source run is terminal. A run that cannot prove reap/drain/
            // stdin quiescence keeps its handles, view and writer and blocks
            // restore publication.
            if let Some(binding) = self.handle(run_id).and_then(|handle| {
                handle
                    .pinned_tool
                    .as_ref()
                    .and_then(|pin| pin.managed.clone())
            }) {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let mut cleanup = binding.cleanup_run(remaining);
                if cleanup != crate::effects::broker::ManagedCleanup::Quiescent {
                    // The cancelled source worker may still be disposing the
                    // finalizing publication claim it reserved before the stop.
                    // Wait for the writer gate to drain, then let the same
                    // idempotent cleanup consume the proven-quiescent view.
                    runtime.wait_restore_source_idle(&branch, &cancellation)?;
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    cleanup = binding.cleanup_run(remaining);
                }
                if cleanup != crate::effects::broker::ManagedCleanup::Quiescent {
                    return Err(failure("managed_restore_busy"));
                }
            }
        }
        if Instant::now() >= deadline || cancellation.requested().is_some() {
            return Err(failure("managed_restore_busy"));
        }
        // Subscriber/call occupancy can reach zero before the cancelled
        // worker's terminal fence releases the branch writer. Publication
        // requires the writer genuinely Idle, so wait for that same bounded
        // event instead of detaching a still-reserved view.
        runtime.wait_restore_source_idle(&branch, &cancellation)?;
        let permit = self
            .inner
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| "managed_restore_busy")?;
        let input = request.input.text.clone();
        let request_id = request.request_id.clone();
        let proof =
            serde_json::to_string(&request).map_err(|_| "managed_metadata_budget_exceeded")?;
        let claim = runtime.repository.maintenance_claim(
            context.workspace.identity.clone(),
            proof,
            request_id.clone(),
            "restore",
        )?;
        let branch = Arc::new(branch);
        let attempt = Arc::new(ManagedMaintenanceAttempt {
            claim,
            _authority: authority.clone(),
            _original_cancellation: cancellation.clone(),
            checkpoint: ParkingMutex::new(None),
            restore: ParkingMutex::new(None),
            envelope: ParkingMutex::new(None),
            published: AtomicBool::new(false),
            branch: ParkingMutex::new(Some(branch.clone())),
        });
        let origin = ManagedRestoreAdmission {
            request,
            checkpoint,
            session_id,
            messages,
            compaction: lookup.compaction,
            execution_config: lookup.execution_config,
            registry,
            branch,
            attempt: attempt.clone(),
            authority,
            management_cancel: cancellation.clone(),
        };
        self.inner
            .maintenance_attempts
            .lock()
            .insert(request_id.clone(), attempt.clone());
        let admitted = self.admit_blocking_from(
            AdmitRunRequest {
                input: json!({"message":input}),
                model: Some(origin.checkpoint.public_config.config.model.clone()),
                provider: origin.checkpoint.public_config.config.provider.clone(),
                instructions: origin
                    .checkpoint
                    .public_config
                    .config
                    .system_instructions
                    .clone(),
                platform: "api_server".into(),
                ..Default::default()
            },
            Some(config.source_root.to_string_lossy().into_owned()),
            false,
            permit,
            Some(&origin),
        );
        if matches!(&admitted,Err(AdmitError::Persistence(code)) if code == "managed_submitted_unknown")
        {
            origin.branch.submitted_unknown();
            return Err("managed_submitted_unknown".into());
        }
        if admitted.is_err() {
            self.inner.maintenance_attempts.lock().remove(&request_id);
            if matches!(&admitted, Err(AdmitError::PluginArtifactUnavailable)) {
                return Err(failure("plugin_artifact_unavailable"));
            }
            if matches!(&admitted, Err(AdmitError::PluginGraphRevoked)) {
                return Err(failure("plugin_graph_revoked"));
            }
            if matches!(&admitted, Err(AdmitError::PluginGraphPinRequired)) {
                return Err(failure("plugin_graph_pin_required"));
            }
            if matches!(
                &admitted,
                Err(AdmitError::HarnessPolicy(
                    "harness_policy_selection_invalid"
                ))
            ) {
                return Err(failure("harness_policy_selection_invalid"));
            }
            if matches!(&admitted, Err(AdmitError::Invalid(code)) if code == "managed_metadata_budget_exceeded")
            {
                return Err(failure("managed_metadata_budget_exceeded"));
            }
            return Err(failure("managed_storage_unavailable"));
        }
        let read_cancel = RunCancellation::with_timeout(Duration::from_secs(5));
        let _publication_gate = self.inner.commit_gate.lock();
        let receipt = runtime
            .repository
            .lookup_restore_receipt_claim(&origin.request, &read_cancel, Some(&attempt.claim))?
            .ok_or("managed_submitted_unknown")?;
        let envelope = attempt
            .envelope
            .lock()
            .clone()
            .ok_or("managed_restore_reconciliation_required")?;
        if receipt != envelope.result {
            return Err("managed_restore_reconciliation_required".into());
        }
        runtime
            .repository
            .branch_publication_history(&attempt.claim, &envelope, &read_cancel)?;
        origin
            .branch
            .publish()
            .map_err(|_| "managed_restore_reconciliation_required")?;
        self.inner.maintenance_attempts.lock().remove(&request_id);
        Ok(receipt)
    }

    pub async fn create_managed_checkpoint(
        &self,
        request: ManagedCheckpointCreateRequest,
    ) -> Result<ManagedCheckpointReceipt, ManagedMaintenanceFailure> {
        let service = self.clone();
        let request_id = request.request_id.clone();
        tokio::task::spawn_blocking(move || service.create_managed_checkpoint_blocking(request))
            .await
            .map_err(|_| {
                public_failure(failure("managed_storage_unavailable"), request_id.clone())
            })?
            .map_err(|code| public_failure(code, request_id))
    }

    fn create_managed_checkpoint_blocking(
        &self,
        request: ManagedCheckpointCreateRequest,
    ) -> Result<ManagedCheckpointReceipt, String> {
        let config = self
            .inner
            .config
            .managed_workspace
            .as_ref()
            .ok_or("managed_authority_required")?;
        if self.inner.config.bearer_token.is_none() || !config.maintenance_policy.create_checkpoint
        {
            return Err(failure("managed_management_denied"));
        }
        crate::effects::broker::validate_id("ws", &request.workspace_id)
            .map_err(|_| failure("managed_authority_required"))?;
        if let Some(binding) = self
            .handle(&request.source_run_id)
            .as_ref()
            .and_then(|handle| handle.pinned_tool.as_ref())
            .and_then(|pin| pin.managed.as_ref())
            && binding.workspace.identity.workspace_id == request.workspace_id
            && binding.admitted_branch.branch_id != request.source_branch_id
        {
            return Err(failure("managed_checkpoint_conflict"));
        }
        crate::effects::broker::validate_id("br", &request.source_branch_id)
            .map_err(|_| failure("managed_authority_required"))?;
        if Uuid::parse_str(&request.source_run_id).is_err()
            || Uuid::parse_str(&request.request_id).is_err()
            || request.expected_epoch == 0
        {
            return Err(failure("managed_source_conflict"));
        }
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(5));
        let runtime = self
            .inner
            .managed_effects
            .read()
            .clone()
            .ok_or("managed_authority_required")?;
        let source = config
            .source_root
            .to_str()
            .ok_or("managed_authority_required")?;
        // An independent owner is issued by the existing restricted admission.
        let (_, authority) = self
            .resolve_workspace_admission(Some(source), None, &cancellation, false)
            .map_err(|_| failure("managed_authority_required"))?;
        let authority = authority.ok_or("managed_authority_required")?;
        let attempt = self
            .inner
            .maintenance_attempts
            .lock()
            .get(&request.request_id)
            .cloned();
        if let Some(attempt) = attempt {
            let proof =
                serde_json::to_string(&request).map_err(|_| "managed_metadata_budget_exceeded")?;
            if attempt.claim.action != "checkpoint" || attempt.claim.proof != proof {
                return Err("managed_request_conflict".into());
            }
            runtime
                .authorize_query(&authority, &attempt.claim.identity)
                .map_err(|_| "managed_authority_required")?;
            let _gate = self.inner.commit_gate.lock();
            let mut state = attempt.checkpoint.lock();
            if let Some(mut receipt) = runtime.repository.checkpoint_receipt(
                &request,
                &cancellation,
                Some(&attempt.claim),
            )? {
                if let Some((_, input)) = state.as_ref()
                    && receipt != input.receipt
                {
                    return Err("managed_restore_reconciliation_required".into());
                }
                state.take();
                self.inner
                    .maintenance_attempts
                    .lock()
                    .remove(&request.request_id);
                receipt.replayed = true;
                return Ok(receipt);
            }
            if let Some((_, input)) = state.as_ref()
                && runtime.repository.checkpoint_rollback_confirmed(
                    &attempt.claim,
                    input,
                    &cancellation,
                )?
            {
                state.take();
                self.inner
                    .maintenance_attempts
                    .lock()
                    .remove(&request.request_id);
                return Err("managed_transaction_rolled_back".into());
            }
            return Err("managed_submitted_unknown".into());
        }
        runtime
            .authorize_workspace_query(
                &authority,
                ADMISSION_SESSION_PROFILE,
                &request.workspace_id,
                &cancellation,
            )
            .map_err(|_| failure("managed_authority_required"))?;
        if let Some(mut receipt) =
            runtime
                .repository
                .checkpoint_receipt(&request, &cancellation, None)?
        {
            receipt.replayed = true;
            return Ok(receipt);
        }
        let context = runtime
            .repository
            .checkpoint_context(&request, &cancellation)?;
        runtime
            .authorize_query(&authority, &context.workspace.identity)
            .map_err(|_| failure("managed_authority_required"))?;
        if context.head.epoch != request.expected_epoch
            || context.head.branch_id != request.source_branch_id
            || context.head.workspace_id != request.workspace_id
        {
            return Err(failure("managed_source_conflict"));
        }
        if context.head.process_lineage_tainted {
            return Err(failure("managed_process_lineage_unsupported"));
        }
        let closed_batch = request.mode == ManagedCheckpointMode::AtClosedBatch
            && !context.effects.is_empty()
            && context.effects.iter().all(|effect| {
                effect.outcome.is_some()
                    && matches!(
                        effect.state,
                        ManagedPublicationStatus::Committed | ManagedPublicationStatus::ReadOnly
                    )
            });
        let _pause = {
            let _gate = self.inner.commit_gate.lock();
            runtime.begin_checkpoint_pause(&context.workspace.identity, context.head.epoch)?
        };
        if closed_batch {
            _pause.wait_closed_batch(&cancellation)?;
        } else {
            _pause.wait_frozen(&cancellation)?;
        }
        let context = runtime
            .repository
            .checkpoint_context(&request, &cancellation)?;
        if context.pending_compactions != 0 {
            return Err(failure("managed_history_incomplete"));
        }
        validate_frozen_compaction(
            &context.messages,
            context.compaction.as_ref(),
            context.session_generation,
        )?;
        if context.messages.is_empty()
            || context.messages.len() > 128
            || context.effects.len() > 128
            || context.external.len() > 32
        {
            return Err(failure("managed_history_budget_exceeded"));
        }
        let history_bytes = serde_json::to_vec(&(&context.messages, &context.compaction))
            .map_err(|_| failure("managed_metadata_budget_exceeded"))?
            .len();
        if history_bytes > 512 * 1024 {
            return Err(failure("managed_history_budget_exceeded"));
        }
        let handle = self
            .handle(&request.source_run_id)
            .ok_or("managed_state_unsupported")?;
        let binding = handle
            .pinned_tool
            .as_ref()
            .and_then(|pin| pin.managed.as_ref())
            .ok_or("managed_state_unsupported")?;
        let code = binding.code.clone();
        if binding.owner.session_id != context.session_id
            || binding.workspace.identity != context.workspace.identity
        {
            return Err(failure("managed_authority_required"));
        }
        self.check_harness_run(&request.source_run_id, &cancellation)
            .map_err(str::to_string)?;
        let selected = handle
            .pinned_tool
            .as_ref()
            .ok_or("managed_state_unsupported")?
            .harness_selection
            .clone();
        let packages = self.tool_store().ok_or("plugin_artifact_unavailable")?;
        let installed = packages
            .read_installed(&code.artifact_id)
            .map_err(|_| failure("plugin_artifact_unavailable"))?;
        // A tool that imports pure leaves names its lock's captured leaves; the
        // edgeless inventory has no dependencies and keeps its empty evidence.
        // The admitted S2 link instead names its single run-scoped callee, which
        // owns the state this checkpoint covers, and the admitted S1 link names
        // its single stateless callee, which owns no state root at all.
        let (leaves, stateless_callee, stateful_callee) =
            if installed.manifest.dependencies.is_empty() {
                (Vec::new(), None, None)
            } else {
                let persistence = self
                    .inner
                    .persistence
                    .clone()
                    .ok_or("managed_state_unsupported")?;
                let lock = crate::plugins::PluginControlStore::new(&persistence)
                    .load_lock(&code.graph_id)
                    .map_err(|_| failure("managed_state_unsupported"))?
                    .lock;
                if lock.graph_id != code.graph_id {
                    return Err(failure("managed_state_unsupported"));
                }
                match crate::plugins::verified_stateful_callee(packages.as_ref(), &lock, &installed)
                    .map_err(|_| failure("managed_state_unsupported"))?
                {
                    Some(found) => (Vec::new(), None, Some(found)),
                    None => {
                        match crate::plugins::verified_stateless_callee(
                            packages.as_ref(),
                            &lock,
                            &installed,
                        )
                        .map_err(|_| failure("managed_state_unsupported"))?
                        {
                            Some(found) => (Vec::new(), Some(found), None),
                            None => (
                                crate::plugins::verified_pure_leaves(
                                    packages.as_ref(),
                                    &lock,
                                    &installed,
                                )
                                .map_err(|_| failure("managed_state_unsupported"))?,
                                None,
                                None,
                            ),
                        }
                    }
                }
            };
        match (&stateful_callee, &stateless_callee) {
            (Some((link, callee)), _) => {
                validate_stateful_captured_inventory(&installed, &code, link, callee)?
            }
            (None, Some((link, callee))) => {
                validate_stateless_captured_inventory(&installed, &code, link, callee)?
            }
            (None, None) => validate_captured_inventory(&installed, &code, &leaves)?,
        }
        let run_context = self
            .run_context(&request.source_run_id)
            .ok_or("managed_state_unsupported")?;
        verify_context_metadata(&run_context).map_err(|_| "managed_state_unsupported")?;
        if run_context.metadata.as_object().is_none_or(|fields| {
            fields.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "schema_version"
                        | "run_id"
                        | "session_id"
                        | "registry_identity"
                        | "toolset_hash"
                        | "approval_settings"
                        | "provider_profile"
                        | "message_id"
                        | "created_at_ms"
                        | "deadline_at_ms"
                        | "admitted_workspace_binding"
                )
            })
        }) || run_context.limits.as_object().is_none_or(|fields| {
            fields.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "max_turns"
                        | "max_tool_calls"
                        | "max_tool_output_bytes"
                        | "workspace_root"
                        | "max_events"
                        | "max_event_bytes"
                        | "timeout_ms"
                )
            })
        }) || run_context.tool_schemas != binding.captured_registry().schemas()
        {
            return Err(failure("managed_state_unsupported"));
        }
        let profile_name = run_context.metadata["provider_profile"]
            .as_str()
            .ok_or("managed_state_unsupported")?;
        let profile = ProviderProfile::new(profile_name, run_context.provider_options.clone())
            .map_err(|_| "managed_state_unsupported")?;
        let execution_config = ManagedFrozenExecutionConfig {
            provider_profile: profile.name.clone(),
            provider_options: serde_json::from_value(profile.options().clone())
                .map_err(|_| "managed_state_unsupported")?,
        };
        let mut outputs = Vec::new();
        let mut parents = HashMap::new();
        for (index, message) in context.messages.iter().enumerate() {
            if message.ordinal != index as u64 + 1 {
                return Err(failure("managed_history_incomplete"));
            }
            let content: JsonValue = serde_json::from_str(&message.content_json)
                .map_err(|_| failure("managed_history_incomplete"))?;
            for block in content.as_array().ok_or("managed_history_incomplete")? {
                if block["type"] == "tool_call" {
                    let call = block["tool_call_id"]
                        .as_str()
                        .ok_or("managed_history_incomplete")?;
                    if parents
                        .insert(call.to_string(), message.id.clone())
                        .is_some()
                    {
                        return Err(failure("managed_history_incomplete"));
                    }
                }
            }
        }
        for effect in &context.effects {
            let outcome = effect
                .outcome
                .as_ref()
                .ok_or("managed_history_incomplete")?;
            let prepared = effect
                .prepared
                .as_ref()
                .ok_or("managed_history_incomplete")?;
            let output = context
                .messages
                .iter()
                .find(|message| message.id == outcome.message.id)
                .ok_or("managed_history_incomplete")?;
            let parent = parents
                .remove(&effect.identity.call_id)
                .ok_or("managed_history_incomplete")?;
            if output.parent_message_id.as_deref() != Some(&parent)
                || output.tool_call_id.as_deref() != Some(&effect.identity.call_id)
            {
                return Err(failure("managed_history_incomplete"));
            }
            let result = runtime
                .read_result(&outcome.canonical_result_ref)
                .map_err(|_| failure("managed_artifact_unavailable"))?;
            if result["artifacts"]
                .as_array()
                .is_some_and(|artifacts| !artifacts.is_empty())
            {
                return Err(failure("managed_artifact_unavailable"));
            }
            outputs.push(ManagedClosedOutputRef {
                run_id: effect.identity.owner.run_id.clone(),
                call_id: effect.identity.call_id.clone(),
                parent_message_id: parent,
                output_message_id: output.id.clone(),
                receipt_id: prepared.effect_id.clone(),
                result: outcome.canonical_result_ref.clone(),
            });
        }
        if !parents.is_empty() {
            return Err(failure("managed_history_incomplete"));
        }
        let frozen_root = runtime
            .repository
            .object_metadata(
                &ManagedObjectReferencesRequest {
                    store_id: context.head.store_id.clone(),
                    object_id: context.head.head_object_id.clone(),
                },
                &cancellation,
            )?
            .ok_or("managed_artifact_unavailable")?;
        runtime
            .verify_tree(&frozen_root.object_id)
            .map_err(|_| failure("managed_artifact_unavailable"))?;
        let state_declaration = installed.manifest.state.as_ref();
        // S2 keeps the caller stateless: the locked callee declares the run
        // scope this checkpoint covers, so the durable owner is the callee.
        let callee_state = stateful_callee
            .as_ref()
            .and_then(|(link, _)| link.callee_state.as_ref());
        let checkpoint_state = state_declaration.or(callee_state);
        let stateful = checkpoint_state.is_some();
        let invocation_stateful =
            state_declaration.is_some_and(|state| state.scope == "invocation");
        if stateful
            && !invocation_stateful
            && !matches!(
                checkpoint_state.map(|state| state.scope.as_str()),
                Some("run" | "session")
            )
        {
            return Err(failure("managed_state_unsupported"));
        }
        let state_binding = handle
            .pinned_tool
            .as_ref()
            .and_then(|pin| pin.state_binding.as_ref());
        // A stateful caller owns the writer lease this checkpoint freezes. The
        // S2 callee's writer is not addressable from the caller pin, and its
        // run root is only read after the closed batch.
        if stateful && !invocation_stateful && callee_state.is_none() && state_binding.is_none() {
            return Err(failure("managed_plugin_state_unavailable"));
        }
        let _state_freeze = if stateful && !invocation_stateful && callee_state.is_none() {
            let state_store = self
                .inner
                .persistence
                .as_ref()
                .map(|persistence| crate::plugins::PluginStateStore::open(Arc::clone(persistence)))
                .ok_or_else(|| failure("managed_plugin_state_unavailable"))?;
            Some(
                state_store
                    .freeze_writer(
                        state_binding.ok_or("managed_plugin_state_unavailable")?,
                        &cancellation,
                    )
                    .map_err(|_| failure("managed_checkpoint_busy"))?,
            )
        } else {
            None
        };
        let state_roots = self
            .inner
            .persistence
            .as_ref()
            .map(|persistence| {
                crate::plugins::PluginStateStore::open(Arc::clone(persistence))
                    .checkpoint_roots(&request.source_run_id)
            })
            .transpose()
            .map_err(|_| failure("managed_plugin_state_unavailable"))?
            .unwrap_or_default();
        if stateful && !invocation_stateful && state_roots.is_empty() {
            return Err(failure("managed_plugin_state_unavailable"));
        }
        if !stateful && !state_roots.is_empty() {
            return Err(failure("managed_plugin_state_unavailable"));
        }
        if invocation_stateful && !state_roots.is_empty() {
            return Err(failure("managed_plugin_state_unavailable"));
        }
        // The S2 checkpoint covers exactly the locked callee's one run root: the
        // caller stays stateless, so a root naming any other package is refused.
        let state_owner = match &stateful_callee {
            Some((_, callee)) => {
                let schema = callee
                    .manifest
                    .state
                    .as_ref()
                    .and_then(|state| u32::try_from(state.schema).ok());
                if state_roots.len() != 1
                    || state_roots.iter().any(|root| {
                        root.owner_kind != "run"
                            || root.plugin_id != callee.manifest.id
                            || root.package_id != callee.manifest.id
                            || root.artifact_id != callee.artifact_id
                            || Some(root.schema) != schema
                    })
                {
                    return Err(failure("managed_plugin_state_unavailable"));
                }
                (callee.manifest.id.clone(), callee.artifact_id.clone())
            }
            None => (code.package_id.clone(), code.artifact_id.clone()),
        };
        let plugin_state_coverage = if stateful {
            ManagedCheckpointStateCoverage::Stateful {
                graph_id: code.graph_id.clone(),
                package_id: state_owner.0,
                artifact_id: state_owner.1,
                manifest_state_present: true,
                invocation_excluded_from_checkpoint: invocation_stateful,
                roots: state_roots
                    .into_iter()
                    .map(|root| {
                        let scope = match root.owner_kind.as_str() {
                            "run" => "run".to_string(),
                            _ => "session".to_string(),
                        };
                        ManagedPluginStateRootRef {
                            owner_kind: root.owner_kind,
                            owner_id: root.owner_id,
                            workspace_id: root.workspace_id,
                            branch_id: root.branch_id,
                            plugin_id: root.plugin_id,
                            package_id: root.package_id,
                            artifact_id: root.artifact_id,
                            scope,
                            schema: root.schema.to_string(),
                            revision: root.revision,
                            immutable_root_id: root.object_id,
                        }
                    })
                    .collect(),
            }
        } else {
            match &selected {
                crate::plugins::HarnessSelection::ContextPrompt { policy, .. } => {
                    ManagedCheckpointStateCoverage::StatelessBuiltinWithPurePolicy {
                        graph_id: code.graph_id.clone(),
                        package_id: code.package_id.clone(),
                        artifact_id: code.artifact_id.clone(),
                        policy: policy.clone(),
                        manifest_state_absent: true,
                        state_effects_absent: true,
                        policy_host_imports_absent: true,
                        roots: vec![],
                    }
                }
                _ => ManagedCheckpointStateCoverage::StatelessBuiltin {
                    graph_id: code.graph_id.clone(),
                    package_id: code.package_id.clone(),
                    artifact_id: code.artifact_id.clone(),
                    manifest_state_absent: true,
                    state_effects_absent: true,
                    roots: vec![],
                },
            }
        };
        let policy_revision: String = if invocation_stateful {
            "stateful_invocation_ephemeral".into()
        } else if stateful {
            if checkpoint_state.map(|state| state.scope.as_str()) == Some("run") {
                "stateful_run".into()
            } else {
                "stateful_session".into()
            }
        } else {
            match &selected {
                crate::plugins::HarnessSelection::ContextPrompt { .. } => {
                    "stateless_builtin_with_pure_policy".into()
                }
                _ => "stateless_builtin".into(),
            }
        };
        let checkpoint_id = Uuid::new_v4().to_string();
        let last = context
            .messages
            .last()
            .ok_or("managed_history_incomplete")?;
        let receipt = ManagedCheckpointReceipt {
            request_id: request.request_id.clone(),
            checkpoint: ManagedCheckpointRef {
                checkpoint_id: checkpoint_id.clone(),
                workspace_id: request.workspace_id.clone(),
                parent_run_id: request.source_run_id.clone(),
                source_branch_id: request.source_branch_id.clone(),
                source_epoch: context.head.epoch,
                frozen_root,
                history: ManagedFrozenHistoryRef {
                    history_root_id: Uuid::new_v4().to_string(),
                    source_session_id: context.session_id.clone(),
                    session_generation: context.session_generation,
                    last_message_id: last.id.clone(),
                    last_ordinal: context.last_ordinal,
                    last_closed_batch_id: outputs
                        .last()
                        .map(|output| output.parent_message_id.clone())
                        .unwrap_or_else(|| last.id.clone()),
                    message_count: context.messages.len(),
                    byte_count: history_bytes,
                    closed_output_refs: outputs,
                },
                graph: ManagedCheckpointGraphRef {
                    graph_id: code.graph_id.clone(),
                    harness_selection: selected.clone(),
                    checkpoint_graph_ref_id: Uuid::new_v4().to_string(),
                    captured_activation_generation: code.activation_generation,
                    package_id: code.package_id.clone(),
                    artifact_id: code.artifact_id.clone(),
                    export: code.export.clone(),
                    registry_identity: code.registry_identity.clone(),
                    effect_contract_version: code.effect_contract_version,
                },
                public_config: ManagedPublicConfigRef {
                    config_ref_id: Uuid::new_v4().to_string(),
                    config: ManagedCheckpointPublicConfig {
                        model: run_context.model,
                        provider: run_context.provider,
                        system_instructions: run_context.system_prompt,
                        registry_identity: code.registry_identity.clone(),
                        tool_schemas_ref: code.artifact_id.clone(),
                        policy_revision: policy_revision.clone(),
                        publication_policy: ManagedCheckpointPublication::ManagedOnly,
                    },
                },
                plugin_state: plugin_state_coverage,
                external_boundary: ManagedExternalBoundary {
                    high_water: context.external,
                    not_reverted: vec![
                        ManagedExternalNotice::ProviderUsageNotReverted,
                        ManagedExternalNotice::DeliveredContentNotReverted,
                    ],
                    artifact_refs: Vec::new(),
                },
            },
            committed_at_ms: timestamp(),
            replayed: false,
        };
        let original_request_proof = serde_json::to_string(&request)
            .map_err(|_| failure("managed_metadata_budget_exceeded"))?;
        let input = ManagedCheckpointCommitInput {
            request,
            original_request_proof,
            captured_source: ManagedSourceCas {
                store_id: context.head.store_id,
                workspace_id: context.head.workspace_id,
                branch_id: context.head.branch_id,
                epoch: context.head.epoch,
                head_object_id: context.head.head_object_id,
                head_version: context.head.head_version,
            },
            receipt,
            messages: context.messages,
            compaction: context.compaction,
            execution_config,
        };
        let _gate = self.inner.commit_gate.lock();
        authority
            .check()
            .map_err(|_| failure("managed_authority_required"))?;
        if cancellation.deadline_passed() || cancellation.requested().is_some() {
            return Err(failure("managed_deadline_elapsed"));
        }
        let request_id = input.request.request_id.clone();
        let claim = runtime.repository.maintenance_claim(
            context.workspace.identity.clone(),
            input.original_request_proof.clone(),
            request_id.clone(),
            "checkpoint",
        )?;
        let attempt = Arc::new(ManagedMaintenanceAttempt {
            claim: claim.clone(),
            _authority: authority,
            _original_cancellation: cancellation.clone(),
            checkpoint: ParkingMutex::new(Some((_pause, input))),
            restore: ParkingMutex::new(None),
            envelope: ParkingMutex::new(None),
            published: AtomicBool::new(false),
            branch: ParkingMutex::new(None),
        });
        self.inner
            .maintenance_attempts
            .lock()
            .insert(request_id.clone(), attempt.clone());
        let outcome = runtime.repository.checkpoint_submit(
            &attempt
                .checkpoint
                .lock()
                .as_ref()
                .expect("prepared checkpoint")
                .1,
            &cancellation,
            &claim,
        );
        if !matches!(&outcome,Err(code) if code == "managed_submitted_unknown") {
            attempt.checkpoint.lock().take();
            self.inner.maintenance_attempts.lock().remove(&request_id);
        }
        outcome
    }
}
