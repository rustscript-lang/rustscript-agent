//! Required workspace publication completion.
//!
//! One frozen completion request: the Native branch completion reservation,
//! the exact publication proof/head/revision and the terminal events are all
//! captured before the single claimed `run.terminal` send. RSS commits the
//! pointer, receipt, run status, events and message in one transaction; this
//! owner only classifies the already-decided outcome and never emits a second
//! terminal for an unsettled request.

use std::sync::Arc;
use std::time::Instant;

use serde_json::{Value, json};

use super::{
    AgentService, PendingPublication, PendingRetryOutcome, PendingTerminal, SessionMessage,
    TerminalRetryOutcome, TerminalStatus, apply_terminal, decode_message_content, failed_payload,
    handle_cancel_reason, next_message_ordinal, timestamp,
};
use crate::domain::truncate_for_log;
use crate::effects::broker::ManagedRunBinding;
use crate::effects::journal::ManagedPublishRequest;
use crate::gateway::store::{GatewayEvent, GatewayPersistence, RunRecord, SessionRecord};

/// The exact one-shot Native fact faults selected for this completion attempt.
/// Production builds hold the default (all false): the shipped completion
/// contains no substituted expectation and cannot skip any refusal.
#[derive(Clone, Copy, Default)]
struct CompletionFactFaults {
    #[cfg_attr(not(any(test, feature = "workspace-io-fault")), allow(dead_code))]
    stale_authority_generation: bool,
    #[cfg_attr(not(any(test, feature = "workspace-io-fault")), allow(dead_code))]
    stale_binding_epoch: bool,
    #[cfg_attr(not(any(test, feature = "workspace-io-fault")), allow(dead_code))]
    stale_branch_schema: bool,
    observe_tainted_lineage_refusal: bool,
}

/// Take the one exact-run one-shot fact fault. Only the fixture/test seam can
/// arm it; unarmed production builds return the default cheaply.
fn take_completion_fact_fault(
    persistence: &GatewayPersistence,
    run_id: &str,
) -> CompletionFactFaults {
    #[cfg(any(test, feature = "workspace-io-fault"))]
    {
        use crate::gateway::store::ManagedCompletionFactFault as Fault;
        let fault = persistence.take_managed_completion_fact_fault(run_id);
        CompletionFactFaults {
            stale_authority_generation: fault == Some(Fault::AuthorityGeneration),
            stale_binding_epoch: fault == Some(Fault::BindingEpoch),
            stale_branch_schema: fault == Some(Fault::BranchSchema),
            observe_tainted_lineage_refusal: fault == Some(Fault::TaintedLineageRefusal),
        }
    }
    #[cfg(not(any(test, feature = "workspace-io-fault")))]
    {
        let _ = (persistence, run_id);
        CompletionFactFaults::default()
    }
}

/// Outcome of one required-publication completion attempt.
enum PublicationOutcome {
    Committed,
    NotActive,
    SessionMissing,
    /// A deterministic refusal: nothing publication-bearing was committed, so
    /// the run may fail with the matching publication status.
    Rejected {
        code: &'static str,
        status: &'static str,
        message: String,
    },
    /// The send may have been queued: keep the reachable owner and settle the
    /// exact frozen request in order. No competing terminal may be sent.
    Pending {
        error: String,
        pending: Box<PendingTerminal>,
    },
    /// A pre-send failure that provably never queued work; a later bounded
    /// attempt may retry the same frozen completion.
    Retryable {
        error: String,
    },
}

impl AgentService {
    /// Required completion entry used by `finish_completed`. It reuses the
    /// bounded retry shell but hands publication requests to the retained
    /// settlement owner instead of the ordinary terminal commit.
    pub(crate) async fn finish_completed_publication(
        &self,
        run_id: &str,
        session_id: &str,
        output_text: &str,
    ) {
        let attempts = 1 + self.inner.config.terminal_persist_retries;
        // One frozen request identity for the whole completion attempt, so a
        // bounded pre-send retry replays the same request instead of minting a
        // second publication identity.
        let request_id = uuid::Uuid::new_v4().to_string();
        for attempt in 0..attempts {
            match self
                .commit_completed_publication_once(run_id, session_id, output_text, &request_id)
                .await
            {
                PublicationOutcome::Committed => {
                    self.inner.metrics.runs_terminal(TerminalStatus::Completed);
                    self.mark_terminal(run_id);
                    return;
                }
                PublicationOutcome::NotActive => {
                    let reason = self
                        .inner
                        .runs
                        .lock()
                        .expect("runs lock")
                        .get(run_id)
                        .map(|handle| handle_cancel_reason(handle, "requested"))
                        .unwrap_or("requested");
                    self.finish_cancelled(run_id, reason).await;
                    return;
                }
                PublicationOutcome::SessionMissing => {
                    self.finish_failed(run_id, failed_payload("session not found".to_string()))
                        .await;
                    return;
                }
                PublicationOutcome::Rejected {
                    code,
                    status,
                    message,
                } => {
                    self.finish_failed(
                        run_id,
                        json!({
                            "status": "failed",
                            "error_code": code,
                            "error_message": message,
                            "publication": {"status": status, "code": code},
                        }),
                    )
                    .await;
                    return;
                }
                PublicationOutcome::Pending { error, pending } => {
                    // A send that may have queued is never re-sent and never
                    // counted as committed. The one frozen request and its
                    // Native owner go straight to ordered, read-only settlement
                    // on the same FIFO worker.
                    tracing::error!(
                        run_id,
                        error = %truncate_for_log(&error, 256),
                        "required publication completion outcome unknown; retaining the Native owner for ordered settlement"
                    );
                    self.register_pending_terminal(run_id, *pending);
                    self.mark_terminal(run_id);
                    self.spawn_terminal_retry(run_id.to_string());
                    return;
                }
                PublicationOutcome::Retryable { error } => {
                    if attempt + 1 < attempts {
                        self.inner.metrics.terminal_persist_backoff();
                        tokio::time::sleep(self.inner.config.terminal_persist_retry_delay).await;
                        tracing::warn!(
                            run_id,
                            error = %truncate_for_log(&error, 256),
                            "required publication completion was not sent; retrying within the original deadline"
                        );
                    } else {
                        self.finish_failed(
                            run_id,
                            json!({
                                "status": "failed",
                                "error_code": "managed_publication_unavailable",
                                "error_message": "required publication was not submitted",
                                "publication": {"status": "not_published"},
                            }),
                        )
                        .await;
                        return;
                    }
                }
            }
        }
    }

    /// One frozen completion attempt. The branch gate is reserved before the
    /// head/revision are read and remains Finalizing across the single claimed
    /// send; commit_gate is held only around the durable command.
    async fn commit_completed_publication_once(
        &self,
        run_id: &str,
        session_id: &str,
        output_text: &str,
        request_id: &str,
    ) -> PublicationOutcome {
        let request_id = request_id.to_string();
        let service = self.clone();
        let run_id_for_commit = run_id.to_string();
        let session_id_for_commit = session_id.to_string();
        let output_text_for_commit = output_text.to_string();
        let retry_window = self.inner.config.terminal_commit_retry_window;
        let max_event_bytes = self.inner.config.max_event_bytes;
        let max_events_per_run = self.inner.config.max_events_per_run;
        tokio::task::spawn_blocking(move || {
            let Some(persistence) = service.persistence_handle() else {
                return PublicationOutcome::Rejected {
                    code: "managed_publication_unavailable",
                    status: "not_published",
                    message: "managed workspace requires persistence".to_string(),
                };
            };
            let Some(binding) = service.managed_binding(&run_id_for_commit) else {
                return PublicationOutcome::Rejected {
                    code: "managed_publication_conflict",
                    status: "conflict",
                    message: "managed run binding is missing".to_string(),
                };
            };
            if let Err(error) = binding.completion_authority_facts() {
                return PublicationOutcome::Rejected {
                    code: "managed_publication_conflict",
                    status: "conflict",
                    message: error,
                };
            }
            // One-shot, exact-run, fixture-only fact selection. It is taken
            // before the reservation because the negative control for the
            // Native taint return must be known at that exact refusal; every
            // other fault is applied later, at its own producer boundary.
            let fact_faults = take_completion_fact_fault(&persistence, &run_id_for_commit);
            let deadline = binding
                .cancel
                .deadline_instant()
                .unwrap_or_else(Instant::now);
            let reservation = match binding.reserve_completion_publication(
                // Phase-independent whole-table proof, not a cleanup: the
                // reservation has already sealed Finalizing, so a cleanup could
                // never report this run quiescent. Only an Open-origin
                // reservation calls this; the run's own original deadline
                // bounds every observation.
                || binding.probe_completion_group(deadline),
                || {
                    // Fixture-only pause at the exact quiesce -> mint window.
                    // It runs no durable byte itself; a test may perform a real
                    // workspace/graph revoke here.
                    #[cfg(any(test, feature = "workspace-io-fault"))]
                    if let Some(hook) =
                        persistence.take_managed_completion_quiescence_pause(&run_id_for_commit)
                    {
                        hook();
                    }
                    // The admitted Native authority must still hold after
                    // quiescence and before this permit is minted.
                    binding.completion_authority_facts()
                },
                deadline,
            ) {
                Ok(reservation) => reservation,
                Err(error) => {
                    return classify_native_outcome(&binding, &error);
                }
            };
            if binding.cancel.requested().is_some() || binding.cancel.deadline_passed() {
                reservation.dispose_verified();
                return PublicationOutcome::NotActive;
            }
            let head = match binding.completion_head(&binding.cancel) {
                Ok(head) => head,
                Err(error) => {
                    reservation.dispose_verified();
                    return classify_native_outcome(&binding, &error);
                }
            };
            if head.branch_id != binding.admitted_branch.branch_id
                || head.workspace_id != binding.admitted_branch.workspace_id
                || head.store_id != binding.admitted_branch.store_id
                || head.epoch != binding.admitted_epoch()
            {
                reservation.dispose_verified();
                return PublicationOutcome::Rejected {
                    code: "managed_publication_conflict",
                    status: "conflict",
                    message: "frozen branch head does not match the admitted owner".to_string(),
                };
            }
            // The existing Native early refusal stays the shipped behavior.
            // The approved negative control only observes the real
            // unchanged-lineage RSS refusal: the reservation, quiescence/owner
            // proof and tainted producer above are unchanged.
            if head.process_lineage_tainted && !fact_faults.observe_tainted_lineage_refusal {
                reservation.dispose_verified();
                return PublicationOutcome::Rejected {
                    code: "managed_process_lineage_unsupported",
                    status: "conflict",
                    message: "managed process lineage is tainted".to_string(),
                };
            }
            let publication_pointer = match binding.completion_publication(&binding.cancel) {
                Ok(pointer) => pointer,
                Err(error) => {
                    reservation.dispose_verified();
                    return PublicationOutcome::Retryable { error };
                }
            };
            let expected_revision = publication_pointer
                .as_ref()
                .map(|pointer| pointer.revision)
                .unwrap_or(0);
            let now_ms = timestamp();
            let declared = json!({
                "status": "committed",
                "workspace_id": binding.admitted_branch.workspace_id,
                "branch_id": binding.admitted_branch.branch_id,
                "epoch": head.epoch,
                "head_object_id": head.head_object_id,
                "head_version": head.head_version,
                "request_id": request_id,
            });
            let (message, events) = {
                let store = service.inner.store.read();
                let Some(run) = store.runs.get(&run_id_for_commit) else {
                    reservation.dispose_verified();
                    return PublicationOutcome::NotActive;
                };
                if run.status != "started" {
                    reservation.dispose_verified();
                    return PublicationOutcome::NotActive;
                }
                let Some(session) = store.sessions.get(&session_id_for_commit) else {
                    reservation.dispose_verified();
                    return PublicationOutcome::SessionMissing;
                };
                publication_delta(
                    run,
                    session,
                    &run_id_for_commit,
                    &session_id_for_commit,
                    &output_text_for_commit,
                    max_event_bytes,
                    now_ms,
                    declared,
                )
            };
            #[cfg(any(test, feature = "workspace-io-fault"))]
            if let Some(hook) =
                persistence.take_managed_publication_precommit_pause(&run_id_for_commit)
            {
                hook();
            }
            // The pause has released. The original owner clock stays
            // authoritative, and the fresh source identity is observed from
            // the admitted path itself after that pause and outside the
            // service-wide commit gate. The already-captured directory
            // descriptor is never used as this fresh observation.
            if binding.cancel.requested().is_some() || binding.cancel.deadline_passed() {
                reservation.dispose_verified();
                return PublicationOutcome::NotActive;
            }
            let fresh_source_identity =
                match observe_source_identity(binding.authority.canonical_path()) {
                    Ok(identity) => identity,
                    Err(error) => {
                        reservation.dispose_verified();
                        return PublicationOutcome::Rejected {
                            code: "managed_publication_conflict",
                            status: "conflict",
                            message: error,
                        };
                    }
                };
            // Two real generation reads: the admitted grant's captured
            // generation and the owner's current workspace epoch. A frozen
            // generation compared with itself is not the fact.
            let (authority_generation, observed_authority_generation) =
                binding.authority.generation_observation();
            #[cfg(any(test, feature = "workspace-io-fault"))]
            let observed_authority_generation = if fact_faults.stale_authority_generation {
                // Native producer-boundary fault: the owner epoch advanced
                // after this grant was captured. Only the fresh observation
                // is substituted; the captured value stays real.
                observed_authority_generation.saturating_add(1)
            } else {
                observed_authority_generation
            };
            if authority_generation != observed_authority_generation {
                reservation.dispose_verified();
                return PublicationOutcome::Rejected {
                    code: "managed_publication_conflict",
                    status: "conflict",
                    message: "workspace_generation_stale".to_string(),
                };
            }
            // The frozen expected head is the exact trusted expectation the
            // claimed command carries. The one-shot Native producer-boundary
            // fault substitutes only that expectation, before the payload and
            // claim are frozen; the real head above is untouched.
            let mut expected_head = head.clone();
            #[cfg(any(test, feature = "workspace-io-fault"))]
            if fact_faults.stale_binding_epoch {
                expected_head.epoch = if expected_head.epoch > 1 {
                    expected_head.epoch - 1
                } else {
                    expected_head.epoch.saturating_add(1)
                };
            }
            #[cfg(any(test, feature = "workspace-io-fault"))]
            if fact_faults.stale_branch_schema {
                expected_head.schema_version = expected_head.schema_version.saturating_add(1);
            }
            let request = ManagedPublishRequest {
                workspace_id: binding.admitted_branch.workspace_id.clone(),
                branch_id: binding.admitted_branch.branch_id.clone(),
                expected_head: expected_head.clone(),
                request_id: request_id.clone(),
            };
            let proof = match serde_json::to_string(&request) {
                Ok(proof) => proof,
                Err(_) => {
                    reservation.dispose_verified();
                    return PublicationOutcome::Rejected {
                        code: "managed_publication_conflict",
                        status: "conflict",
                        message: "publication proof is not encodable".to_string(),
                    };
                }
            };
            let _serial = service.inner.commit_gate.lock();
            {
                let store = service.inner.store.read();
                let active = store
                    .runs
                    .get(&run_id_for_commit)
                    .is_some_and(|run| run.status == "started");
                if !active {
                    drop(store);
                    reservation.dispose_verified();
                    return PublicationOutcome::NotActive;
                }
            }
            let publication_document = json!({
                "run_id": run_id_for_commit.clone(),
                "session_id": session_id_for_commit.clone(),
                "workspace_id": binding.admitted_branch.workspace_id,
                "branch_id": binding.admitted_branch.branch_id,
                "profile": binding.owner.profile,
                "epoch": expected_head.epoch,
                "expected_head": expected_head.clone(),
                "request_id": request_id,
                "proof": proof,
                "now_ms": now_ms,
                "published_at_ms": now_ms,
                "expected_revision": expected_revision,
                "captured_source_identity": binding.workspace.identity.source_identity.clone(),
                "fresh_source_identity": fresh_source_identity,
                "authority_generation": authority_generation,
                "observed_authority_generation": observed_authority_generation,
            });
            let payload = finalize_payload(
                &run_id_for_commit,
                &session_id_for_commit,
                &binding,
                &events,
                message.as_ref(),
                &publication_document,
                now_ms,
            );
            let access = match persistence.claim_finalize(
                managed_identity(&binding),
                proof.clone(),
                request_id.clone(),
                reservation.into_owner(),
            ) {
                Ok(access) => access,
                Err(error) => {
                    return PublicationOutcome::Rejected {
                        code: "managed_publication_conflict",
                        status: "conflict",
                        message: error,
                    };
                }
            };
            let outcome = persistence.run_terminal_finalized(access, &payload, &binding.cancel);
            let pending_publication = PendingPublication {
                request_id: request_id.clone(),
                proof,
                workspace_id: binding.admitted_branch.workspace_id.clone(),
                _profile: binding.owner.profile.clone(),
                run_id: run_id_for_commit.clone(),
                expected_head: expected_head.clone(),
                _expected_revision: expected_revision,
                owner: outcome.owner.clone(),
            };
            let pending =
                |events: &[GatewayEvent], message: &Option<SessionMessage>| PendingTerminal {
                    to_status: "completed".to_string(),
                    session_id: Some(session_id_for_commit.clone()),
                    events: events.to_vec(),
                    assistant_message: message.clone(),
                    deadline: Instant::now() + retry_window,
                    publication: Some(pending_publication.clone()),
                };
            match outcome.result {
                Ok(data) => {
                    match verify_finalize_readback(&data, &request_id, &request, expected_revision)
                    {
                        Ok(seqs) => {
                            let mut store = service.inner.store.write();
                            apply_terminal(
                                &mut store,
                                &run_id_for_commit,
                                "completed",
                                &events,
                                &seqs,
                                message.as_ref(),
                                max_events_per_run,
                            );
                            let sender = store
                                .runs
                                .get(&run_id_for_commit)
                                .and_then(|run| run.sender.clone());
                            drop(store);
                            if let Some(sender) = sender {
                                for event in &events {
                                    let _ = sender.send(event.clone());
                                }
                            }
                            outcome.owner.dispose_verified();
                            PublicationOutcome::Committed
                        }
                        Err(error) => {
                            tracing::error!(
                                run_id = %run_id_for_commit,
                                error = %truncate_for_log(&error, 256),
                                "publication terminal readback is inconsistent; retaining the owner"
                            );
                            PublicationOutcome::Pending {
                                error,
                                pending: Box::new(pending(&events, &message)),
                            }
                        }
                    }
                }
                Err(error)
                    if error.code == "managed_transaction_rolled_back"
                        || error.code == "managed_request_conflict" =>
                {
                    // A deterministic in-transaction guard abort: nothing was
                    // committed, so the run may fail with a conflict status.
                    outcome.owner.dispose_verified();
                    PublicationOutcome::Rejected {
                        code: "managed_publication_conflict",
                        status: "conflict",
                        message: error.message,
                    }
                }
                Err(error) if outcome.submitted => {
                    let cause = error.message;
                    PublicationOutcome::Pending {
                        error: cause,
                        pending: Box::new(pending(&events, &message)),
                    }
                }
                Err(error) => {
                    // send Ok never queued: the pre-send rejection is
                    // authoritative. The owner is released because no
                    // publication-bearing write exists.
                    outcome.owner.dispose_verified();
                    if binding.cancel.requested().is_some() || binding.cancel.deadline_passed() {
                        PublicationOutcome::NotActive
                    } else {
                        PublicationOutcome::Retryable {
                            error: error.message,
                        }
                    }
                }
            }
        })
        .await
        .expect("publication commit task must complete")
    }
}

fn classify_native_outcome(binding: &Arc<ManagedRunBinding>, error: &str) -> PublicationOutcome {
    if error.contains("deadline") || binding.cancel.deadline_passed() {
        return PublicationOutcome::NotActive;
    }
    if error.contains("busy") || error.contains("unavailable") {
        return PublicationOutcome::Rejected {
            code: "managed_publication_conflict",
            status: "conflict",
            message: error.to_string(),
        };
    }
    PublicationOutcome::Rejected {
        code: "managed_publication_conflict",
        status: "conflict",
        message: error.to_string(),
    }
}

/// Freeze the terminal delta with deterministic identities so an unacknowledged
/// send can be replayed field by field. The run/session identities, output,
/// event budget and the one frozen publication are a single terminal fact a
/// caller must supply together; a bag struct would only rename that fact.
#[allow(clippy::too_many_arguments)]
fn publication_delta(
    run: &RunRecord,
    session: &SessionRecord,
    run_id: &str,
    session_id: &str,
    output_text: &str,
    max_event_bytes: usize,
    now_ms: u64,
    publication: Value,
) -> (Option<SessionMessage>, Vec<GatewayEvent>) {
    let mut seq = run.events.last().map(|event| event.seq + 1).unwrap_or(1);
    let provider_step_present = run
        .events
        .iter()
        .any(|event| event.event == "model.completed");
    let mut events = Vec::new();
    let message = if provider_step_present {
        None
    } else {
        let ordinal = next_message_ordinal(session);
        let message = SessionMessage {
            id: format!("{run_id}:finalize:message"),
            session_id: session_id.to_string(),
            role: "assistant".to_string(),
            content: decode_message_content(&Value::String(output_text.to_string())),
            created_at: now_ms,
            run_id: Some(run_id.to_string()),
            finish_reason: Some("stop".to_string()),
            name: None,
            tool_call_id: None,
            parent_message_id: None,
            token_estimate: None,
            metadata: Value::Null,
            ordinal: Some(ordinal),
        };
        let delta = util_event(
            run,
            "message.delta",
            json!({
                "message_id": message.id,
                "delta": output_text,
                "role": "assistant",
            }),
            max_event_bytes,
            &format!("{run_id}:finalize:delta"),
            seq,
            now_ms,
        );
        seq += 1;
        events.push(delta);
        Some(message)
    };
    events.push(util_event(
        run,
        "workspace.published",
        json!({
            "workspace_id": publication.get("workspace_id").cloned().unwrap_or(Value::Null),
            "branch_id": publication.get("branch_id").cloned().unwrap_or(Value::Null),
            "epoch": publication.get("epoch").cloned().unwrap_or(Value::Null),
            "head_object_id": publication.get("head_object_id").cloned().unwrap_or(Value::Null),
            "head_version": publication.get("head_version").cloned().unwrap_or(Value::Null),
            "request_id": publication.get("request_id").cloned().unwrap_or(Value::Null),
        }),
        max_event_bytes,
        &format!("{run_id}:finalize:published"),
        seq,
        now_ms,
    ));
    seq += 1;
    let output = message.as_ref().map_or_else(
        || json!({"text": output_text}),
        |message| json!({"message": message}),
    );
    events.push(util_event(
        run,
        "run.completed",
        json!({
            "status": "completed",
            "output": output,
            "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            "publication": publication,
        }),
        max_event_bytes,
        &format!("{run_id}:finalize:completed"),
        seq,
        now_ms,
    ));
    (message, events)
}

fn util_event(
    run: &RunRecord,
    event_type: &str,
    data: Value,
    max_event_bytes: usize,
    event_id: &str,
    seq: u64,
    now_ms: u64,
) -> GatewayEvent {
    crate::runtime::delivery::event_candidate(run, event_type, data, max_event_bytes).with_identity(
        event_id.to_string(),
        seq,
        now_ms,
    )
}

trait EventIdentity {
    fn with_identity(self, event_id: String, seq: u64, now_ms: u64) -> Self;
}

impl EventIdentity for GatewayEvent {
    fn with_identity(mut self, event_id: String, seq: u64, now_ms: u64) -> Self {
        self.event_id = event_id;
        self.seq = seq;
        self.timestamp = now_ms;
        self
    }
}

fn finalize_payload(
    run_id: &str,
    session_id: &str,
    binding: &Arc<ManagedRunBinding>,
    events: &[GatewayEvent],
    message: Option<&SessionMessage>,
    publication: &Value,
    now_ms: u64,
) -> Value {
    let event = |index: usize| events.get(index);
    let event_id = |index: usize| {
        event(index)
            .map(|event| event.event_id.clone())
            .unwrap_or_default()
    };
    let event_type = |index: usize| {
        event(index)
            .map(|event| event.event.clone())
            .unwrap_or_default()
    };
    let event_payload = |index: usize| {
        event(index)
            .map(|event| serde_json::to_string(&event.data).unwrap_or_else(|_| "{}".to_string()))
            .unwrap_or_else(|| "{}".to_string())
    };
    json!({
        "run_id": run_id,
        "session_id": session_id,
        "profile": binding.owner.profile,
        "workspace_id": binding.admitted_branch.workspace_id,
        "branch_id": binding.admitted_branch.branch_id,
        "epoch": binding.admitted_epoch(),
        "to_status": "completed",
        "error_code": "",
        "error_message": "",
        "event_1_id": event_id(0),
        "event_1_type": event_type(0),
        "event_1_payload": event_payload(0),
        "event_2_id": event_id(1),
        "event_2_type": event_type(1),
        "event_2_payload": event_payload(1),
        "event_3_id": event_id(2),
        "event_3_type": event_type(2),
        "event_3_payload": event_payload(2),
        "event_count": events.len(),
        "message_id": message.map(|message| message.id.clone()).unwrap_or_default(),
        "message_session_id": message.map(|_| session_id.to_string()).unwrap_or_default(),
        "message_role": message.map(|message| message.role.clone()).unwrap_or_default(),
        "message_content_json": message
            .map(|message| serde_json::to_string(&message.content).unwrap_or_else(|_| "null".to_string()))
            .unwrap_or_default(),
        "message_run_id": message.and_then(|message| message.run_id.clone()).unwrap_or_default(),
        "message_finish_reason": message
            .and_then(|message| message.finish_reason.clone())
            .unwrap_or_default(),
        "message_ordinal": message.and_then(|message| message.ordinal).unwrap_or(0),
        "now_ms": now_ms,
        "publication_json": serde_json::to_string(publication).unwrap_or_else(|_| "{}".to_string()),
    })
}

/// Exact verification of one already-committed readback. A mismatch is an
/// unresolved storage inconsistency, never authority for another terminal.
fn verify_finalize_readback(
    data: &Value,
    request_id: &str,
    request: &ManagedPublishRequest,
    expected_revision: u64,
) -> Result<Vec<(String, u64)>, String> {
    let rows = data
        .get("receipt")
        .ok_or("publication readback is missing")
        .and_then(|receipt| {
            crate::sqlite_storage_rows::sqlite_storage_rows(receipt)
                .map_err(|_| "publication readback is missing")
        })?;
    let row = rows.first().ok_or("publication receipt row is missing")?;
    let cell = row.first().ok_or("publication receipt cell is missing")?;
    let record = cell
        .as_str()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .unwrap_or_else(|| cell.clone());
    let receipt = record
        .get("receipt")
        .ok_or("publication receipt is missing")?;
    let pointer = record
        .get("publication")
        .ok_or("publication pointer is missing")?;
    verify_receipt(receipt, request, request_id)?;
    verify_pointer(pointer, request, request_id, expected_revision)?;
    let events = data
        .get("events")
        .ok_or("publication event rows are missing")
        .and_then(|events| {
            crate::sqlite_storage_rows::sqlite_storage_rows(events)
                .map_err(|_| "publication event rows are missing")
        })?;
    collect_event_seqs(&events)
}

fn managed_identity(binding: &Arc<ManagedRunBinding>) -> crate::effects::ManagedWorkspaceIdentity {
    let mut identity = binding.workspace.identity.clone();
    identity.branch_id = binding.admitted_branch.branch_id.clone();
    identity
}

/// Fresh, path-based observation of the admitted source directory's
/// device/inode. It stats the path the owner currently resolves, not the
/// already-captured root descriptor, and performs no tree walk. The RSS
/// publication transaction compares this observation with the durable
/// captured source identity; SQLite does not make an external rename atomic.
fn observe_source_identity(path: &str) -> Result<crate::effects::DirectoryIdentity, String> {
    use std::os::unix::fs::MetadataExt;
    let metadata =
        std::fs::metadata(path).map_err(|_| "managed source path is unavailable".to_string())?;
    if !metadata.is_dir() {
        return Err("managed source path is not a directory".to_string());
    }
    Ok(crate::effects::DirectoryIdentity {
        device_decimal: metadata.dev().to_string(),
        inode_decimal: metadata.ino().to_string(),
    })
}

fn verify_receipt(
    receipt: &Value,
    request: &ManagedPublishRequest,
    request_id: &str,
) -> Result<(), String> {
    let matches = receipt.get("status").and_then(Value::as_str) == Some("committed")
        && receipt.get("workspace_id").and_then(Value::as_str)
            == Some(request.workspace_id.as_str())
        && receipt.get("branch_id").and_then(Value::as_str) == Some(request.branch_id.as_str())
        && receipt.get("epoch").and_then(Value::as_u64) == Some(request.expected_head.epoch)
        && receipt.get("head_object_id").and_then(Value::as_str)
            == Some(request.expected_head.head_object_id.as_str())
        && receipt.get("head_version").and_then(Value::as_u64)
            == Some(request.expected_head.head_version)
        && receipt.get("request_id").and_then(Value::as_str) == Some(request_id);
    if matches {
        Ok(())
    } else {
        Err("publication receipt does not match the frozen request".into())
    }
}

fn verify_pointer(
    pointer: &Value,
    request: &ManagedPublishRequest,
    request_id: &str,
    expected_revision: u64,
) -> Result<(), String> {
    let expected = if expected_revision == 0 {
        1
    } else {
        expected_revision + 1
    };
    let matches = pointer.get("workspace_id").and_then(Value::as_str)
        == Some(request.workspace_id.as_str())
        && pointer.get("branch_id").and_then(Value::as_str) == Some(request.branch_id.as_str())
        && pointer.get("request_id").and_then(Value::as_str) == Some(request_id)
        && pointer.get("revision").and_then(Value::as_u64) == Some(expected)
        && pointer.get("head_object_id").and_then(Value::as_str)
            == Some(request.expected_head.head_object_id.as_str())
        && pointer.get("head_version").and_then(Value::as_u64)
            == Some(request.expected_head.head_version);
    if matches {
        Ok(())
    } else {
        Err("publication pointer does not match the frozen request revision".into())
    }
}

fn collect_event_seqs(rows: &[Vec<Value>]) -> Result<Vec<(String, u64)>, String> {
    let mut seqs = Vec::new();
    for cells in rows {
        let seq = cells
            .first()
            .and_then(Value::as_u64)
            .ok_or("event seq is malformed")?;
        let event_id = cells
            .get(2)
            .and_then(Value::as_str)
            .ok_or("event id is malformed")?;
        seqs.push((event_id.to_string(), seq));
    }
    Ok(seqs)
}

/// Ordered settlement of a sent-but-unsettled publication. Runs on the same
/// FIFO worker through the independent five-second metadata read context. A
/// receipt hit applies the exact committed result; a completed snapshot without
/// a receipt is proven absence and permits one existing failed bookkeeping
/// terminal; everything else stays unknown.
pub(crate) fn settle_pending_publication(
    service: &AgentService,
    run_id: &str,
    pending: &PendingTerminal,
) -> PublicationSettlement {
    let Some(publication) = pending.publication.as_ref() else {
        return PublicationSettlement::NotPublication;
    };
    let Some(persistence) = service.persistence_handle() else {
        return PublicationSettlement::Unknown {
            error: "managed workspace requires persistence".into(),
        };
    };
    let payload = json!({
        "maintenance_json": serde_json::to_string(&json!({
            "workspace_id": publication.workspace_id,
            "request_id": publication.request_id,
            "run_id": publication.run_id,
        }))
        .unwrap_or_default(),
    });
    let snapshot = match persistence.finalize_settle(&payload, None) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return PublicationSettlement::Unknown {
                error: error.message,
            };
        }
    };
    let record = crate::sqlite_storage_rows::sqlite_storage_first_row(&snapshot)
        .and_then(|row| row.first().cloned())
        .and_then(|cell| cell.as_str().map(str::to_string))
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let Some(record) = record else {
        return PublicationSettlement::Unknown {
            error: "finalize settlement snapshot is malformed".into(),
        };
    };
    let receipt = record.get("receipt").cloned().unwrap_or(Value::Null);
    let run_status = record
        .get("run_status")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !receipt.is_null() {
        if record.get("proof").and_then(Value::as_str) != Some(publication.proof.as_str()) {
            return PublicationSettlement::Unknown {
                error: "settlement receipt proof does not match".into(),
            };
        }
        let request = ManagedPublishRequest {
            workspace_id: publication.workspace_id.clone(),
            branch_id: publication.expected_head.branch_id.clone(),
            expected_head: publication.expected_head.clone(),
            request_id: publication.request_id.clone(),
        };
        if let Err(error) = verify_receipt(&receipt, &request, &publication.request_id) {
            return PublicationSettlement::Unknown { error };
        }
        if run_status != "completed" {
            return PublicationSettlement::Unknown {
                error: "settlement receipt exists without a completed run".into(),
            };
        }
        let events = record
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut seqs = Vec::new();
        for event in &pending.events {
            let seq = events.iter().find_map(|row| {
                (row.get("event_id").and_then(Value::as_str) == Some(event.event_id.as_str()))
                    .then(|| row.get("seq").and_then(Value::as_u64))
                    .flatten()
            });
            let Some(seq) = seq else {
                return PublicationSettlement::Unknown {
                    error: "settlement receipt misses a frozen event identity".into(),
                };
            };
            seqs.push((event.event_id.clone(), seq));
        }
        let mut store = service.inner.store.write();
        apply_terminal(
            &mut store,
            run_id,
            &pending.to_status,
            &pending.events,
            &seqs,
            pending.assistant_message.as_ref(),
            service.inner.config.max_events_per_run,
        );
        let sender = store.runs.get(run_id).and_then(|run| run.sender.clone());
        drop(store);
        if let Some(sender) = sender {
            for event in &pending.events {
                let _ = sender.send(event.clone());
            }
        }
        publication.owner.dispose_verified();
        service.clear_pending_terminal(run_id);
        return PublicationSettlement::Committed;
    }
    if run_status == "running" {
        // Completed exact snapshot on the same FIFO worker after every
        // previously sent write, with further sends fenced: absence is proven.
        // Proven absence permits one failed/cancelled bookkeeping terminal, so
        // the Native owner and the pending entry stay reachable until that
        // single terminal is durably applied by `retry_pending_publication`.
        // Disposing here would move the branch writer to Idle (admitting a new
        // writer) while the run row is still running and would drop the only
        // retry for the bookkeeping terminal.
        return PublicationSettlement::Absent;
    }
    PublicationSettlement::Unknown {
        error: "settlement snapshot is neither a receipt hit nor a proven absence".into(),
    }
}

pub(crate) enum PublicationSettlement {
    NotPublication,
    Committed,
    Absent,
    Unknown { error: String },
}

/// Exact durable run status from the existing typed `run.get` read. Used to
/// decide whether the single failed bookkeeping terminal already landed after
/// an unknown submission; error text alone is never treated as proof.
fn durable_run_status(service: &AgentService, run_id: &str) -> Option<String> {
    let persistence = service.persistence_handle()?;
    let data = persistence.run_get(run_id).ok()?;
    let rows = crate::sqlite_storage_rows::sqlite_storage_rows(&data).ok()?;
    let row = rows.first()?;
    row.get(3).and_then(Value::as_str).map(str::to_string)
}

/// Bounded retry entry for one sent-but-unsettled publication. It never calls
/// the ordinary terminal commit for the frozen publication and never clears the
/// pending entry as clean.
pub(crate) fn retry_pending_publication(
    service: &AgentService,
    run_id: &str,
    pending: PendingTerminal,
) -> PendingRetryOutcome {
    if Instant::now() >= pending.deadline {
        // Expiry transfers the still-reachable Unresolved owner and returns;
        // it fabricates no failed terminal and assumes no future restart.
        if let Some(publication) = &pending.publication {
            publication.owner.transfer_unresolved();
        }
        service
            .inner
            .metrics
            .terminal_retry(TerminalRetryOutcome::Expired);
        tracing::warn!(
            run_id,
            "publication settlement window expired; branch owner retained as Unresolved"
        );
        return PendingRetryOutcome::Expired;
    }
    match settle_pending_publication(service, run_id, &pending) {
        PublicationSettlement::NotPublication => PendingRetryOutcome::RetryFailed,
        PublicationSettlement::Committed => {
            service
                .inner
                .metrics
                .terminal_retry(TerminalRetryOutcome::Committed);
            tracing::info!(run_id, "publication settled from the ordered FIFO receipt");
            PendingRetryOutcome::Committed
        }
        PublicationSettlement::Absent => {
            let Some(persistence) = service.persistence_handle() else {
                return PendingRetryOutcome::RetryFailed;
            };
            let event = {
                let store = service.inner.store.read();
                let Some(run) = store.runs.get(run_id) else {
                    service.clear_pending_terminal(run_id);
                    return PendingRetryOutcome::Gone;
                };
                let mut event = crate::runtime::delivery::event_candidate(
                    run,
                    "run.failed",
                    json!({
                        "status": "failed",
                        "error_code": "managed_publication_conflict",
                        "error_message": "required publication absence proven after the original deadline",
                        "publication": {"status": "not_published"},
                    }),
                    service.inner.config.max_event_bytes,
                );
                event.timestamp = timestamp();
                event
            };
            // Exactly one existing failed bookkeeping terminal with empty
            // publication data; it grants no publication authority.
            match super::terminal_commit(
                Some(&persistence),
                run_id,
                "",
                "failed",
                std::slice::from_ref(&event),
                None,
            ) {
                Ok(seqs) => {
                    let mut store = service.inner.store.write();
                    apply_terminal(
                        &mut store,
                        run_id,
                        "failed",
                        std::slice::from_ref(&event),
                        &seqs,
                        None,
                        service.inner.config.max_events_per_run,
                    );
                    let sender = store.runs.get(run_id).and_then(|run| run.sender.clone());
                    drop(store);
                    if let Some(sender) = sender {
                        let mut published = event;
                        if let Some((_, seq)) = seqs
                            .iter()
                            .find(|(event_id, _)| event_id == &published.event_id)
                        {
                            published.seq = *seq;
                        }
                        let _ = sender.send(published);
                    }
                    // The single bookkeeping terminal is durable: only now may
                    // the Native owner be disposed and the pending entry
                    // cleared.
                    if let Some(publication) = &pending.publication {
                        publication.owner.dispose_verified();
                    }
                    service.clear_pending_terminal(run_id);
                    service
                        .inner
                        .metrics
                        .terminal_retry(TerminalRetryOutcome::Committed);
                    PendingRetryOutcome::Committed
                }
                Err(error) => {
                    tracing::error!(
                        run_id,
                        error = %truncate_for_log(&error.to_string(), 256),
                        "publication absence bookkeeping terminal could not be persisted"
                    );
                    // The submit may have failed after the durable row landed.
                    // Read the exact durable run state back: only an existing
                    // failed/cancelled terminal proves the single bookkeeping
                    // row exists. `transition_conflict` and any other error
                    // text are not accepted as durable proof.
                    match durable_run_status(service, run_id) {
                        Some(status) if status == "failed" || status == "cancelled" => {
                            if let Some(publication) = &pending.publication {
                                publication.owner.dispose_verified();
                            }
                            service.clear_pending_terminal(run_id);
                            service
                                .inner
                                .metrics
                                .terminal_retry(TerminalRetryOutcome::Conflict);
                            PendingRetryOutcome::Conflict
                        }
                        _ => {
                            // Keep the Native owner and the pending entry: the
                            // next janitor tick retries only this bookkeeping
                            // terminal and never a second publication send.
                            service
                                .inner
                                .metrics
                                .terminal_retry(TerminalRetryOutcome::RetryFailed);
                            PendingRetryOutcome::RetryFailed
                        }
                    }
                }
            }
        }
        PublicationSettlement::Unknown { error } => {
            tracing::warn!(
                run_id,
                error = %truncate_for_log(&error, 256),
                "publication settlement is still unknown; the Native owner stays retained"
            );
            service
                .inner
                .metrics
                .terminal_retry(TerminalRetryOutcome::RetryFailed);
            PendingRetryOutcome::RetryFailed
        }
    }
}
