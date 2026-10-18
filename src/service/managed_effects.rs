//! Joint managed metadata publication; all filesystem work precedes this module.
use super::*;
#[cfg(test)]
#[path = "managed_effects_tests.rs"]
mod tests;
use crate::effects::journal::*;
use crate::effects::{ManagedFinalWitness, ManagedStartedWitness};

fn query_context(
    service: &AgentService,
) -> Result<
    (
        Arc<crate::effects::broker::ManagedEffectRuntime>,
        Arc<crate::runtime::rss_runner::WorkspaceAuthority>,
    ),
    String,
> {
    let runtime = service
        .inner
        .managed_effects
        .read()
        .clone()
        .ok_or("managed query unavailable")?;
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(5));
    let source = service
        .inner
        .config
        .managed_workspace
        .as_ref()
        .ok_or("managed query unavailable")?
        .source_root
        .to_str()
        .ok_or("managed source invalid")?;
    let (_, authority) = service
        .resolve_workspace_admission(Some(source), None, &cancellation, false)
        .map_err(|_| "managed query unavailable")?;
    Ok((runtime, authority.ok_or("managed query unavailable")?))
}
pub(super) fn query(
    service: &AgentService,
    request: ManagedEffectListRequest,
) -> Result<ManagedEffectPage, String> {
    if request.limit == 0 || request.limit > 128 {
        return Err("managed page limit must be 1..=128".into());
    }
    crate::effects::broker::validate_id("ws", &request.workspace_id)?;
    if let Some(cursor) = &request.after_effect_id {
        crate::effects::broker::validate_id("effect", cursor)?;
    }
    let (runtime, authority) = query_context(service)?;
    runtime.authorize_workspace_query(
        &authority,
        ADMISSION_SESSION_PROFILE,
        &request.workspace_id,
    )?;
    let page = service
        .inner
        .persistence
        .as_ref()
        .ok_or("managed query unavailable")?
        .managed_effect_list(&request)
        .map_err(|e| e.to_string())?;
    runtime.authorize_workspace_query(
        &authority,
        ADMISSION_SESSION_PROFILE,
        &request.workspace_id,
    )?;
    Ok(page)
}
pub(super) fn read_chunk(
    service: &AgentService,
    request: ManagedResultReadRequest,
) -> Result<ManagedResultChunk, String> {
    if request.limit == 0 || request.limit > 131072 {
        return Err("managed result chunk limit must be 1..=131072".into());
    }
    crate::effects::broker::validate_id("effect", &request.effect_id)?;
    let (runtime, authority) = query_context(service)?;
    let record = service
        .inner
        .persistence
        .as_ref()
        .ok_or("managed query unavailable")?
        .managed_effect_by_id(&request.effect_id)
        .map_err(|e| e.to_string())?
        .ok_or("managed effect unavailable")?;
    if record.identity.owner.profile != ADMISSION_SESSION_PROFILE {
        return Err("managed effect unavailable".into());
    }
    runtime.authorize_query(&authority, &record.identity.workspace)?;
    let object = if let Some(outcome) = &record.outcome {
        runtime.verify_tree(
            outcome
                .publication
                .candidate_head
                .as_deref()
                .unwrap_or(&outcome.publication.base_head),
        )?;
        &outcome.canonical_result_ref
    } else {
        &record
            .prepared
            .as_ref()
            .ok_or("managed result unavailable")?
            .canonical_result
    };
    let chunk = runtime.read_result_chunk(object, request.offset, request.limit)?;
    runtime.authorize_query(&authority, &record.identity.workspace)?;
    Ok(chunk)
}

fn failed(message: impl ToString) -> EventCommitError {
    EventCommitError::PersistFailed(message.to_string())
}
pub(super) enum ManagedDurableReplay {
    Unmanaged,
    Final(ToolResult),
}
pub(super) fn replay_durable(
    service: &AgentService,
    run_id: &str,
    call_id: &str,
    name: &str,
) -> Result<ManagedDurableReplay, EventCommitError> {
    let Some(persistence) = service.inner.persistence.as_ref() else {
        return Ok(ManagedDurableReplay::Unmanaged);
    };
    let session_id = {
        let store = service.inner.store.read();
        store
            .runs
            .get(run_id)
            .ok_or(EventCommitError::Terminal)?
            .session_id
            .clone()
    };
    let request = ManagedEffectGetRequest {
        owner: ManagedOwnerScope {
            profile: ADMISSION_SESSION_PROFILE.into(),
            session_id,
            run_id: run_id.into(),
        },
        call_id: call_id.into(),
    };
    let Some(record) = persistence.managed_effect_get(&request).map_err(failed)? else {
        return Ok(ManagedDurableReplay::Unmanaged);
    };
    if record.identity.tool_name != name {
        return Err(EventCommitError::Corrupt(
            "managed replay tool name mismatch".into(),
        ));
    }
    match service.replay_managed_call(request).map_err(failed)? {
        ManagedCallReplay::Final {
            canonical_result, ..
        } => {
            let mut result: ToolResult =
                serde_json::from_str(canonical_result.as_str()).map_err(failed)?;
            result.replayed = true;
            Ok(ManagedDurableReplay::Final(result))
        }
        ManagedCallReplay::Staged { .. } => Err(failed("managed_effect_staged")),
        ManagedCallReplay::Indeterminate { .. } => Err(failed("managed_effect_indeterminate")),
        ManagedCallReplay::Unavailable { code } => Err(failed(code)),
    }
}
fn eligible(
    committer: &ServiceEventCommitter,
    call: &crate::effects::broker::ManagedCallContext,
) -> Result<(), EventCommitError> {
    if committer.is_terminal() {
        return Err(EventCommitError::Terminal);
    }
    if committer.stop_requested() {
        return Err(EventCommitError::Cancelled);
    }
    call.binding().map_err(failed)?.check().map_err(failed)?;
    if call.identity.owner.run_id != committer.run_id {
        return Err(EventCommitError::Corrupt("managed run mismatch".into()));
    }
    Ok(())
}
fn event_draft(event: &GatewayEvent) -> JsonValue {
    json!({"event_id":event.event_id,"event_type":event.event,"seq":event.seq,"payload_json":event.data.to_string()})
}
fn apply(
    committer: &ServiceEventCommitter,
    events: &[GatewayEvent],
    message: Option<SessionMessage>,
) {
    let mut store = committer.store.write();
    if let Some(run) = store.runs.get_mut(&committer.run_id) {
        for event in events {
            if !run
                .events
                .iter()
                .any(|stored| stored.event_id == event.event_id)
            {
                apply_event_locked(run, event, committer.max_events_per_run);
            }
        }
    }
    if let Some(message) = message
        && let Some(session) = store.sessions.get_mut(&message.session_id)
        && !session.messages.iter().any(|old| old.id == message.id)
    {
        session.messages.push(message);
        session.view.message_count = session.messages.len();
        session.view.updated_at = timestamp();
    }
    let sender = store
        .runs
        .get(&committer.run_id)
        .and_then(|run| run.sender.clone());
    drop(store);
    if let Some(sender) = sender {
        for event in events {
            let _ = sender.send(event.clone());
        }
    }
}
#[derive(serde::Serialize)]
struct ManagedStartedAudit<'a> {
    tool_call_id: &'a str,
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    argument_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    managed_argument_identity: Option<&'a ManagedArgumentIdentity>,
    registry_identity: &'a str,
    risk_class: &'a str,
    generation: u64,
}
pub(super) fn commit_started(
    committer: &ServiceEventCommitter,
    witness: &ManagedStartedWitness,
) -> Result<(), EventCommitError> {
    let call = &witness.call;
    let binding = call.binding().map_err(failed)?;
    let record = &witness.started;
    if record.run_id != call.identity.owner.run_id
        || record.call_id != call.identity.call_id
        || record.generation != call.identity.authorization_generation
    {
        return Err(EventCommitError::Corrupt(
            "managed started identity mismatch".into(),
        ));
    }
    call.validate_started(record).map_err(failed)?;
    let inline = matches!(
        &call.identity.argument_identity,
        ManagedArgumentIdentity::Inline { .. }
    );
    let data = serde_json::to_value(ManagedStartedAudit {
        tool_call_id: &record.call_id,
        name: &record.tool_name,
        argument_digest: inline.then_some(record.argument_digest.as_str()),
        managed_argument_identity: (!inline).then_some(&call.identity.argument_identity),
        registry_identity: &record.registry_identity,
        risk_class: record.risk_class.as_str(),
        generation: record.generation,
    })
    .map_err(failed)?;
    let record_json = serde_json::to_string(&call.record()).map_err(failed)?;
    #[cfg(feature = "workspace-io-fault")]
    if binding
        .runtime
        .take_fault(crate::effects::ManagedEffectFault::BeforeIntent)
    {
        return Err(failed("managed fixture cut before durable intent"));
    }
    let cut = {
        #[cfg(feature = "workspace-io-fault")]
        {
            if binding
                .runtime
                .take_fault(crate::effects::ManagedEffectFault::BeginAfterFirstEvent)
            {
                "BeginAfterFirstEvent"
            } else {
                ""
            }
        }
        #[cfg(not(feature = "workspace-io-fault"))]
        {
            ""
        }
    };
    let _gate = committer.commit_gate.lock();
    eligible(committer, call)?;
    let (first, second) = {
        let store = committer.store.read();
        let run = store
            .runs
            .get(&committer.run_id)
            .ok_or(EventCommitError::Terminal)?;
        let mut first = event_candidate(
            run,
            "tool.requested",
            data.clone(),
            committer.max_event_bytes,
        );
        first.event_id =
            durable_tool_event_id(&committer.run_id, &record.call_id, "tool.requested");
        let mut second = event_candidate(run, "tool.started", data, committer.max_event_bytes);
        second.event_id = durable_tool_event_id(&committer.run_id, &record.call_id, "tool.started");
        second.seq = first.seq + 1;
        (first, second)
    };
    let projection =
        json!({"normal":{"output":event_draft(&first),"terminal":event_draft(&second)}});
    binding.runtime.repository.command_with_cancellation("effect.begin",&json!({"effect_id":call.effect_id,"run_id":committer.run_id,"call_id":record.call_id,
        "workspace_id":call.identity.workspace.workspace_id,"branch_id":call.identity.workspace.branch_id,"record_json":record_json,
        "commit_id":call.receipt_id,"projections_json":projection.to_string(),"max_events":committer.max_events_per_run,"cut":cut}),&binding.cancel).map_err(failed)?;
    apply(committer, &[first, second], None);
    Ok(())
}
struct Projection {
    events: [GatewayEvent; 2],
    message: SessionMessage,
    wire: JsonValue,
}
struct ProjectionReservation<'a> {
    seq: u64,
    ordinal: i64,
    parent: &'a str,
}
fn projection(
    committer: &ServiceEventCommitter,
    call: &crate::effects::broker::ManagedCallContext,
    prepared: &ManagedPreparedRecord,
    result: &ToolResult,
    reservation: &ProjectionReservation<'_>,
    content: &JsonValue,
    conflict: bool,
) -> Projection {
    let ProjectionReservation {
        seq,
        ordinal,
        parent,
    } = *reservation;
    let identity = &call.identity;
    let status = if conflict {
        ManagedPublicationStatus::Conflict
    } else if !prepared.observation_ok {
        ManagedPublicationStatus::NotPublished
    } else if prepared.operation_class == ManagedOperationClass::ReadOnly {
        ManagedPublicationStatus::ReadOnly
    } else {
        ManagedPublicationStatus::Committed
    };
    let publication = ManagedPublicationRef {
        format: MANAGED_FORMAT.into(),
        effect_id: call.effect_id.clone(),
        workspace_id: identity.workspace.workspace_id.clone(),
        branch_id: identity.workspace.branch_id.clone(),
        epoch: identity.epoch,
        base_head: identity.expected_head.clone(),
        base_head_version: identity.expected_head_version,
        candidate_head: prepared
            .candidate_root
            .as_ref()
            .map(|object| object.object_id.clone()),
        observed_head: identity.expected_head.clone(),
        observed_head_version: identity.expected_head_version,
        status: status.clone(),
    };
    let terminal = if result.ok {
        "tool.completed"
    } else {
        "tool.failed"
    };
    let mut data = json!({"tool_call_id":identity.call_id,"ok":result.ok,"truncated":result.truncated,"managed_publication":publication});
    if let Some(error) = &result.error {
        data["error_code"] = json!(error.code);
    }
    if !result.artifacts.is_empty() {
        data["artifacts"] = json!(result.artifacts);
    }
    let make_event = |name: &str, seq: u64| GatewayEvent {
        event_id: durable_tool_event_id(&committer.run_id, &identity.call_id, name),
        run_id: committer.run_id.clone(),
        seq,
        event: name.into(),
        data: data.clone(),
        timestamp: timestamp(),
    };
    let events = [
        make_event("tool.output", seq),
        make_event(terminal, seq + 1),
    ];
    let message = SessionMessage {
        id: durable_message_id(&committer.run_id, "result", &identity.call_id),
        session_id: identity.owner.session_id.clone(),
        role: "user".into(),
        content: content.clone(),
        created_at: timestamp(),
        run_id: Some(committer.run_id.clone()),
        finish_reason: None,
        name: Some(identity.tool_name.clone()),
        tool_call_id: Some(identity.call_id.clone()),
        parent_message_id: Some(parent.into()),
        token_estimate: None,
        metadata: json!(publication),
        ordinal: Some(ordinal),
    };
    let selected = if conflict {
        prepared
            .conflict_result
            .clone()
            .unwrap_or_else(|| prepared.canonical_result.clone())
    } else {
        prepared.canonical_result.clone()
    };
    let outcome = ManagedCommitOutcome {
        disposition: status,
        publication,
        canonical_result_ref: selected,
        output_event: ManagedEventRef {
            event_id: events[0].event_id.clone(),
            seq,
        },
        terminal_event: ManagedEventRef {
            event_id: events[1].event_id.clone(),
            seq: seq + 1,
        },
        message: ManagedMessageRef {
            id: message.id.clone(),
            ordinal,
        },
        replayed: false,
    };
    let wire = json!({"output":event_draft(&events[0]),"terminal":event_draft(&events[1]),"outcome":outcome,
        "message":{"id":message.id,"ordinal":ordinal,"content_json":content.to_string(),"parent_message_id":parent}});
    Projection {
        events,
        message,
        wire,
    }
}
fn managed_message_content(
    call_id: &str,
    result: &ToolResult,
) -> Result<JsonValue, EventCommitError> {
    // Durable messages remain bounded, deliberately lossy projections. The
    // immutable canonical object retains all data, errors and artifact refs.
    const PROJECTION_BYTES: usize = 64 * 1024;
    const PREVIEW_CHARS: usize = 4096;
    let content = tool_result_content_json(call_id, result);
    if serde_json::to_vec(&content).map_err(failed)?.len() <= PROJECTION_BYTES {
        return Ok(content);
    }
    let mut preview = result.clone();
    preview.data = json!({});
    preview.truncated = true;
    preview.content = truncate_utf8_chars(&preview.content, PREVIEW_CHARS).0;
    if let Some(error) = preview.error.as_mut() {
        error.message = truncate_utf8_chars(&error.message, PREVIEW_CHARS).0;
    }
    let content = tool_result_content_json(call_id, &preview);
    if serde_json::to_vec(&content).map_err(failed)?.len() > PROJECTION_BYTES {
        return Err(failed("managed message projection exceeds bound"));
    }
    Ok(content)
}

pub(super) fn commit_result(
    committer: &ServiceEventCommitter,
    witness: &ManagedFinalWitness,
) -> Result<JsonValue, EventCommitError> {
    let call = &witness.call;
    let binding = call.binding().map_err(failed)?;
    let observed =
        canonical_tool_result(&witness.prepared.original).map_err(|e| failed(e.code()))?;
    let conflict =
        canonical_tool_result(&witness.prepared.conflict).map_err(|e| failed(e.code()))?;
    let content = managed_message_content(&call.identity.call_id, &observed)?;
    let conflict_content = managed_message_content(&call.identity.call_id, &conflict)?;
    let prepared_json = serde_json::to_string(&witness.prepared.record).map_err(failed)?;
    witness
        .prepared
        .check_ready(&binding.runtime)
        .map_err(failed)?;
    let _gate = committer.commit_gate.lock();
    eligible(committer, call)?;
    call.check_current_generation().map_err(failed)?;
    let (seq, ordinal, parent) = {
        let store = committer.store.read();
        let run = store
            .runs
            .get(&committer.run_id)
            .ok_or(EventCommitError::Terminal)?;
        let session = store
            .sessions
            .get(&run.session_id)
            .ok_or(EventCommitError::MissingParent)?;
        let (parent, name) =
            lookup_tool_call_parent(&store, &run.session_id, &call.identity.call_id)
                .ok_or(EventCommitError::MissingParent)?;
        if name != call.identity.tool_name {
            return Err(EventCommitError::MissingParent);
        }
        (
            event_candidate(run, "tool.output", json!({}), committer.max_event_bytes).seq,
            next_message_ordinal(session),
            parent,
        )
    };
    let normal = projection(
        committer,
        call,
        &witness.prepared.record,
        &observed,
        &ProjectionReservation {
            seq,
            ordinal,
            parent: &parent,
        },
        &content,
        false,
    );
    let losing = projection(
        committer,
        call,
        &witness.prepared.record,
        &conflict,
        &ProjectionReservation {
            seq,
            ordinal,
            parent: &parent,
        },
        &conflict_content,
        true,
    );
    let projections = json!({"normal":normal.wire,"conflict":losing.wire});
    let cut = {
        #[cfg(feature = "workspace-io-fault")]
        {
            binding.runtime.take_sql_fault()
        }
        #[cfg(not(feature = "workspace-io-fault"))]
        {
            String::new()
        }
    };
    let request = json!({"effect_id":call.effect_id,"receipt_id":call.receipt_id,"commit_id":call.receipt_id,"run_id":committer.run_id,"cut":cut,
        "workspace_id":call.identity.workspace.workspace_id,"branch_id":call.identity.workspace.branch_id,"prepared_json":prepared_json,
        "projections_json":projections.to_string(),"max_events":committer.max_events_per_run});
    let outcome = match binding
        .runtime
        .repository
        .command_with_cancellation("effect.commit", &request, &binding.cancel)
        .and_then(|value| crate::effects::journal::decode_record::<ManagedEffectRecord>(&value))
    {
        Ok(Some(record)) => record.outcome,
        Ok(None) => None,
        Err(_) => binding
            .runtime
            .repository
            .get(&ManagedEffectGetRequest {
                owner: call.identity.owner.clone(),
                call_id: call.identity.call_id.clone(),
            })
            .ok()
            .flatten()
            .and_then(|record| record.outcome),
    };
    let Some(outcome) = outcome else {
        call.finalize(false);
        return Err(failed("managed_commit_outcome_unknown_or_staged"));
    };
    call.record_outcome(&outcome);
    #[cfg(feature = "workspace-io-fault")]
    if binding
        .runtime
        .take_fault(crate::effects::ManagedEffectFault::AfterDurableBeforeLive)
    {
        call.finalize(true);
        binding.cancel.request(CancellationReason::ResourceClosed);
        return Err(failed(
            "managed fixture durable commit acknowledged only on exact query; live apply suppressed",
        ));
    }
    let is_conflict = outcome.disposition == ManagedPublicationStatus::Conflict;
    let mut selected = if is_conflict { losing } else { normal };
    if outcome.output_event.event_id != selected.events[0].event_id
        || outcome.terminal_event.event_id != selected.events[1].event_id
        || outcome.message.id != selected.message.id
    {
        return Err(EventCommitError::Corrupt(
            "managed outcome reservations differ".into(),
        ));
    }
    selected.events[0].seq = outcome.output_event.seq;
    selected.events[1].seq = outcome.terminal_event.seq;
    for event in &mut selected.events {
        event.data["managed_publication"] = json!(outcome.publication);
    }
    selected.message.ordinal = Some(outcome.message.ordinal);
    selected.message.metadata = json!(outcome.publication);
    apply(committer, &selected.events, Some(selected.message));
    call.finalize(true);
    drop(_gate);
    let _retention_disposition = call.cleanup_final_view();
    Ok(if is_conflict {
        witness.prepared.conflict.clone()
    } else {
        witness.prepared.original.clone()
    })
}
