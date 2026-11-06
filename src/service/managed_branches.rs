//! Non-destructive managed branch creation. Does not retire or close the source.

use super::*;
use crate::effects::journal::{
    ManagedBranchCreateRequest, ManagedBranchReceipt, ManagedSavedBranchReceipt, ManagedSourceCas,
};

fn failure(code: &'static str) -> String {
    code.into()
}

fn native_branch_code(error: &str) -> &'static str {
    match error {
        "managed_checkpoint_busy" => "managed_checkpoint_busy",
        "managed_branch_missing" => "managed_branch_missing",
        _ => "managed_storage_unavailable",
    }
}

impl AgentService {
    pub async fn create_managed_branch(
        &self,
        request: ManagedBranchCreateRequest,
    ) -> Result<ManagedBranchReceipt, String> {
        let service = self.clone();
        tokio::task::spawn_blocking(move || service.create_managed_branch_blocking(request))
            .await
            .map_err(|_| failure("managed_storage_unavailable"))?
    }

    fn create_managed_branch_blocking(
        &self,
        request: ManagedBranchCreateRequest,
    ) -> Result<ManagedBranchReceipt, String> {
        let config = self
            .inner
            .config
            .managed_workspace
            .as_ref()
            .ok_or("managed_authority_required")?;
        if self.inner.config.bearer_token.is_none() || !config.maintenance_policy.branch {
            return Err(failure("managed_management_denied"));
        }
        crate::effects::broker::validate_id("ws", &request.workspace_id)
            .map_err(|_| failure("managed_authority_required"))?;
        crate::effects::broker::validate_id("br", &request.source_branch_id)
            .map_err(|_| failure("managed_branch_missing"))?;
        if Uuid::parse_str(&request.request_id).is_err() {
            return Err(failure("managed_request_conflict"));
        }
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(5));
        let runtime = self
            .inner
            .managed_effects
            .read()
            .clone()
            .ok_or("managed_authority_required")?;
        let source_root = config
            .source_root
            .to_str()
            .ok_or("managed_authority_required")?;
        let (_, authority) = self
            .resolve_workspace_admission(Some(source_root), None, &cancellation, false)
            .map_err(|_| failure("managed_authority_required"))?;
        let authority = authority.ok_or("managed_authority_required")?;
        let workspace = runtime
            .authorized_workspace(
                &authority,
                ADMISSION_SESSION_PROFILE,
                &request.workspace_id,
                &cancellation,
            )
            .map_err(|_| failure("managed_authority_required"))?;
        let proof = serde_json::to_string(&request)
            .map_err(|_| failure("managed_metadata_budget_exceeded"))?;
        if let Some(saved) = runtime
            .repository
            .branch_receipt(&request.workspace_id, &request.request_id, &cancellation)
            .map_err(|_| failure("managed_storage_unavailable"))?
        {
            return replayed_branch(
                &runtime,
                &workspace.identity,
                &proof,
                saved,
                &cancellation,
            );
        }
        // One atomic reservation on the shared branch writer gate excludes a
        // new producer/file writer for the head read and durable branch
        // creation window. A persisted branch that this process has not touched
        // yet is first established through its typed durable head and the
        // startup restart gate: an empty in-memory map is never proof that
        // nobody owns the branch and must not surface as an unexplained missing
        // branch.
        let mut source_identity = workspace.identity.clone();
        source_identity.branch_id = request.source_branch_id.clone();
        let holder = format!("branch:{}", request.request_id);
        let _reservation = match runtime.reserve_maintenance(&request.source_branch_id, &holder) {
            Ok(reservation) => reservation,
            Err(error) if error == "managed_branch_missing" => {
                runtime
                    .ensure_branch_owner(&source_identity, &cancellation)
                    .map_err(|error| match error.as_str() {
                        "managed_branch_missing" => failure("managed_branch_missing"),
                        "managed_source_conflict" => failure("managed_source_conflict"),
                        "managed_restart_unresolved" => failure("managed_checkpoint_busy"),
                        _ => failure("managed_storage_unavailable"),
                    })?;
                runtime
                    .reserve_maintenance(&request.source_branch_id, &holder)
                    .map_err(|error| failure(native_branch_code(&error)))?
            }
            Err(error) => return Err(failure(native_branch_code(&error))),
        };
        let head = runtime
            .repository
            .head(&source_identity, &cancellation)
            .map_err(|error| {
                if error.contains("missing") {
                    failure("managed_branch_missing")
                } else {
                    failure("managed_storage_unavailable")
                }
            })?;
        if head.workspace_id != request.workspace_id {
            return Err(failure("managed_authority_required"));
        }
        if head.process_lineage_tainted {
            return Err(failure("managed_process_lineage_unsupported"));
        }
        let source = ManagedSourceCas {
            store_id: head.store_id.clone(),
            workspace_id: head.workspace_id.clone(),
            branch_id: head.branch_id.clone(),
            epoch: head.epoch,
            head_object_id: head.head_object_id.clone(),
            head_version: head.head_version,
        };
        if request
            .expected_source
            .as_ref()
            .is_some_and(|expected| expected != &source)
        {
            return Err(failure("managed_source_conflict"));
        }
        let (head_object_id, checkpoint_id) =
            if let Some(checkpoint_id) = request.checkpoint_id.clone() {
                let lookup = runtime
                    .repository
                    .checkpoint_get(&request.workspace_id, &checkpoint_id, &cancellation)
                    .map_err(|_| failure("managed_checkpoint_missing"))?;
                let checkpoint = lookup.checkpoint;
                if checkpoint.workspace_id != request.workspace_id
                    || checkpoint.source_branch_id != request.source_branch_id
                {
                    return Err(failure("managed_source_conflict"));
                }
                runtime
                    .verify_tree(&checkpoint.frozen_root.object_id)
                    .map_err(|_| failure("managed_artifact_unavailable"))?;
                (checkpoint.frozen_root.object_id, Some(checkpoint_id))
            } else {
                if request.expected_source.is_none() {
                    return Err(failure("managed_source_conflict"));
                }
                if runtime.source_has_foreign_writer(&request.source_branch_id, &holder) {
                    return Err(failure("managed_checkpoint_busy"));
                }
                runtime
                    .verify_tree(&source.head_object_id)
                    .map_err(|_| failure("managed_artifact_unavailable"))?;
                (source.head_object_id.clone(), None)
            };
        let epoch = source
            .epoch
            .checked_add(1)
            .filter(|epoch| *epoch <= i64::MAX as u64)
            .ok_or_else(|| failure("managed_source_conflict"))?;
        let mut branch_identity = source_identity.clone();
        branch_identity.branch_id = crate::effects::broker::fresh("br");
        let branch = ManagedSourceCas {
            store_id: source.store_id.clone(),
            workspace_id: source.workspace_id.clone(),
            branch_id: branch_identity.branch_id.clone(),
            epoch,
            head_object_id: head_object_id.clone(),
            head_version: 1,
        };
        let receipt = ManagedBranchReceipt {
            request_id: request.request_id.clone(),
            checkpoint_id: checkpoint_id.clone(),
            source: source.clone(),
            branch: branch.clone(),
            replayed: false,
        };
        let origin = json!({
            "kind": if checkpoint_id.is_some() { "checkpoint" } else { "head" },
            "workspace_id": source.workspace_id,
            "source_branch_id": source.branch_id,
            "checkpoint_id": checkpoint_id,
            "head_object_id": head_object_id,
            "source_epoch": source.epoch,
        });
        let document = json!({
            "source": source,
            "branch": branch,
            "checkpoint_id": checkpoint_id,
            "request_id": request.request_id,
            "proof": proof,
            "receipt": receipt,
            "origin": origin,
        });
        let committed = runtime
            .repository
            .branch_submit(&document, &cancellation)
            .map_err(|error| {
                if error == "managed_source_conflict" || error == "managed_metadata_budget_exceeded"
                {
                    error
                } else {
                    failure("managed_storage_unavailable")
                }
            })?;
        let replayed = committed.branch.branch_id != branch.branch_id;
        let mut remembered = source_identity;
        remembered.branch_id = committed.branch.branch_id.clone();
        remembered.store_id = committed.branch.store_id.clone();
        runtime
            .remember_branch(&remembered, committed.branch.epoch, &cancellation)
            .map_err(|_| failure("managed_storage_unavailable"))?;
        Ok(ManagedBranchReceipt {
            replayed,
            ..committed
        })
    }
}

fn replayed_branch(
    runtime: &crate::effects::broker::ManagedEffectRuntime,
    workspace: &crate::effects::journal::ManagedWorkspaceIdentity,
    proof: &str,
    saved: ManagedSavedBranchReceipt,
    cancellation: &RunCancellation,
) -> Result<ManagedBranchReceipt, String> {
    if saved.proof != proof {
        return Err(failure("managed_request_conflict"));
    }
    if saved.origin.get("workspace_id").and_then(JsonValue::as_str)
        != Some(workspace.workspace_id.as_str())
        || saved.receipt.branch.workspace_id != workspace.workspace_id
    {
        return Err(failure("managed_authority_required"));
    }
    let mut identity = workspace.clone();
    identity.branch_id = saved.receipt.branch.branch_id.clone();
    identity.store_id = saved.receipt.branch.store_id.clone();
    runtime
        .remember_branch(&identity, saved.receipt.branch.epoch, cancellation)
        .map_err(|_| failure("managed_storage_unavailable"))?;
    Ok(ManagedBranchReceipt {
        replayed: true,
        ..saved.receipt
    })
}
