use std::time::Duration;

use serde_json::json;

use crate::RunCancellation;
use crate::config::ADMISSION_SESSION_PROFILE;
use crate::domain::timestamp;
use crate::effects::ManagedMaintenanceFailure;
use crate::effects::journal::{
    ManagedPublishEligibility, ManagedPublishReceipt, ManagedPublishRequest,
    ManagedWorkspacePublication,
};

use super::AgentService;

fn rejected(code: &str) -> ManagedMaintenanceFailure {
    ManagedMaintenanceFailure::Rejected {
        code: code.to_string(),
    }
}

fn unknown(request_id: &str) -> ManagedMaintenanceFailure {
    ManagedMaintenanceFailure::SubmittedUnknown {
        request_id: request_id.to_string(),
        receipt_lookup_id: request_id.to_string(),
    }
}

fn budget_code(cancellation: &RunCancellation) -> Option<&'static str> {
    if cancellation.has_deadline_overflow() || cancellation.deadline_passed() {
        Some("managed_deadline_elapsed")
    } else if cancellation.requested().is_some() {
        Some("managed_checkpoint_busy")
    } else {
        None
    }
}

fn native_code(error: &str) -> &'static str {
    match error {
        "managed_deadline_elapsed" | "deadline_elapsed" => "managed_deadline_elapsed",
        "managed_checkpoint_busy" | "cancelled" => "managed_checkpoint_busy",
        "managed_request_invalid" | "managed identifier malformed" => "managed_request_invalid",
        "managed_branch_missing" => "managed_branch_missing",
        "managed_source_conflict" | "managed_transaction_rolled_back" => "managed_source_conflict",
        "managed_request_conflict" => "managed_request_conflict",
        "managed_metadata_budget_exceeded" => "managed_metadata_budget_exceeded",
        "managed_process_lineage_unsupported" => "managed_process_lineage_unsupported",
        "managed_authority_required" => "managed_authority_required",
        "managed_management_denied" => "managed_management_denied",
        "managed_storage_unavailable" => "managed_storage_unavailable",
        "managed_submitted_unknown" => "managed_submitted_unknown",
        other if other.contains("deadline") => "managed_deadline_elapsed",
        other if other.contains("cancel") => "managed_checkpoint_busy",
        other if other.contains("missing") && !other.contains('/') => "managed_branch_missing",
        _ => "managed_storage_unavailable",
    }
}

fn authority_code(error: &str) -> &'static str {
    if error.contains("deadline") {
        "managed_deadline_elapsed"
    } else if error.contains("cancel") {
        "managed_checkpoint_busy"
    } else if error.contains("missing") && !error.contains('/') {
        "managed_branch_missing"
    } else {
        "managed_authority_required"
    }
}

fn eligibility_code(code: &str) -> &'static str {
    match code {
        "foreign" => "managed_authority_required",
        "missing" => "managed_branch_missing",
        "stale" => "managed_source_conflict",
        "busy" => "managed_checkpoint_busy",
        "conflict" => "managed_request_conflict",
        _ => "managed_source_conflict",
    }
}

fn pointer_matches(pointer: &ManagedWorkspacePublication, receipt: &ManagedPublishReceipt) -> bool {
    pointer.workspace_id == receipt.workspace_id
        && pointer.profile == receipt.profile
        && pointer.branch_id == receipt.branch_id
        && pointer.epoch == receipt.epoch
        && pointer.head_object_id == receipt.head_object_id
        && pointer.head_version == receipt.head_version
        && pointer.previous_published_head == receipt.previous_published_head
        && pointer.request_id == receipt.request_id
        && pointer.published_at_ms == receipt.published_at_ms
}

impl AgentService {
    pub async fn publish_managed_workspace(
        &self,
        request: ManagedPublishRequest,
    ) -> Result<ManagedPublishReceipt, ManagedMaintenanceFailure> {
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(5));
        self.publish_managed_workspace_with_cancellation(request, cancellation)
            .await
    }

    pub(crate) async fn publish_managed_workspace_with_cancellation(
        &self,
        request: ManagedPublishRequest,
        cancellation: RunCancellation,
    ) -> Result<ManagedPublishReceipt, ManagedMaintenanceFailure> {
        let service = self.clone();
        tokio::task::spawn_blocking(move || {
            service.publish_managed_workspace_blocking(request, &cancellation)
        })
        .await
        .map_err(|_| rejected("managed_storage_unavailable"))?
    }

    pub(crate) fn publish_managed_workspace_blocking(
        &self,
        request: ManagedPublishRequest,
        cancellation: &RunCancellation,
    ) -> Result<ManagedPublishReceipt, ManagedMaintenanceFailure> {
        crate::effects::journal::validate_maintenance_value::<ManagedPublishRequest>(
            &serde_json::to_value(&request)
                .map_err(|_| rejected("managed_metadata_budget_exceeded"))?,
        )
        .map_err(|_| rejected("managed_request_invalid"))?;
        let config = self
            .inner
            .config
            .managed_workspace
            .as_ref()
            .ok_or_else(|| rejected("managed_authority_required"))?;
        if self.inner.config.bearer_token.is_none() || !config.maintenance_policy.publish {
            return Err(rejected("managed_management_denied"));
        }
        if let Some(code) = budget_code(cancellation) {
            return Err(rejected(code));
        }
        crate::effects::broker::validate_id("ws", &request.workspace_id)
            .map_err(|_| rejected("managed_request_invalid"))?;
        crate::effects::broker::validate_id("br", &request.branch_id)
            .map_err(|_| rejected("managed_branch_missing"))?;
        if request.workspace_id != request.expected_head.workspace_id
            || request.branch_id != request.expected_head.branch_id
        {
            return Err(rejected("managed_authority_required"));
        }
        if request.expected_head.process_lineage_tainted {
            return Err(rejected("managed_process_lineage_unsupported"));
        }
        uuid::Uuid::parse_str(&request.request_id)
            .map_err(|_| rejected("managed_request_conflict"))?;
        let proof = serde_json::to_string(&request)
            .map_err(|_| rejected("managed_metadata_budget_exceeded"))?;
        let runtime = self
            .inner
            .managed_effects
            .read()
            .clone()
            .ok_or_else(|| rejected("managed_authority_required"))?;
        let source_root = config
            .source_root
            .to_str()
            .ok_or_else(|| rejected("managed_authority_required"))?;
        if let Some(code) = budget_code(cancellation) {
            return Err(rejected(code));
        }
        let (_, authority) = self
            .resolve_workspace_admission(Some(source_root), None, cancellation, false)
            .map_err(|_| {
                budget_code(cancellation)
                    .map(rejected)
                    .unwrap_or_else(|| rejected("managed_authority_required"))
            })?;
        let authority = authority.ok_or_else(|| rejected("managed_authority_required"))?;
        if let Some(code) = budget_code(cancellation) {
            return Err(rejected(code));
        }
        runtime
            .authorize_workspace_query(
                &authority,
                ADMISSION_SESSION_PROFILE,
                &request.workspace_id,
                cancellation,
            )
            .map_err(|error| {
                budget_code(cancellation)
                    .map(rejected)
                    .unwrap_or_else(|| rejected(authority_code(&error)))
            })?;
        if let Some(code) = budget_code(cancellation) {
            return Err(rejected(code));
        }
        let workspace = runtime
            .authorized_workspace(
                &authority,
                ADMISSION_SESSION_PROFILE,
                &request.workspace_id,
                cancellation,
            )
            .map_err(|error| {
                budget_code(cancellation)
                    .map(rejected)
                    .unwrap_or_else(|| rejected(authority_code(&error)))
            })?;
        if workspace.profile != ADMISSION_SESSION_PROFILE {
            return Err(rejected("managed_authority_required"));
        }
        if let Some(saved) = runtime
            .repository
            .publish_receipt(&request.workspace_id, &request.request_id, cancellation)
            .map_err(|error| rejected(native_code(&error)))?
        {
            return if saved.proof == proof {
                Ok(saved.receipt)
            } else {
                Err(rejected("managed_request_conflict"))
            };
        }
        if let Some(code) = budget_code(cancellation) {
            return Err(rejected(code));
        }
        let mut document = json!({
            "workspace_id": request.workspace_id,
            "branch_id": request.branch_id,
            "profile": workspace.profile,
            "expected_head": request.expected_head,
            "request_id": request.request_id,
            "proof": proof,
            "now_ms": timestamp(),
            "expected_revision": 0,
        });
        let eligibility = runtime
            .repository
            .publish_eligibility(&document, cancellation)
            .map_err(|error| rejected(native_code(&error)))?;
        if eligibility.code != "idle" {
            return Err(rejected(eligibility_code(&eligibility.code)));
        }
        document["expected_revision"] = json!(eligibility.revision);
        if let Some(code) = budget_code(cancellation) {
            return Err(rejected(code));
        }
        if runtime.source_has_active_writer(&request.branch_id) {
            return Err(rejected("managed_checkpoint_busy"));
        }
        if let Some(code) = budget_code(cancellation) {
            return Err(rejected(code));
        }
        let mut identity = workspace.identity.clone();
        identity.branch_id = request.branch_id.clone();
        let claim = runtime
            .repository
            .maintenance_claim(
                identity,
                proof.clone(),
                request.request_id.clone(),
                "publish",
            )
            .map_err(|_| rejected("managed_storage_unavailable"))?;
        match runtime
            .repository
            .publish_submit(&document, cancellation, &claim)
        {
            Ok(receipt) => confirm_publication(
                &runtime,
                &request,
                &workspace.profile,
                eligibility.revision,
                receipt,
                cancellation,
                claim.submitted(),
            ),
            Err(error) if error == "managed_submitted_unknown" || claim.submitted() => {
                saved_or_unknown(&runtime, &request, &proof, cancellation)
            }
            Err(error) if error == "managed_transaction_rolled_back" => {
                if let Some(saved) = runtime
                    .repository
                    .publish_receipt(&request.workspace_id, &request.request_id, cancellation)
                    .ok()
                    .flatten()
                    && saved.proof == proof
                {
                    return Ok(saved.receipt);
                }
                let again = runtime
                    .repository
                    .publish_eligibility(&document, cancellation)
                    .unwrap_or(ManagedPublishEligibility {
                        code: "stale".into(),
                        revision: eligibility.revision,
                    });
                if again.code == "idle" && again.revision != eligibility.revision {
                    Err(rejected("managed_source_conflict"))
                } else {
                    Err(rejected(eligibility_code(&again.code)))
                }
            }
            Err(error) => Err(rejected(native_code(&error))),
        }
    }
}

fn confirm_publication(
    runtime: &crate::effects::broker::ManagedEffectRuntime,
    request: &ManagedPublishRequest,
    profile: &str,
    expected_revision: u64,
    receipt: ManagedPublishReceipt,
    cancellation: &RunCancellation,
    submitted: bool,
) -> Result<ManagedPublishReceipt, ManagedMaintenanceFailure> {
    let head_matches = receipt.status == "committed"
        && receipt.workspace_id == request.workspace_id
        && receipt.profile == profile
        && receipt.branch_id == request.branch_id
        && receipt.epoch == request.expected_head.epoch
        && receipt.head_object_id == request.expected_head.head_object_id
        && receipt.head_version == request.expected_head.head_version
        && receipt.request_id == request.request_id
        && (expected_revision > 0 || receipt.previous_published_head.is_none());
    let pointer = runtime
        .repository
        .publication(&request.workspace_id, profile, cancellation)
        .ok()
        .flatten();
    if head_matches && pointer.is_some_and(|pointer| pointer_matches(&pointer, &receipt)) {
        Ok(receipt)
    } else if submitted {
        Err(unknown(&request.request_id))
    } else {
        Err(rejected("managed_source_conflict"))
    }
}

fn saved_or_unknown(
    runtime: &crate::effects::broker::ManagedEffectRuntime,
    request: &ManagedPublishRequest,
    proof: &str,
    cancellation: &RunCancellation,
) -> Result<ManagedPublishReceipt, ManagedMaintenanceFailure> {
    if let Ok(Some(saved)) =
        runtime
            .repository
            .publish_receipt(&request.workspace_id, &request.request_id, cancellation)
        && saved.proof == proof
    {
        return Ok(saved.receipt);
    }
    Err(unknown(&request.request_id))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::CancellationReason;
    use crate::RunCancellation;
    use crate::effects::ManagedPublishRequest;

    fn request() -> ManagedPublishRequest {
        ManagedPublishRequest {
            workspace_id: format!("ws-{}", "ab".repeat(16)),
            branch_id: format!("br-{}", "ab".repeat(16)),
            expected_head: crate::effects::ManagedWorkspaceHead {
                workspace_id: format!("ws-{}", "ab".repeat(16)),
                branch_id: format!("br-{}", "ab".repeat(16)),
                epoch: 1,
                head_object_id: format!("obj-{}", "ab".repeat(16)),
                head_version: 1,
                store_id: format!("store-{}", "ab".repeat(16)),
                schema_version: 1,
                process_lineage_tainted: false,
            },
            request_id: "00000000-0000-4000-8000-000000000001".into(),
        }
    }

    fn open(publish: bool) -> crate::AgentGatewayState {
        let root = std::path::PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").unwrap())
            .join(format!("publish-budget-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let mut config = crate::AgentGatewayConfig {
            bearer_token: Some("synthetic-maintenance-fixture".into()),
            managed_workspace: Some(
                crate::config::ManagedWorkspaceConfig::for_workspace(&workspace).unwrap(),
            ),
            ..Default::default()
        };
        config
            .managed_workspace
            .as_mut()
            .unwrap()
            .maintenance_policy
            .publish = publish;
        crate::AgentGatewayState::with_sqlite_path(config, root.join("gateway.sqlite")).unwrap()
    }

    #[tokio::test]
    async fn disabled_publish_and_elapsed_budget_fail_closed() {
        let denied = open(false)
            .service()
            .publish_managed_workspace_blocking(
                request(),
                &RunCancellation::with_timeout(Duration::from_secs(5)),
            )
            .unwrap_err();
        assert_eq!(denied.to_string(), "managed_management_denied");
        let expired = RunCancellation::with_timeout(Duration::ZERO);
        let deadline = open(true)
            .service()
            .publish_managed_workspace_blocking(request(), &expired)
            .unwrap_err();
        assert_eq!(deadline.to_string(), "managed_deadline_elapsed");
        let cancelled = RunCancellation::with_timeout(Duration::from_secs(5));
        cancelled.request(CancellationReason::Requested);
        let busy = open(true)
            .service()
            .publish_managed_workspace_blocking(request(), &cancelled)
            .unwrap_err();
        assert_eq!(busy.to_string(), "managed_checkpoint_busy");
    }
}
