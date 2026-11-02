//! Authenticated managed-workspace maintenance transport.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::{AgentGatewayState, effects::ManagedCheckpointCreateRequest};

#[derive(Serialize)]
struct MaintenanceErrorBody {
    error: MaintenanceError,
}

#[derive(Serialize)]
struct MaintenanceError {
    code: &'static str,
    message: &'static str,
}

fn rejected(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        Json(MaintenanceErrorBody {
            error: MaintenanceError {
                code,
                message: code,
            },
        }),
    )
        .into_response()
}

pub(super) async fn create_checkpoint(
    State(state): State<AgentGatewayState>,
    Path(workspace_id): Path<String>,
    request: Result<Json<ManagedCheckpointCreateRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let request = match request {
        Ok(Json(request)) => request,
        Err(rejection) => return rejected(rejection.status(), "managed_request_invalid"),
    };
    if workspace_id != request.workspace_id {
        return rejected(StatusCode::FORBIDDEN, "managed_authority_required");
    }
    match state.service().create_managed_checkpoint(request).await {
        Ok(receipt) => (StatusCode::CREATED, Json(receipt)).into_response(),
        Err(
            error @ crate::effects::journal::ManagedMaintenanceFailure::SubmittedUnknown { .. },
        ) => (StatusCode::ACCEPTED, Json(error)).into_response(),
        Err(error) => maintenance_failure(&error.to_string()),
    }
}

fn maintenance_failure(error: &str) -> Response {
    let (status, code) = match error {
        "managed_management_denied" => (StatusCode::FORBIDDEN, "managed_management_denied"),
        "managed_authority_required" => (StatusCode::FORBIDDEN, "managed_authority_required"),
        "managed_source_conflict" => (StatusCode::CONFLICT, "managed_source_conflict"),
        "managed_checkpoint_conflict" => (StatusCode::CONFLICT, "managed_checkpoint_conflict"),
        "managed_request_conflict" => (StatusCode::CONFLICT, "managed_request_conflict"),
        "managed_request_invalid" => (StatusCode::BAD_REQUEST, "managed_request_invalid"),
        "managed_checkpoint_busy" => (StatusCode::CONFLICT, "managed_checkpoint_busy"),
        "managed_branch_missing" => (StatusCode::NOT_FOUND, "managed_branch_missing"),
        "managed_checkpoint_missing" => (StatusCode::NOT_FOUND, "managed_checkpoint_missing"),
        "managed_restore_busy" => (StatusCode::CONFLICT, "managed_restore_busy"),
        "managed_process_lineage_unsupported" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "managed_process_lineage_unsupported",
        ),
        "managed_state_unsupported" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "managed_state_unsupported",
        ),
        "managed_history_incomplete" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "managed_history_incomplete",
        ),
        "managed_history_budget_exceeded" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "managed_history_budget_exceeded",
        ),
        "managed_artifact_unavailable" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "managed_artifact_unavailable",
        ),
        "plugin_graph_revoked" => (StatusCode::CONFLICT, "plugin_graph_revoked"),
        "plugin_graph_pin_required" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "plugin_graph_pin_required",
        ),
        "plugin_artifact_unavailable" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "plugin_artifact_unavailable",
        ),
        "harness_policy_selection_invalid" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "harness_policy_selection_invalid",
        ),
        "managed_metadata_budget_exceeded" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "managed_metadata_budget_exceeded",
        ),
        "managed_deadline_elapsed" => (StatusCode::REQUEST_TIMEOUT, "managed_deadline_elapsed"),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "managed_storage_unavailable",
        ),
    };
    rejected(status, code)
}

pub(super) async fn restore_checkpoint(
    State(state): State<AgentGatewayState>,
    Path(workspace_id): Path<String>,
    request: Result<
        Json<crate::effects::ManagedRestoreAndAdmitRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    let request = match request {
        Ok(Json(request)) => request,
        Err(rejection) => return rejected(rejection.status(), "managed_request_invalid"),
    };
    if workspace_id != request.workspace_id {
        return rejected(StatusCode::FORBIDDEN, "managed_authority_required");
    }
    match state
        .service()
        .restore_managed_checkpoint_and_admit(request)
        .await
    {
        Ok(receipt) => {
            let service = state.service();
            service.start_managed_restore_worker(&receipt.new_run_id);
            (StatusCode::ACCEPTED, Json(receipt)).into_response()
        }
        Err(
            error @ crate::effects::journal::ManagedMaintenanceFailure::SubmittedUnknown { .. },
        ) => (StatusCode::ACCEPTED, Json(error)).into_response(),
        Err(error) => maintenance_failure(&error.to_string()),
    }
}

pub(super) async fn create_branch(
    State(state): State<AgentGatewayState>,
    Path(workspace_id): Path<String>,
    request: Result<
        Json<crate::effects::ManagedBranchCreateRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    let request = match request {
        Ok(Json(request)) => request,
        Err(rejection) => return rejected(rejection.status(), "managed_request_invalid"),
    };
    if workspace_id != request.workspace_id {
        return rejected(StatusCode::FORBIDDEN, "managed_authority_required");
    }
    match state.service().create_managed_branch(request).await {
        Ok(receipt) => (StatusCode::CREATED, Json(receipt)).into_response(),
        Err(error) => maintenance_failure(&error),
    }
}

pub(super) async fn publish_workspace(
    State(state): State<AgentGatewayState>,
    Path(workspace_id): Path<String>,
    request: Result<
        Json<crate::effects::ManagedPublishRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    let request = match request {
        Ok(Json(request)) => request,
        Err(rejection) => return rejected(rejection.status(), "managed_request_invalid"),
    };
    if workspace_id != request.workspace_id {
        return rejected(StatusCode::FORBIDDEN, "managed_authority_required");
    }
    match state.service().publish_managed_workspace(request).await {
        Ok(receipt) => (StatusCode::OK, Json(receipt)).into_response(),
        Err(
            error @ crate::effects::journal::ManagedMaintenanceFailure::SubmittedUnknown { .. },
        ) => (StatusCode::ACCEPTED, Json(error)).into_response(),
        Err(error) => maintenance_failure(&error.to_string()),
    }
}
