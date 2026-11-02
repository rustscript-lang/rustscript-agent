//! Authenticated read-only projection of Native-authorized run summaries.
use crate::{
    AgentGatewayState,
    effects::{ManagedRunEffectError, ManagedRunEffectListRequest},
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

/// Default 32, maximum 128. No caller-provided authority or workspace selectors.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RunEffectsQuery {
    after_effect_id: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    32
}
#[derive(Serialize)]
struct ErrorBody {
    error: ErrorFields,
}
#[derive(Serialize)]
struct ErrorFields {
    code: &'static str,
    message: &'static str,
}
fn failure(error: ManagedRunEffectError) -> Response {
    let (status, code) = match error {
        ManagedRunEffectError::InvalidRequest => {
            (StatusCode::UNPROCESSABLE_ENTITY, "managed_request_invalid")
        }
        ManagedRunEffectError::Unavailable => {
            (StatusCode::FORBIDDEN, "managed_effects_unavailable")
        }
        ManagedRunEffectError::StorageUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "managed_storage_unavailable",
        ),
        ManagedRunEffectError::Cancelled => {
            (StatusCode::REQUEST_TIMEOUT, "managed_query_cancelled")
        }
    };
    (
        status,
        Json(ErrorBody {
            error: ErrorFields {
                code,
                message: code,
            },
        }),
    )
        .into_response()
}
pub(super) async fn list(
    State(state): State<AgentGatewayState>,
    run_id: Result<Path<String>, axum::extract::rejection::PathRejection>,
    query: Result<Query<RunEffectsQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Ok(Path(run_id)) = run_id else {
        return failure(ManagedRunEffectError::InvalidRequest);
    };
    let Ok(Query(query)) = query else {
        return failure(ManagedRunEffectError::InvalidRequest);
    };
    let service = state.service();
    let result = tokio::task::spawn_blocking(move || {
        service.query_managed_run_effects(ManagedRunEffectListRequest {
            run_id,
            after_effect_id: query.after_effect_id,
            limit: query.limit,
        })
    })
    .await;
    match result {
        Ok(Ok(page)) => Json(page).into_response(),
        Ok(Err(error)) => failure(error),
        Err(_) => failure(ManagedRunEffectError::StorageUnavailable),
    }
}
