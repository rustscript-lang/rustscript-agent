//! Plugin graph administration over the production router.
//! A verified owner marker is not a grant by itself. The trusted host binding
//! supplies InstallAuthorization. Request JSON cannot.

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use super::AgentGatewayState;

/// Published only after the gateway bearer check succeeds. It carries no token.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VerifiedOwnerCredential;

pub(crate) async fn install(
    State(state): State<AgentGatewayState>,
    owner: Option<Extension<VerifiedOwnerCredential>>,
    body: Bytes,
) -> Response {
    dispatch(&state, owner, Some(&body), |service, parsed| {
        service.install_controlled_plugin(parsed)
    })
}

pub(crate) async fn resolve(
    State(state): State<AgentGatewayState>,
    owner: Option<Extension<VerifiedOwnerCredential>>,
    body: Bytes,
) -> Response {
    dispatch(&state, owner, Some(&body), |service, parsed| {
        service.resolve_controlled_graph(parsed)
    })
}

pub(crate) async fn prepare(
    State(state): State<AgentGatewayState>,
    owner: Option<Extension<VerifiedOwnerCredential>>,
    Path(graph_id): Path<String>,
) -> Response {
    dispatch(&state, owner, None, |service, _| {
        service.prepare_controlled_graph(&graph_id)
    })
}

pub(crate) async fn get_graph(
    State(state): State<AgentGatewayState>,
    owner: Option<Extension<VerifiedOwnerCredential>>,
    Path(graph_id): Path<String>,
) -> Response {
    dispatch(&state, owner, None, |service, _| {
        service.plugin_graph_view(&graph_id)
    })
}

pub(crate) async fn activate(
    State(state): State<AgentGatewayState>,
    owner: Option<Extension<VerifiedOwnerCredential>>,
    body: Bytes,
) -> Response {
    dispatch(&state, owner, Some(&body), |service, parsed| {
        service.activate_controlled_graph(parsed)
    })
}

pub(crate) async fn rollback(
    State(state): State<AgentGatewayState>,
    owner: Option<Extension<VerifiedOwnerCredential>>,
    Path(activation_id): Path<String>,
) -> Response {
    dispatch(&state, owner, None, |service, _| {
        service.rollback_controlled_activation(&activation_id)
    })
}

fn dispatch(
    state: &AgentGatewayState,
    owner: Option<Extension<VerifiedOwnerCredential>>,
    body: Option<&Bytes>,
    operation: impl FnOnce(&crate::service::AgentService, &Value) -> Result<Value, &'static str>,
) -> Response {
    if owner.is_none() {
        return static_error(StatusCode::FORBIDDEN, "managed_management_denied");
    }
    if !state.service().plugin_control_configured() {
        return static_error(StatusCode::FORBIDDEN, "plugin_control_unconfigured");
    }
    let parsed = match body {
        Some(bytes) => match serde_json::from_slice::<Value>(bytes) {
            Ok(value) if value.is_object() => value,
            _ => return static_error(StatusCode::UNPROCESSABLE_ENTITY, "plugin_request_invalid"),
        },
        None => Value::Null,
    };
    match operation(state.service().as_ref(), &parsed) {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(code) => static_error(status_for(code), code),
    }
}

fn status_for(code: &str) -> StatusCode {
    match code {
        "managed_management_denied"
        | "plugin_control_unconfigured"
        | "plugin_space_mismatch"
        | "plugin_publisher_unauthorized" => StatusCode::FORBIDDEN,
        "plugin_graph_missing" | "plugin_activation_missing" => StatusCode::NOT_FOUND,
        "plugin_activation_conflict" | "plugin_graph_revoked" => StatusCode::CONFLICT,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    }
}

fn static_error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({"error":{"code":code,"message":code}}))).into_response()
}
