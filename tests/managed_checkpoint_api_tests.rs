//! Managed maintenance HTTP contracts exercised over an owned loopback socket.

use std::{net::SocketAddr, time::Duration};

use rustscript_agent::{AgentGatewayConfig, AgentGatewayState, build_agent_gateway_app};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn management_routes_require_configured_authentication() {
    let state = AgentGatewayState::new(AgentGatewayConfig::default()).expect("fixture gateway");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("owned listener");
    let address = listener.local_addr().expect("listener address");
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            build_agent_gateway_app(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = stopped.await;
        })
        .await
    });
    // Always close and join the owned server before propagating an assertion.
    let outcome = tokio::spawn(async move {
        for action in ["checkpoints", "restore", "branches", "publish"] {
            let mut connection = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect owned listener");
            let request = format!(
                "POST /v1/workspaces/workspace-fixture/{action} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            );
            connection
                .write_all(request.as_bytes())
                .await
                .expect("send management request");
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), connection.read_to_end(&mut response))
                .await
                .expect("bounded response")
                .expect("read response");
            let response = String::from_utf8(response).expect("HTTP response UTF-8");
            assert!(
                response.starts_with("HTTP/1.1 403"),
                "unconfigured management authentication must fail closed before DTO parsing for {action}; received {}",
                response.lines().next().unwrap_or_default()
            );
            let (_, body) = response.split_once("\r\n\r\n").expect("HTTP body");
            let body: serde_json::Value = serde_json::from_str(body).expect("static JSON error");
            assert_eq!(body["error"]["code"], "managed_management_denied");
        }
    })
    .await;
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server shutdown deadline")
        .expect("server task joined")
        .expect("server closed");
    drop(std::net::TcpListener::bind(address).expect("listener released"));
    if let Err(error) = outcome {
        std::panic::resume_unwind(error.into_panic());
    }
}
