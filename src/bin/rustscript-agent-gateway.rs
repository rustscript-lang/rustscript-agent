use std::{env, fs, net::SocketAddr};

use edge::init_logging;
use rustscript_agent::{AgentGatewayConfig, AgentGatewayState, build_agent_gateway_app};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging(false)?;
    let address = env::var("PD_EDGE_AGENT_GATEWAY_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8090".to_string())
        .parse::<SocketAddr>()?;
    let mut config = AgentGatewayConfig {
        bearer_token: env::var("PD_EDGE_AGENT_BEARER_TOKEN").ok(),
        ..AgentGatewayConfig::default()
    };
    if let Ok(hosts) = env::var("PD_EDGE_AGENT_ALLOW_HOSTS") {
        config.http.allowed_hosts = split_list(&hosts);
    }
    if let Ok(schemes) = env::var("PD_EDGE_AGENT_ALLOW_SCHEMES") {
        config.http.allowed_schemes = split_list(&schemes);
    }
    if let Ok(ports) = env::var("PD_EDGE_AGENT_ALLOW_PORTS") {
        config.http.allowed_ports = ports
            .split(',')
            .filter_map(|port| port.trim().parse::<u16>().ok())
            .collect();
    }
    if env::var("PD_EDGE_AGENT_ALLOW_PRIVATE_IPS").as_deref() == Ok("1") {
        config.http.allow_private_ips = true;
    }

    let script = match env::var("PD_EDGE_AGENT_SCRIPT") {
        Ok(path) => Some(fs::read_to_string(path)?),
        Err(env::VarError::NotPresent) => None,
        Err(error) => return Err(error.into()),
    };
    let state_db = env::var("PD_EDGE_AGENT_STATE_DB").ok();
    let state = match (script, state_db) {
        (Some(source), Some(path)) => {
            AgentGatewayState::with_agent_source_and_sqlite(config, source, path)
                .map_err(std::io::Error::other)?
        }
        (Some(source), None) => {
            AgentGatewayState::with_agent_source(config, source).map_err(std::io::Error::other)?
        }
        (None, Some(path)) => {
            AgentGatewayState::with_sqlite_path(config, path).map_err(std::io::Error::other)?
        }
        (None, None) => AgentGatewayState::new(config),
    };

    let listener = tokio::net::TcpListener::bind(address).await?;
    eprintln!(
        "pd-edge-agent-gateway listening on http://{}",
        listener.local_addr()?
    );
    axum::serve(listener, build_agent_gateway_app(state)).await?;
    Ok(())
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}
