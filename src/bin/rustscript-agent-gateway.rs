use std::{env, fs, net::SocketAddr};

use rustscript_agent::{AgentGatewayConfig, AgentGatewayState, build_agent_gateway_app};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = env_value(
        "RUSTSCRIPT_AGENT_GATEWAY_ADDR",
        "PD_EDGE_AGENT_GATEWAY_ADDR",
    )?
    .unwrap_or_else(|| "127.0.0.1:8090".to_string())
    .parse::<SocketAddr>()?;
    let bearer_token = env_value(
        "RUSTSCRIPT_AGENT_BEARER_TOKEN",
        "PD_EDGE_AGENT_BEARER_TOKEN",
    )?;
    if bearer_token
        .as_deref()
        .is_some_and(|token| token.trim().is_empty())
    {
        return Err("RUSTSCRIPT_AGENT_BEARER_TOKEN must not be blank".into());
    }
    if bearer_token.is_none()
        && env_value(
            "RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS",
            "PD_EDGE_AGENT_ALLOW_ANONYMOUS",
        )?
        .as_deref()
            != Some("1")
    {
        return Err(
            "RUSTSCRIPT_AGENT_BEARER_TOKEN is required; set RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS=1 only for local testing"
                .into(),
        );
    }
    let mut config = AgentGatewayConfig {
        bearer_token,
        ..AgentGatewayConfig::default()
    };
    if let Some(hosts) = env_value("RUSTSCRIPT_AGENT_ALLOW_HOSTS", "PD_EDGE_AGENT_ALLOW_HOSTS")? {
        config.http.allowed_hosts = split_list(&hosts);
    }
    if let Some(schemes) = env_value(
        "RUSTSCRIPT_AGENT_ALLOW_SCHEMES",
        "PD_EDGE_AGENT_ALLOW_SCHEMES",
    )? {
        config.http.allowed_schemes = split_list(&schemes);
    }
    if let Some(ports) = env_value("RUSTSCRIPT_AGENT_ALLOW_PORTS", "PD_EDGE_AGENT_ALLOW_PORTS")? {
        let mut parsed = Vec::new();
        for port in ports.split(',').map(str::trim) {
            if port.is_empty() {
                return Err("RUSTSCRIPT_AGENT_ALLOW_PORTS contains an empty entry".into());
            }
            parsed
                .push(port.parse::<u16>().map_err(|_| {
                    format!("invalid port in RUSTSCRIPT_AGENT_ALLOW_PORTS: {port}")
                })?);
        }
        if parsed.is_empty() {
            return Err("RUSTSCRIPT_AGENT_ALLOW_PORTS must contain at least one port".into());
        }
        config.http.allowed_ports = parsed;
    }
    if env_value(
        "RUSTSCRIPT_AGENT_ALLOW_PRIVATE_IPS",
        "PD_EDGE_AGENT_ALLOW_PRIVATE_IPS",
    )?
    .as_deref()
        == Some("1")
    {
        config.http.allow_private_ips = true;
    }

    // A7: bounded rate limiting (per peer IP and per bearer account) and
    // the client-disconnect policy. Every bound is validated by
    // `AgentGatewayConfig::validate` before the server starts.
    if let Some(value) = env_value(
        "RUSTSCRIPT_AGENT_RATE_LIMIT_ENABLED",
        "PD_EDGE_AGENT_RATE_LIMIT_ENABLED",
    )? {
        config.rate_limit.enabled = match value.as_str() {
            "0" => false,
            "1" => true,
            other => {
                return Err(format!(
                    "RUSTSCRIPT_AGENT_RATE_LIMIT_ENABLED must be 0 or 1, got {other:?}"
                )
                .into());
            }
        };
    }
    if let Some(value) = env_value(
        "RUSTSCRIPT_AGENT_RATE_LIMIT_IP_BURST",
        "PD_EDGE_AGENT_RATE_LIMIT_IP_BURST",
    )? {
        config.rate_limit.ip_burst = value
            .parse::<u32>()
            .map_err(|_| format!("invalid RUSTSCRIPT_AGENT_RATE_LIMIT_IP_BURST: {value:?}"))?;
    }
    if let Some(value) = env_value(
        "RUSTSCRIPT_AGENT_RATE_LIMIT_ACCOUNT_BURST",
        "PD_EDGE_AGENT_RATE_LIMIT_ACCOUNT_BURST",
    )? {
        config.rate_limit.account_burst = value
            .parse::<u32>()
            .map_err(|_| format!("invalid RUSTSCRIPT_AGENT_RATE_LIMIT_ACCOUNT_BURST: {value:?}"))?;
    }
    if let Some(value) = env_value(
        "RUSTSCRIPT_AGENT_RATE_LIMIT_WINDOW_MS",
        "PD_EDGE_AGENT_RATE_LIMIT_WINDOW_MS",
    )? {
        config.rate_limit.window =
            std::time::Duration::from_millis(value.parse::<u64>().map_err(|_| {
                format!("invalid RUSTSCRIPT_AGENT_RATE_LIMIT_WINDOW_MS: {value:?}")
            })?);
    }
    if let Some(value) = env_value(
        "RUSTSCRIPT_AGENT_RATE_LIMIT_MAX_BUCKETS",
        "PD_EDGE_AGENT_RATE_LIMIT_MAX_BUCKETS",
    )? {
        config.rate_limit.max_buckets = value
            .parse::<usize>()
            .map_err(|_| format!("invalid RUSTSCRIPT_AGENT_RATE_LIMIT_MAX_BUCKETS: {value:?}"))?;
    }
    if let Some(value) = env_value(
        "RUSTSCRIPT_AGENT_CLIENT_DISCONNECT_POLICY",
        "PD_EDGE_AGENT_CLIENT_DISCONNECT_POLICY",
    )? {
        config.client_disconnect_policy =
            rustscript_agent::config::ClientDisconnectPolicy::parse(&value)
                .map_err(std::io::Error::other)?;
    }

    let script = match env_value("RUSTSCRIPT_AGENT_SCRIPT", "PD_EDGE_AGENT_SCRIPT")? {
        Some(path) => Some(fs::read_to_string(path)?),
        None => None,
    };
    let state_db = env_value("RUSTSCRIPT_AGENT_STATE_DB", "PD_EDGE_AGENT_STATE_DB")?;
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
        (None, None) => AgentGatewayState::new(config).map_err(std::io::Error::other)?,
    };

    let listener = tokio::net::TcpListener::bind(address).await?;
    eprintln!(
        "rustscript-agent-gateway listening on http://{}",
        listener.local_addr()?
    );
    let app = build_agent_gateway_app(state.clone());
    tokio::select! {
        // ConnectInfo carries the peer address so the rate limiter can key
        // per-IP buckets; without it every request would share one bucket.
        result = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        ) => result?,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            eprintln!("halting: cancelling active runs with the typed resource-closed reason");
            state.service().halt();
        }
    }
    Ok(())
}

fn env_value(primary: &str, legacy: &str) -> Result<Option<String>, env::VarError> {
    match env::var(primary) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => match env::var(legacy) {
            Ok(value) => {
                eprintln!("warning: {legacy} is deprecated; use {primary}");
                Ok(Some(value))
            }
            Err(env::VarError::NotPresent) => Ok(None),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}
