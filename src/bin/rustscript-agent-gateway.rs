use std::{
    env, fs,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rustscript_agent::{
    AgentGatewayConfig, AgentGatewayState, TelegramConfig, build_agent_gateway_app,
    gateway::telegram::{TelegramAdapter, spawn_telegram_adapter},
};

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
    let telegram = telegram_config()?;
    let mut config = AgentGatewayConfig {
        bearer_token,
        telegram: telegram.clone(),
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
    // Optional Telegram adapter: same AgentService/store as the API server.
    // A startup failure (getMe/network) must never terminate the API
    // gateway: the adapter records a redacted degraded state and retries
    // with bounded backoff in the background; after the bound it is
    // disabled for this process while the API keeps serving.
    let telegram_handle = Arc::new(std::sync::Mutex::new(None::<TelegramAdapter>));
    // Set before shutdown begins so the bounded reconnect task can never
    // spawn a second adapter after the graceful stop path started.
    let stopping = Arc::new(AtomicBool::new(false));
    if let Some(telegram) = telegram {
        match spawn_telegram_adapter(state.clone(), telegram.clone()).await {
            Ok(adapter) => {
                eprintln!("rustscript-agent-gateway telegram adapter started");
                *telegram_handle.lock().expect("telegram handle lock") = Some(adapter);
            }
            Err(error) => {
                eprintln!(
                    "rustscript-agent-gateway telegram adapter degraded (startup failed: {error}); \
                     retrying with bounded backoff in the background"
                );
                let reconnect_state = state.clone();
                let reconnect_handle = Arc::clone(&telegram_handle);
                let stopping_reconnect = Arc::clone(&stopping);
                tokio::spawn(async move {
                    let mut delay = Duration::from_secs(1);
                    for attempt in 1..=3 {
                        tokio::time::sleep(delay).await;
                        if stopping_reconnect.load(Ordering::Acquire) {
                            return;
                        }
                        match spawn_telegram_adapter(reconnect_state.clone(), telegram.clone())
                            .await
                        {
                            Ok(adapter) => {
                                eprintln!(
                                    "rustscript-agent-gateway telegram adapter started (reconnect attempt {attempt})"
                                );
                                if stopping_reconnect.load(Ordering::Acquire) {
                                    // Shutdown began while the reconnect was
                                    // in flight: stop the adapter we just
                                    // spawned (bounded join) and never leave
                                    // it running after the graceful stop
                                    // path.
                                    adapter.shutdown().await;
                                    return;
                                }
                                *reconnect_handle.lock().expect("telegram handle lock") =
                                    Some(adapter);
                                return;
                            }
                            Err(error) => {
                                eprintln!(
                                    "rustscript-agent-gateway telegram adapter retry {attempt} failed: {error}"
                                );
                                delay *= 2;
                            }
                        }
                    }
                    eprintln!(
                        "rustscript-agent-gateway telegram adapter disabled after bounded retries"
                    );
                });
            }
        }
    }
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
            eprintln!(
                "halting: stopping admission and Telegram, then cancelling active runs, \
                 then closing the storage worker"
            );
            // 1. Stop admission first: new runs answer the typed Halting
            //    rejection, so no new work can start after shutdown begins.
            state.service().stop_admission();
            // 2. Bounded Telegram shutdown: stop the poller, wait for the
            //    final offset persist (join bounded at 60s). The stopping
            //    flag prevents the reconnect task from spawning a second
            //    adapter mid-shutdown.
            stopping.store(true, Ordering::Release);
            let adapter = telegram_handle.lock().expect("telegram handle lock").take();
            if let Some(adapter) = adapter {
                adapter.shutdown().await;
            }
            // 3. Cancel active runs with the typed resource-closed reason;
            //    workers exit within their configured bounds and commit
            //    their typed terminal transitions.
            state.service().halt();
            // 4. Deterministic storage-worker shutdown: queued commands fail
            //    fast with a typed error instead of hanging, and the worker
            //    thread is joined.
            if let Some(persistence) = state.persistence() {
                persistence.shutdown();
            }
        }
    }
    Ok(())
}

/// Builds the optional Telegram adapter configuration from the environment.
/// The token is required when Telegram is enabled; the allowlists default to
/// empty (deny-by-default). The token is never echoed by this binary.
fn telegram_config() -> Result<Option<TelegramConfig>, Box<dyn std::error::Error>> {
    let Some(token) = env_value(
        "RUSTSCRIPT_AGENT_TELEGRAM_BOT_TOKEN",
        "PD_EDGE_AGENT_TELEGRAM_BOT_TOKEN",
    )?
    else {
        return Ok(None);
    };
    if token.trim().is_empty() {
        return Err("RUSTSCRIPT_AGENT_TELEGRAM_BOT_TOKEN must not be blank".into());
    }
    let mut config = TelegramConfig {
        bot_token: token,
        ..TelegramConfig::default()
    };
    if let Some(api_base) = env_value(
        "RUSTSCRIPT_AGENT_TELEGRAM_API_BASE",
        "PD_EDGE_AGENT_TELEGRAM_API_BASE",
    )? {
        config.api_base = api_base;
    }
    if env_value(
        "RUSTSCRIPT_AGENT_TELEGRAM_ALLOW_INSECURE_LOCALHOST",
        "PD_EDGE_AGENT_TELEGRAM_ALLOW_INSECURE_LOCALHOST",
    )?
    .as_deref()
        == Some("1")
    {
        // Explicit escape hatch for local fixture servers; production
        // api_base stays https-only so the token never travels in cleartext.
        config.allow_insecure_localhost = true;
    }
    if env_value(
        "RUSTSCRIPT_AGENT_TELEGRAM_DROP_PENDING_UPDATES",
        "PD_EDGE_AGENT_TELEGRAM_DROP_PENDING_UPDATES",
    )?
    .as_deref()
        == Some("0")
    {
        // Opt out of the safe first-boot default: process updates queued
        // while the bot was offline instead of dropping them.
        config.drop_pending_updates = false;
    }
    if let Some(accounts) = env_value(
        "RUSTSCRIPT_AGENT_TELEGRAM_ALLOWED_ACCOUNTS",
        "PD_EDGE_AGENT_TELEGRAM_ALLOWED_ACCOUNTS",
    )? {
        config.allowed_accounts = split_list(&accounts);
    }
    if let Some(chats) = env_value(
        "RUSTSCRIPT_AGENT_TELEGRAM_ALLOWED_CHATS",
        "PD_EDGE_AGENT_TELEGRAM_ALLOWED_CHATS",
    )? {
        config.allowed_chats = parse_i64_list(&chats, "RUSTSCRIPT_AGENT_TELEGRAM_ALLOWED_CHATS")?;
    }
    if let Some(users) = env_value(
        "RUSTSCRIPT_AGENT_TELEGRAM_ALLOWED_USERS",
        "PD_EDGE_AGENT_TELEGRAM_ALLOWED_USERS",
    )? {
        config.allowed_users = parse_i64_list(&users, "RUSTSCRIPT_AGENT_TELEGRAM_ALLOWED_USERS")?;
    }
    if let Some(seconds) = env_value(
        "RUSTSCRIPT_AGENT_TELEGRAM_POLL_TIMEOUT_SECS",
        "PD_EDGE_AGENT_TELEGRAM_POLL_TIMEOUT_SECS",
    )? {
        config.poll_timeout = Duration::from_secs(seconds.parse().map_err(
            |_| "RUSTSCRIPT_AGENT_TELEGRAM_POLL_TIMEOUT_SECS must be an integer number of seconds",
        )?);
    }
    config
        .validate()
        .map_err(|error| -> Box<dyn std::error::Error> {
            format!("invalid Telegram configuration: {error}").into()
        })?;
    Ok(Some(config))
}

fn parse_i64_list(value: &str, name: &str) -> Result<Vec<i64>, Box<dyn std::error::Error>> {
    let mut parsed = Vec::new();
    for item in split_list(value) {
        parsed.push(
            item.parse::<i64>()
                .map_err(|_| format!("{name} contains a non-integer entry: {item}"))?,
        );
    }
    Ok(parsed)
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
