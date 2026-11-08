use std::{
    env,
    future::{Future, IntoFuture},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};

use rustscript_agent::{
    AgentGatewayConfig, AgentGatewayState, ConfigFile, TelegramConfig, build_agent_gateway_app,
    config::ProviderProfile,
    config_file::{AgentPaths, ConfigFileError},
    gateway::telegram::{TelegramAdapter, spawn_telegram_adapter},
    plugins::{InstallAuthorization, PublisherKey},
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
    let explicit_home = env::var_os("RUSTSCRIPT_AGENT_HOME").is_some();
    let paths = AgentPaths::resolve()
        .map_err(|_| std::io::Error::other("agent home could not be resolved"))?;
    let loaded_config = match ConfigFile::load(paths.config_path()) {
        Ok(config) => Some(config),
        Err(ConfigFileError::MissingFile { .. }) => None,
        Err(_) => {
            return Err(std::io::Error::other("agent config.yaml could not be loaded").into());
        }
    };
    let config_present = loaded_config.is_some();
    let config_source = loaded_config
        .as_ref()
        .map(|config| config.agent.source.clone());
    let compaction_settings = loaded_config
        .as_ref()
        .map(|config| config.compaction.clone())
        .unwrap_or_default();
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
    // The loaded document is authoritative for the gateway default
    // model/provider and for the public provider profiles. A missing
    // document keeps the built-in local-agent defaults; an invalid profile
    // fails startup before any listener or platform adapter exists.
    let (mut config, provider_profiles) =
        apply_loaded_config(config, loaded_config.as_ref()).map_err(std::io::Error::other)?;

    // Collect config and legacy source facts mechanically. RSS owns their
    // priority; the config and compaction values come from one bounded snapshot.
    let source = source_env_value("RUSTSCRIPT_AGENT_SOURCE", "PD_EDGE_AGENT_SOURCE");
    let legacy_script = source_env_value("RUSTSCRIPT_AGENT_SCRIPT", "PD_EDGE_AGENT_SCRIPT");
    let state_db = env_value("RUSTSCRIPT_AGENT_STATE_DB", "PD_EDGE_AGENT_STATE_DB")?;
    config.managed_workspace = std::env::var_os("RUSTSCRIPT_AGENT_MANAGED_WORKSPACE")
        .map(rustscript_agent::config::ManagedWorkspaceConfig::for_workspace)
        .transpose()
        .map_err(std::io::Error::other)?;
    if let Some(policy) = std::env::var_os("RUSTSCRIPT_AGENT_MANAGED_COMPLETION_POLICY") {
        config.managed_completion_policy =
            rustscript_agent::config::ManagedCompletionPolicy::parse(&policy.to_string_lossy())
                .map_err(std::io::Error::other)?;
    }
    let mut selection = serde_json::Map::new();
    selection.insert(
        "config_present".to_string(),
        serde_json::Value::Bool(config_present),
    );
    if let Some(config_source) = config_source {
        selection.insert("config_source".to_string(), source_fact(config_source));
    }
    if let Some(source) = source {
        selection.insert("source".to_string(), source);
    }
    if let Some(script) = legacy_script {
        selection.insert("legacy_script".to_string(), script);
    }
    // Built before the listener binds: an invalid authoritative source is a
    // static construction error and never falls back to a legacy/default
    // source, and never reaches the socket.
    let state = AgentGatewayState::with_agent_selection_and_compaction(
        config,
        serde_json::Value::Object(selection),
        state_db.as_deref().map(std::path::Path::new),
        compaction_settings,
    )
    .map_err(std::io::Error::other)?;
    let home = paths.home.clone();
    let state = state
        .with_operator_auth_home(home.clone())
        .map_err(std::io::Error::other)?;
    let service = state.service();
    for profile in provider_profiles {
        service
            .set_provider_profile(profile)
            .map_err(|_| std::io::Error::other("agent provider profile could not be registered"))?;
    }
    drop(service);
    let state = if explicit_home {
        state.with_workspace_home(home)
    } else {
        state
    };
    let state = bind_host_plugin_control(state).map_err(std::io::Error::other)?;

    // The process-wide Ctrl-C handler is registered before the listener
    // binds and before the ready line is published; the same future is then
    // supervised beside the served app. A signal that completes during
    // registration is acknowledged by running the existing shutdown block
    // exactly once, without starting the server.
    let telegram_handle = Arc::new(std::sync::Mutex::new(None::<TelegramAdapter>));
    // Set before shutdown begins so the bounded reconnect task can never
    // spawn a second adapter after the graceful stop path started.
    let stopping = Arc::new(AtomicBool::new(false));
    let startup_state = state.clone();
    let startup_telegram_handle = Arc::clone(&telegram_handle);
    let startup_stopping = Arc::clone(&stopping);
    let startup = move || async move {
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
        if let Some(telegram) = telegram {
            match spawn_telegram_adapter(startup_state.clone(), telegram.clone()).await {
                Ok(adapter) => {
                    eprintln!("rustscript-agent-gateway telegram adapter started");
                    *startup_telegram_handle
                        .lock()
                        .expect("telegram handle lock") = Some(adapter);
                }
                Err(error) => {
                    eprintln!(
                        "rustscript-agent-gateway telegram adapter degraded (startup failed: {error}); \
                         retrying with bounded backoff in the background"
                    );
                    let reconnect_state = startup_state.clone();
                    let reconnect_handle = Arc::clone(&startup_telegram_handle);
                    let stopping_reconnect = Arc::clone(&startup_stopping);
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
        let app = build_agent_gateway_app(startup_state);
        Ok::<_, std::io::Error>(
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .into_future(),
        )
    };
    let acknowledged = serve_after_signal_registration(tokio::signal::ctrl_c(), startup).await?;
    if acknowledged {
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
    Ok(())
}

/// Applies the loaded `config.yaml` document to the existing gateway
/// boundaries: the default model/provider and one validated public
/// `ProviderProfile` per configured provider. Only public request-shaping
/// fields enter the profile; credential values stay in the native AuthStore.
fn apply_loaded_config(
    mut config: AgentGatewayConfig,
    loaded: Option<&ConfigFile>,
) -> Result<(AgentGatewayConfig, Vec<ProviderProfile>), String> {
    let Some(loaded) = loaded else {
        return Ok((config, Vec::new()));
    };
    config.model = loaded.model.model.clone();
    config.provider = Some(loaded.model.provider.clone());
    let mut profiles = Vec::new();
    for (name, provider) in &loaded.providers {
        let mut options = serde_json::Map::new();
        options.insert(
            "profile".to_string(),
            serde_json::Value::String(name.clone()),
        );
        options.insert(
            "protocol".to_string(),
            serde_json::Value::String(provider.protocol.clone()),
        );
        options.insert(
            "base_url".to_string(),
            serde_json::Value::String(provider.base_url.clone()),
        );
        if let Some(credential_id) = provider.auth.as_ref() {
            options.insert(
                "credential_id".to_string(),
                serde_json::Value::String(credential_id.clone()),
            );
        }
        let profile = ProviderProfile::new(name.clone(), serde_json::Value::Object(options))
            .map_err(|_| "agent provider profile is invalid".to_string())?;
        profiles.push(profile);
    }
    Ok((config, profiles))
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

/// Collects one legacy source fact for RSS without applying source priority.
/// Oversized and non-UTF8 facts use the same present-invalid sentinel; values
/// are never truncated, repaired, or rendered into errors.
fn source_env_value(primary: &str, legacy: &str) -> Option<serde_json::Value> {
    match env_value(primary, legacy) {
        Ok(Some(value)) => Some(source_fact(value)),
        Ok(None) | Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => Some(serde_json::Value::Bool(false)),
    }
}

/// Preserves RSS-bounded source facts exactly and uses the existing sentinel
/// for values beyond the scalar bound, never truncating them.
fn source_fact(value: String) -> serde_json::Value {
    const MAX_SOURCE_SCALARS: usize = 4096;
    if value.len() > MAX_SOURCE_SCALARS * 4 || value.chars().count() > MAX_SOURCE_SCALARS {
        serde_json::Value::Bool(false)
    } else {
        serde_json::Value::String(value)
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

fn bind_host_plugin_control(state: AgentGatewayState) -> Result<AgentGatewayState, String> {
    let root = match env::var_os("RUSTSCRIPT_AGENT_PLUGIN_SOURCE_ROOT") {
        Some(value) => value,
        None => return Ok(state),
    };
    let space = env::var("RUSTSCRIPT_AGENT_PLUGIN_DEPLOYMENT_SPACE")
        .map_err(|_| "plugin control deployment space is not configured".to_string())?;
    let mut accepted_publishers = Vec::new();
    if let Some(dir) = env::var_os("RUSTSCRIPT_AGENT_PLUGIN_PUBLISHER_DIR") {
        let dir = std::path::PathBuf::from(dir);
        let entries = std::fs::read_dir(&dir)
            .map_err(|_| "plugin publisher directory is unavailable".to_string())?;
        for entry in entries {
            let entry =
                entry.map_err(|_| "plugin publisher directory is unavailable".to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "plugin publisher name is invalid".to_string())?;
            if name.contains('/') || name.contains('\\') || name.starts_with('.') {
                return Err("plugin publisher name is invalid".into());
            }
            let bytes = std::fs::read(entry.path())
                .map_err(|_| "plugin publisher key is unavailable".to_string())?;
            if bytes.len() != 32 {
                return Err("plugin publisher key is invalid".into());
            }
            accepted_publishers.push(PublisherKey {
                publisher: name,
                verifying_key: bytes,
            });
        }
    }
    let unsigned_dev_space =
        env::var_os("RUSTSCRIPT_AGENT_PLUGIN_UNSIGNED_DEV").map(std::path::PathBuf::from);
    state.with_plugin_control(
        InstallAuthorization {
            admin: true,
            accepted_publishers,
            unsigned_dev_space,
        },
        std::path::PathBuf::from(root),
        space,
    )
}

/// Supervises one lazy gateway startup beside the process-wide Ctrl-C future.
///
/// Returns `Ok(true)` when the signal was observed and the caller must run the
/// existing shutdown block exactly once, or `Ok(false)` when the server
/// returned normally. Startup and server errors keep their original outcome.
async fn serve_after_signal_registration<Signal, Start, Setup, Server>(
    signal: Signal,
    start: Start,
) -> std::io::Result<bool>
where
    Signal: Future<Output = std::io::Result<()>>,
    Start: FnOnce() -> Setup,
    Setup: Future<Output = std::io::Result<Server>>,
    Server: Future<Output = std::io::Result<()>>,
{
    let mut signal = std::pin::pin!(signal);
    // The first poll completes the Ctrl-C handler registration before the lazy
    // startup binds the listener or publishes readiness. `Pending` means the
    // handler is registered; a failed registration never starts the server, and
    // a future that completed on this first poll is never polled again.
    let first_poll = std::future::poll_fn(|cx| Poll::Ready(signal.as_mut().poll(cx))).await;
    match first_poll {
        Poll::Ready(Err(error)) => return Err(error),
        Poll::Ready(Ok(())) => return Ok(true),
        Poll::Pending => {}
    }
    let mut server = std::pin::pin!(start().await?);
    tokio::select! {
        result = &mut server => {
            result?;
            Ok(false)
        }
        result = &mut signal => {
            result?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod gateway_registration_tests {
    use super::serve_after_signal_registration;
    use std::{
        cell::{Cell, RefCell},
        future::{Future, Ready},
        io,
        pin::Pin,
        rc::Rc,
        task::{Context, Poll},
    };

    #[derive(Clone, Copy)]
    enum SignalStep {
        Pending,
        Error,
        ReadyNow,
        ReadyAt(usize),
    }

    #[derive(Clone)]
    struct Recorder {
        events: Rc<RefCell<Vec<String>>>,
        startup_calls: Rc<Cell<usize>>,
        signal_polls: Rc<Cell<usize>>,
        server_polls: Rc<Cell<usize>>,
        acks: Rc<Cell<usize>>,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                events: Rc::new(RefCell::new(Vec::new())),
                startup_calls: Rc::new(Cell::new(0)),
                signal_polls: Rc::new(Cell::new(0)),
                server_polls: Rc::new(Cell::new(0)),
                acks: Rc::new(Cell::new(0)),
            }
        }

        fn event(&self, event: String) {
            self.events.borrow_mut().push(event);
        }

        fn events(&self) -> Vec<String> {
            self.events.borrow().clone()
        }
    }

    struct ScriptedSignal {
        step: SignalStep,
        recorder: Recorder,
    }

    impl ScriptedSignal {
        fn new(step: SignalStep, recorder: Recorder) -> Self {
            Self { step, recorder }
        }
    }

    impl Future for ScriptedSignal {
        type Output = io::Result<()>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            let poll = this.recorder.signal_polls.get() + 1;
            this.recorder.signal_polls.set(poll);
            this.recorder.event(format!("signal-poll#{poll}"));
            match this.step {
                SignalStep::Error => {
                    Poll::Ready(Err(io::Error::other("signal registration failed")))
                }
                SignalStep::ReadyNow => {
                    this.recorder.acks.set(this.recorder.acks.get() + 1);
                    Poll::Ready(Ok(()))
                }
                SignalStep::ReadyAt(target) if poll >= target => {
                    this.recorder.acks.set(this.recorder.acks.get() + 1);
                    Poll::Ready(Ok(()))
                }
                _ => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    enum ServerStep {
        Pending,
        OkNow,
        ErrNow,
    }

    struct ScriptedServer {
        step: ServerStep,
        recorder: Recorder,
    }

    impl ScriptedServer {
        fn new(step: ServerStep, recorder: Recorder) -> Self {
            Self { step, recorder }
        }
    }

    impl Future for ScriptedServer {
        type Output = io::Result<()>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            let poll = this.recorder.server_polls.get() + 1;
            this.recorder.server_polls.set(poll);
            this.recorder.event(format!("server-poll#{poll}"));
            match this.step {
                ServerStep::Pending => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                ServerStep::OkNow => Poll::Ready(Ok(())),
                ServerStep::ErrNow => Poll::Ready(Err(io::Error::other("serve failed"))),
            }
        }
    }

    fn lazy_startup(
        recorder: Recorder,
        server: ScriptedServer,
    ) -> impl FnOnce() -> Ready<io::Result<ScriptedServer>> {
        move || {
            recorder.startup_calls.set(recorder.startup_calls.get() + 1);
            let observed_signal_polls = recorder.signal_polls.get();
            recorder.event(format!("startup:signal_polls={observed_signal_polls}"));
            std::future::ready(Ok::<ScriptedServer, io::Error>(server))
        }
    }

    #[tokio::test]
    async fn registration_pending_is_polled_before_lazy_startup() {
        let recorder = Recorder::new();
        let signal = ScriptedSignal::new(SignalStep::Pending, recorder.clone());
        let server = ScriptedServer::new(ServerStep::OkNow, recorder.clone());
        let result =
            serve_after_signal_registration(signal, lazy_startup(recorder.clone(), server)).await;
        let events = recorder.events();
        assert_eq!(result.ok(), Some(false), "actual events: {events:?}");
        assert_eq!(
            events.first().map(String::as_str),
            Some("signal-poll#1"),
            "the first poll must register before startup; actual events: {events:?}"
        );
        let startup = events
            .iter()
            .find(|event| event.starts_with("startup:"))
            .cloned();
        assert_eq!(
            startup.as_deref(),
            Some("startup:signal_polls=1"),
            "startup must observe one completed signal poll; actual events: {events:?}"
        );
        assert_eq!(recorder.startup_calls.get(), 1, "actual events: {events:?}");
        assert_eq!(recorder.server_polls.get(), 1, "actual events: {events:?}");
        assert_eq!(
            recorder.acks.get(),
            0,
            "normal completion is not an ack; actual events: {events:?}"
        );
    }

    #[tokio::test]
    async fn registration_error_fails_closed_without_startup() {
        let recorder = Recorder::new();
        let signal = ScriptedSignal::new(SignalStep::Error, recorder.clone());
        let server = ScriptedServer::new(ServerStep::Pending, recorder.clone());
        let result =
            serve_after_signal_registration(signal, lazy_startup(recorder.clone(), server)).await;
        let events = recorder.events();
        let error = result.expect_err("registration error must be returned");
        assert_eq!(error.to_string(), "signal registration failed");
        assert_eq!(recorder.startup_calls.get(), 0, "actual events: {events:?}");
        assert_eq!(recorder.server_polls.get(), 0, "actual events: {events:?}");
        assert_eq!(events, vec!["signal-poll#1"], "actual events: {events:?}");
        assert_eq!(recorder.acks.get(), 0);
    }

    #[tokio::test]
    async fn already_completed_signal_skips_startup_and_repoll() {
        let recorder = Recorder::new();
        let signal = ScriptedSignal::new(SignalStep::ReadyNow, recorder.clone());
        let server = ScriptedServer::new(ServerStep::Pending, recorder.clone());
        let result =
            serve_after_signal_registration(signal, lazy_startup(recorder.clone(), server)).await;
        let events = recorder.events();
        assert_eq!(result.ok(), Some(true), "actual events: {events:?}");
        assert_eq!(recorder.startup_calls.get(), 0, "actual events: {events:?}");
        assert_eq!(
            recorder.signal_polls.get(),
            1,
            "a completed signal must not be repolled; actual events: {events:?}"
        );
        assert_eq!(recorder.server_polls.get(), 0, "actual events: {events:?}");
        assert_eq!(recorder.acks.get(), 1);
        assert_eq!(events, vec!["signal-poll#1"]);
    }

    #[tokio::test]
    async fn later_signal_reuses_the_registered_future_once() {
        let recorder = Recorder::new();
        let signal = ScriptedSignal::new(SignalStep::ReadyAt(3), recorder.clone());
        let server = ScriptedServer::new(ServerStep::Pending, recorder.clone());
        let result =
            serve_after_signal_registration(signal, lazy_startup(recorder.clone(), server)).await;
        let events = recorder.events();
        assert_eq!(result.ok(), Some(true), "actual events: {events:?}");
        assert_eq!(recorder.startup_calls.get(), 1, "actual events: {events:?}");
        assert_eq!(
            recorder.signal_polls.get(),
            3,
            "the same future must be polled, not a second handler; actual events: {events:?}"
        );
        assert_eq!(
            recorder.acks.get(),
            1,
            "a later signal is acknowledged once; actual events: {events:?}"
        );
        assert_eq!(
            events.first().map(String::as_str),
            Some("signal-poll#1"),
            "registration must precede startup; actual events: {events:?}"
        );
        let startup_signal_polls = events
            .iter()
            .find(|event| event.starts_with("startup:"))
            .cloned();
        assert_eq!(
            startup_signal_polls.as_deref(),
            Some("startup:signal_polls=1"),
            "startup must observe the completed registration; actual events: {events:?}"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "signal-poll#3")
                .count(),
            1,
            "the later ack comes from the same future; actual events: {events:?}"
        );
    }

    #[tokio::test]
    async fn server_error_is_not_treated_as_signal_ack() {
        let recorder = Recorder::new();
        let signal = ScriptedSignal::new(SignalStep::Pending, recorder.clone());
        let server = ScriptedServer::new(ServerStep::ErrNow, recorder.clone());
        let result =
            serve_after_signal_registration(signal, lazy_startup(recorder.clone(), server)).await;
        let events = recorder.events();
        let error = result.expect_err("serve error must be returned");
        assert_eq!(error.to_string(), "serve failed");
        assert_eq!(recorder.startup_calls.get(), 1, "actual events: {events:?}");
        assert_eq!(recorder.acks.get(), 0, "actual events: {events:?}");
    }

    #[tokio::test]
    async fn server_normal_completion_returns_false_without_ack() {
        let recorder = Recorder::new();
        let signal = ScriptedSignal::new(SignalStep::Pending, recorder.clone());
        let server = ScriptedServer::new(ServerStep::OkNow, recorder.clone());
        let result =
            serve_after_signal_registration(signal, lazy_startup(recorder.clone(), server)).await;
        let events = recorder.events();
        assert_eq!(result.ok(), Some(false), "actual events: {events:?}");
        assert_eq!(recorder.startup_calls.get(), 1);
        assert_eq!(recorder.acks.get(), 0, "actual events: {events:?}");
        assert!(
            events.iter().any(|event| event == "server-poll#1"),
            "actual events: {events:?}"
        );
    }
}

#[cfg(test)]
mod gateway_provider_config_tests {
    use super::apply_loaded_config;
    use rustscript_agent::{
        AdmitRunRequest, AgentGatewayConfig, AgentGatewayState, ConfigFile, RunContext,
        config::ProviderProfile, config_file::CompactionSettings,
    };
    use serde_json::{Value, json};

    fn fixture_home() -> std::path::PathBuf {
        let root = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!(
                "gateway-provider-config-unit-{}",
                uuid::Uuid::new_v4()
            ));
        std::fs::create_dir_all(&root).expect("unit home");
        root
    }

    async fn admitted_context(loaded: Option<&ConfigFile>, provider: Option<&str>) -> RunContext {
        let (config, profiles) =
            apply_loaded_config(AgentGatewayConfig::default(), loaded).expect("config applies");
        let state = AgentGatewayState::with_agent_selection_and_compaction(
            config,
            json!({}),
            None,
            CompactionSettings::default(),
        )
        .expect("gateway state");
        let state = state
            .with_operator_auth_home(fixture_home())
            .expect("operator auth home");
        let service = state.service();
        for profile in profiles {
            service
                .set_provider_profile(profile)
                .expect("provider profile registers");
        }
        let admitted = service
            .admit(AdmitRunRequest {
                input: json!("context probe"),
                session_id: None,
                model: None,
                provider: provider.map(ToOwned::to_owned),
                parent_run_id: None,
                instructions: None,
                platform: "unit".to_string(),
                idempotency_key: None,
                idempotency_hash: None,
                graph_id: None,
                workspace_branch: None,
            })
            .await
            .expect("admission");
        service
            .run_context(&admitted.run_id)
            .expect("admitted run context is cached")
    }

    fn profile_options(profiles: &[ProviderProfile], name: &str) -> Option<Value> {
        profiles
            .iter()
            .find(|profile| profile.name == name)
            .map(|profile| profile.options().clone())
    }

    const CONFIG_WITH_AUTH: &str = "version: 1\nmodel:\n  provider: openai\n  model: fixture-model\n\
         providers:\n  openai:\n    protocol: openai-chat-completions\n    \
         base_url: https://127.0.0.1:9/v1\n    auth: demo-primary\n";

    #[tokio::test]
    async fn present_config_reaches_real_admission_context() {
        let loaded = ConfigFile::from_str(CONFIG_WITH_AUTH).expect("fixture config");
        let context = admitted_context(Some(&loaded), None).await;
        assert_eq!(context.model, "fixture-model");
        assert_eq!(context.provider.as_deref(), Some("openai"));
        assert_eq!(
            context.provider_options,
            json!({
                "profile": "openai",
                "protocol": "openai-chat-completions",
                "base_url": "https://127.0.0.1:9/v1",
                "credential_id": "demo-primary"
            })
        );
        assert_eq!(context.metadata["provider_profile"], "openai");
    }

    #[tokio::test]
    async fn missing_config_keeps_builtin_local_agent_admission() {
        let context = admitted_context(None, None).await;
        assert_eq!(context.model, "local-agent");
        assert_eq!(context.provider.as_deref(), Some("local-agent"));
        assert_eq!(
            context.provider_options,
            json!({"profile": "local-agent", "protocol": "local-agent"})
        );
        assert_eq!(context.metadata["provider_profile"], "local-agent");
    }

    #[tokio::test]
    async fn no_auth_and_unselected_provider_do_not_supply_credentials() {
        let loaded = ConfigFile::from_str(
            "version: 1\nmodel:\n  provider: openai\n  model: fixture-model\n\
             providers:\n  openai:\n    protocol: openai-chat-completions\n    \
             base_url: https://127.0.0.1:9/v1\n  other:\n    protocol: openai-chat-completions\n    \
             base_url: https://127.0.0.1:8/v1\n    auth: other-primary\n",
        )
        .expect("fixture config");
        let (_, profiles) =
            apply_loaded_config(AgentGatewayConfig::default(), Some(&loaded)).expect("config");
        assert_eq!(
            profile_options(&profiles, "other"),
            Some(json!({
                "profile": "other",
                "protocol": "openai-chat-completions",
                "base_url": "https://127.0.0.1:8/v1",
                "credential_id": "other-primary"
            }))
        );
        assert_eq!(
            profile_options(&profiles, "openai"),
            Some(json!({
                "profile": "openai",
                "protocol": "openai-chat-completions",
                "base_url": "https://127.0.0.1:9/v1"
            }))
        );
        let context = admitted_context(Some(&loaded), Some("openai")).await;
        assert_eq!(
            context.provider_options,
            json!({
                "profile": "openai",
                "protocol": "openai-chat-completions",
                "base_url": "https://127.0.0.1:9/v1"
            })
        );
        assert!(
            context.provider_options.get("credential_id").is_none(),
            "an unselected provider's credential must not enter the admitted context"
        );
    }
}
