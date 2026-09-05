//! HTTP gateway: state construction, the API server router, and the
//! RSS-backed store. Platform adapters (API Server, later Telegram) consume
//! AgentService and cannot call providers or tools directly.

mod api_server;
/// Native Telegram Bot API transport, poller, and adapter. Public so
/// integration tests can drive the client and adapter against a fixture
/// server.
pub mod telegram;
/// Canonical event → Telegram text rendering (pure; no I/O).
mod telegram_render;
pub use telegram_render::{EventRenderer, RenderAction, TELEGRAM_MAX_UTF16, chunk_text, utf16_len};
/// The typed RSS-backed storage repository (normalized schema, dedicated
/// storage worker). Public so integration tests can exercise the typed
/// repository commands directly; application code reaches it through
/// [`AgentGatewayState`].
pub mod store;

use std::{path::Path as FsPath, sync::Arc};

use parking_lot::RwLock;
use rustscript_vm::HttpConfig;

use crate::config::AgentGatewayConfig;
use crate::metrics::Metrics;
use crate::runtime::rss_runner::{AgentConfig, AgentRunner};
use crate::service::AgentService;

pub use api_server::build_agent_gateway_app;

/// Shared gateway state: validated config, the in-memory store, and the
/// AgentService that owns run admission, cancellation, and delivery.
#[derive(Clone)]
pub struct AgentGatewayState {
    config: Arc<AgentGatewayConfig>,
    store: Arc<RwLock<store::GatewayStore>>,
    service: Arc<AgentService>,
    agent_source: Option<Arc<String>>,
    http_config: HttpConfig,
    metrics: Arc<Metrics>,
}

impl AgentGatewayState {
    pub fn new(config: AgentGatewayConfig) -> Result<Self, String> {
        let http_config = config.http.clone();
        config
            .validate()
            .map_err(|error| format!("invalid gateway configuration: {error}"))?;
        let store = Arc::new(RwLock::new(store::GatewayStore::default()));
        let metrics = Arc::new(Metrics::default());
        let service = Arc::new(AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            None,
            None,
            http_config.clone(),
            Arc::clone(&metrics),
        ));
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source: None,
            http_config,
            metrics,
        })
    }

    pub fn with_agent_source(
        config: AgentGatewayConfig,
        source: impl Into<String>,
    ) -> Result<Self, String> {
        let source = source.into();
        if source.len() > crate::MAX_AGENT_SOURCE_BYTES {
            return Err(format!(
                "RSS source exceeds {} bytes",
                crate::MAX_AGENT_SOURCE_BYTES
            ));
        }
        config
            .validate()
            .map_err(|error| format!("invalid gateway configuration: {error}"))?;
        let agent_config = AgentConfig {
            http: config.http.clone(),
            sqlite: config.sqlite.clone(),
            fuel: config.fuel,
        };
        let runner = AgentRunner::from_source(&source, agent_config)
            .map_err(|error| format!("compile RSS agent source: {error}"))?;
        let http_config = config.http.clone();
        let store = Arc::new(RwLock::new(store::GatewayStore::default()));
        let agent_source = Some(Arc::new(source));
        let metrics = Arc::new(Metrics::default());
        let service = Arc::new(AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            None,
            agent_source.clone(),
            http_config.clone(),
            Arc::clone(&metrics),
        ));
        service.install_agent_runner(runner);
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source,
            http_config,
            metrics,
        })
    }

    pub fn with_agent_file(
        config: AgentGatewayConfig,
        path: impl AsRef<FsPath>,
    ) -> Result<Self, String> {
        config
            .validate()
            .map_err(|error| format!("invalid gateway configuration: {error}"))?;
        let path = path.as_ref().to_path_buf();
        let agent_config = AgentConfig {
            http: config.http.clone(),
            sqlite: config.sqlite.clone(),
            fuel: config.fuel,
        };
        let runner = AgentRunner::from_file(&path, agent_config)
            .map_err(|error| format!("compile RSS agent entry: {error}"))?;
        let http_config = config.http.clone();
        let store = Arc::new(RwLock::new(store::GatewayStore::default()));
        let metrics = Arc::new(Metrics::default());
        let service = Arc::new(AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            None,
            None,
            http_config.clone(),
            Arc::clone(&metrics),
        ));
        service.install_agent_entry(path);
        service.install_agent_runner(runner);
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source: None,
            http_config,
            metrics,
        })
    }

    pub fn with_agent_file_and_sqlite(
        config: AgentGatewayConfig,
        path: impl AsRef<FsPath>,
        sqlite_path: impl AsRef<FsPath>,
    ) -> Result<Self, String> {
        config
            .validate()
            .map_err(|error| format!("invalid gateway configuration: {error}"))?;
        let path = path.as_ref().to_path_buf();
        let agent_config = AgentConfig {
            http: config.http.clone(),
            sqlite: config.sqlite.clone(),
            fuel: config.fuel,
        };
        let runner = AgentRunner::from_file(&path, agent_config)
            .map_err(|error| format!("compile RSS agent entry: {error}"))?;
        let http_config = config.http.clone();
        let metrics = Arc::new(Metrics::default());
        let persistence = Arc::new(
            store::GatewayPersistence::open_with_metrics(
                &config,
                sqlite_path.as_ref(),
                Arc::clone(&metrics),
            )
            .map_err(|error| format!("open gateway SQLite state: {error}"))?,
        );
        let loaded_store = persistence
            .load()
            .map_err(|error| format!("load gateway SQLite state: {error}"))?;
        let store = Arc::new(RwLock::new(loaded_store));
        let service = Arc::new(AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            Some(persistence),
            None,
            http_config.clone(),
            Arc::clone(&metrics),
        ));
        service.install_agent_entry(path);
        service.install_agent_runner(runner);
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source: None,
            http_config,
            metrics,
        })
    }

    pub fn with_agent_source_and_sqlite(
        config: AgentGatewayConfig,
        source: impl Into<String>,
        path: impl AsRef<FsPath>,
    ) -> Result<Self, String> {
        let source = source.into();
        if source.len() > crate::MAX_AGENT_SOURCE_BYTES {
            return Err(format!(
                "RSS source exceeds {} bytes",
                crate::MAX_AGENT_SOURCE_BYTES
            ));
        }
        config
            .validate()
            .map_err(|error| format!("invalid gateway configuration: {error}"))?;
        let agent_config = AgentConfig {
            http: config.http.clone(),
            sqlite: config.sqlite.clone(),
            fuel: config.fuel,
        };
        let runner = AgentRunner::from_source(&source, agent_config)
            .map_err(|error| format!("compile RSS agent source: {error}"))?;
        let http_config = config.http.clone();
        let metrics = Arc::new(Metrics::default());
        let persistence = Arc::new(
            store::GatewayPersistence::open_with_metrics(
                &config,
                path.as_ref(),
                Arc::clone(&metrics),
            )
            .map_err(|error| format!("open gateway SQLite state: {error}"))?,
        );
        let loaded_store = persistence
            .load()
            .map_err(|error| format!("load gateway SQLite state: {error}"))?;
        let store = Arc::new(RwLock::new(loaded_store));
        let agent_source = Some(Arc::new(source));
        let service = Arc::new(AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            Some(persistence),
            agent_source.clone(),
            http_config.clone(),
            Arc::clone(&metrics),
        ));
        service.install_agent_runner(runner);
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source,
            http_config,
            metrics,
        })
    }

    pub fn with_sqlite_path(
        config: AgentGatewayConfig,
        path: impl AsRef<FsPath>,
    ) -> Result<Self, String> {
        let http_config = config.http.clone();
        config
            .validate()
            .map_err(|error| format!("invalid gateway configuration: {error}"))?;
        let metrics = Arc::new(Metrics::default());
        let persistence = Arc::new(
            store::GatewayPersistence::open_with_metrics(
                &config,
                path.as_ref(),
                Arc::clone(&metrics),
            )
            .map_err(|error| format!("open gateway SQLite state: {error}"))?,
        );
        let loaded_store = persistence
            .load()
            .map_err(|error| format!("load gateway SQLite state: {error}"))?;
        let store = Arc::new(RwLock::new(loaded_store));
        let service = Arc::new(AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            Some(persistence),
            None,
            http_config.clone(),
            Arc::clone(&metrics),
        ));
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source: None,
            http_config,
            metrics,
        })
    }

    pub fn service(&self) -> Arc<AgentService> {
        Arc::clone(&self.service)
    }

    /// The bounded metrics registry shared by the service, delivery, storage
    /// worker, and API handlers.
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// The typed storage repository handle (normalized schema), or `None`
    /// when no SQLite path is configured (in-memory only mode).
    pub fn persistence(&self) -> Option<Arc<store::GatewayPersistence>> {
        self.service.persistence_handle()
    }
}
