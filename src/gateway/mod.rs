//! HTTP gateway: state construction, the API server router, and the
//! RSS-backed store. Platform adapters (API Server, later Telegram) consume
//! AgentService and cannot call providers or tools directly.

mod api_server;
/// The typed RSS-backed storage repository (normalized schema, dedicated
/// storage worker). Public so integration tests can exercise the typed
/// repository commands directly; application code reaches it through
/// [`AgentGatewayState`].
pub mod store;

use std::{path::Path as FsPath, sync::Arc};

use parking_lot::RwLock;
use rustscript_vm::HttpConfig;

use crate::config::AgentGatewayConfig;
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
}

impl AgentGatewayState {
    pub fn new(config: AgentGatewayConfig) -> Result<Self, String> {
        let http_config = config.http.clone();
        config
            .validate()
            .map_err(|error| format!("invalid gateway configuration: {error}"))?;
        let store = Arc::new(RwLock::new(store::GatewayStore::default()));
        let service = Arc::new(AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            None,
            None,
            http_config.clone(),
        ));
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source: None,
            http_config,
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
        rustscript_vm::compile_source(&source)
            .map_err(|error| format!("compile RSS agent source: {error}"))?;
        let http_config = config.http.clone();
        config
            .validate()
            .map_err(|error| format!("invalid gateway configuration: {error}"))?;
        let store = Arc::new(RwLock::new(store::GatewayStore::default()));
        let agent_source = Some(Arc::new(source));
        let service = Arc::new(AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            None,
            agent_source.clone(),
            http_config.clone(),
        ));
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source,
            http_config,
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
        rustscript_vm::compile_source(&source)
            .map_err(|error| format!("compile RSS agent source: {error}"))?;
        let http_config = config.http.clone();
        config
            .validate()
            .map_err(|error| format!("invalid gateway configuration: {error}"))?;
        let persistence = Arc::new(
            store::GatewayPersistence::open(&config, path.as_ref())
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
        ));
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source,
            http_config,
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
        let persistence = Arc::new(
            store::GatewayPersistence::open(&config, path.as_ref())
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
        ));
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source: None,
            http_config,
        })
    }

    pub fn service(&self) -> Arc<AgentService> {
        Arc::clone(&self.service)
    }

    /// The typed storage repository handle (normalized schema), or `None`
    /// when no SQLite path is configured (in-memory only mode).
    pub fn persistence(&self) -> Option<Arc<store::GatewayPersistence>> {
        self.service.persistence_handle()
    }
}
