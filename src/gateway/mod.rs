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

use std::{
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};

use parking_lot::RwLock;
use rustscript_vm::HttpConfig;

use crate::config::AgentGatewayConfig;
use crate::config_file::{AgentPaths, CompactionSettings};
use crate::domain::{json_to_vm_value, vm_value_to_json};
use crate::metrics::Metrics;
use crate::runtime::rss_runner::{AgentConfig, AgentRunner};
use crate::service::AgentService;

pub use api_server::build_agent_gateway_app;

/// Bound on the serialized public selection map handed to the RSS source
/// policy, in bytes. The policy itself further bounds every token.
const MAX_AGENT_SELECTION_BYTES: usize = 64 * 1024;

/// Generated-catalog key of the standalone RSS source policy.
const SOURCE_POLICY_KEY: &str = "rss/agent/source_policy.rss";

/// Generated-catalog key of the bundled coding entry named by a native
/// `{kind:"bundled",resource:"coding"}` descriptor.
const BUNDLED_CODING_KEY: &str = "rss/agent/main.rss";

/// The standalone RSS source-policy decision consumed by the gateway. Only
/// the two native descriptors the policy can admit exist here; everything
/// else the policy returns is reported as its static error text.
enum AgentSourceDecision {
    BundledCoding {
        deprecated_override: bool,
    },
    File {
        path: String,
        deprecated_override: bool,
    },
}

/// Bounded public source facts exposed on `/health/detailed`: the native
/// `kind`, the runner's native snapshot `hash`, and the policy's migration
/// indicator. Never a raw selected path or source text.
#[derive(Clone, Debug)]
pub(crate) struct AgentSourceMetadata {
    pub(crate) kind: &'static str,
    pub(crate) hash: String,
    pub(crate) deprecated_override: bool,
}

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
    /// Source facts for `/health/detailed`; `None` for the legacy
    /// constructors that carry no RSS selection.
    source_metadata: Option<Arc<AgentSourceMetadata>>,
}

impl AgentGatewayState {
    pub fn new(config: AgentGatewayConfig) -> Result<Self, String> {
        // Empty selection: every priority/default decision (here, the bundled
        // coding entry) is made by the RSS source policy, not in Rust.
        Self::with_agent_selection(config, serde_json::json!({}), None)
    }

    /// Installs only workspace authority from an explicitly supplied trusted
    /// native home. Provider RSS receives no OAuth host factory.
    pub fn with_workspace_home(self, home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        self.service
            .set_workspace_host_factory(Arc::new(move |cancellation| {
                crate::auth::host::AuthHost::new(home.clone(), cancellation)
            }));
        self
    }

    /// Installs operator authentication for the default provider child only.
    /// AuthStore admission remains lazy until a finite provider invocation.
    pub fn with_operator_auth_home(self, home: impl Into<PathBuf>) -> Result<Self, String> {
        let home = Self::validated_operator_home(home)?.home;
        let factory: crate::runtime::agent_host::AuthHostFactory = Arc::new(move |cancellation| {
            crate::auth::host::AuthHost::new(home.clone(), cancellation)
        });
        Ok(self.attach_operator_auth_factory(factory))
    }

    #[cfg(feature = "config-fixture")]
    pub fn with_operator_auth_home_and_factory_for_test(
        self,
        home: impl Into<PathBuf>,
        factory: Arc<
            dyn Fn(
                    crate::runtime::RunCancellation,
                ) -> std::result::Result<crate::auth::host::AuthHost, String>
                + Send
                + Sync,
        >,
    ) -> Result<Self, String> {
        let _paths = Self::validated_operator_home(home)?;
        Ok(self.attach_operator_auth_factory(factory))
    }

    fn validated_operator_home(home: impl Into<PathBuf>) -> Result<AgentPaths, String> {
        AgentPaths::from_home(home.into())
            .map_err(|_| "agent home could not be resolved".to_string())
    }

    fn attach_operator_auth_factory(
        self,
        factory: crate::runtime::agent_host::AuthHostFactory,
    ) -> Self {
        self.service.set_provider_auth_host_factory(factory);
        self
    }

    /// Compatibility initializer for embeddings that intentionally install
    /// both provider OAuth and workspace authority from one trusted home.
    pub fn with_trusted_auth_home(self, home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let factory: crate::runtime::agent_host::AuthHostFactory = Arc::new(move |cancellation| {
            crate::auth::host::AuthHost::new(home.clone(), cancellation)
        });
        self.service.set_auth_host_factory(Arc::clone(&factory));
        self.service.set_workspace_host_factory(factory);
        self
    }

    /// Selects the RSS agent source through the embedded source policy.
    ///
    /// `selection` is a bounded public map `{source?, legacy_script?}` whose
    /// values are the exact original environment strings. Every priority,
    /// migration, validation, and fallback decision is made by the RSS
    /// policy; this constructor never trims, normalizes, or defaults a
    /// string. `sqlite_path` selects the existing native SQLite host.
    pub fn with_agent_selection(
        config: AgentGatewayConfig,
        selection: serde_json::Value,
        sqlite_path: Option<&FsPath>,
    ) -> Result<Self, String> {
        Self::with_agent_selection_and_compaction(
            config,
            selection,
            sqlite_path,
            CompactionSettings::default(),
        )
    }

    /// Selects the RSS entry and passes the existing validated compaction
    /// settings as typed runtime data to the shared service.
    pub fn with_agent_selection_and_compaction(
        config: AgentGatewayConfig,
        selection: serde_json::Value,
        sqlite_path: Option<&FsPath>,
        compaction_settings: CompactionSettings,
    ) -> Result<Self, String> {
        config
            .validate()
            .map_err(|error| format!("invalid gateway configuration: {error}"))?;
        let decision = run_source_policy(&selection)?;
        let agent_config = AgentConfig {
            http: config.http.clone(),
            sqlite: config.sqlite.clone(),
            fuel: config.fuel,
        };
        match decision {
            AgentSourceDecision::File {
                path,
                deprecated_override,
            } => {
                // Errors opening/compiling the selected file are static and
                // never fall back to bundled nor echo the path or compiler
                // private data.
                let runner = AgentRunner::from_file(&path, agent_config)
                    .map_err(|_| "selected agent source could not be compiled".to_string())?;
                let metadata = AgentSourceMetadata {
                    kind: "file",
                    hash: runner.snapshot_digest().to_string(),
                    deprecated_override,
                };
                Self::assemble(
                    config,
                    runner,
                    Some(PathBuf::from(path)),
                    Some(metadata),
                    sqlite_path,
                    compaction_settings.clone(),
                )
            }
            AgentSourceDecision::BundledCoding {
                deprecated_override,
            } => {
                // Native admitted mapping: the policy recognized
                // `{kind:"bundled",resource:"coding"}`. Compile the immutable
                // embedded entry through the native closed-bundle API and
                // install it through the tagged bundled route. This admits a
                // resource; it never reads the checkout module tree and it
                // does not select a default for any other key.
                Self::assemble_bundled(
                    config,
                    BUNDLED_CODING_KEY,
                    deprecated_override,
                    sqlite_path,
                    compaction_settings,
                )
            }
        }
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
            CompactionSettings::default(),
        ));
        service.install_agent_runner(runner);
        service
            .install_native_tool_runtime(std::path::Path::new(":memory:"))
            .map_err(|error| format!("compile embedded tool runtime: {error}"))?;
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source,
            http_config,
            metrics,
            source_metadata: None,
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
            CompactionSettings::default(),
        ));
        service.install_agent_entry(path);
        service.install_agent_runner(runner);
        service
            .install_native_tool_runtime(std::path::Path::new(":memory:"))
            .map_err(|error| format!("compile embedded tool runtime: {error}"))?;
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source: None,
            http_config,
            metrics,
            source_metadata: None,
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
        Self::assemble(
            config,
            runner,
            Some(path),
            None,
            Some(sqlite_path.as_ref()),
            CompactionSettings::default(),
        )
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
            CompactionSettings::default(),
        ));
        service.install_agent_runner(runner);
        service
            .install_native_tool_runtime(path.as_ref())
            .map_err(|error| format!("compile embedded tool runtime: {error}"))?;
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source,
            http_config,
            metrics,
            source_metadata: None,
        })
    }

    pub fn with_sqlite_path(
        config: AgentGatewayConfig,
        path: impl AsRef<FsPath>,
    ) -> Result<Self, String> {
        // Empty selection, SQLite-backed: the bundled coding entry is chosen
        // by the RSS source policy, never in Rust.
        Self::with_agent_selection(config, serde_json::json!({}), Some(path.as_ref()))
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

    /// Bounded public source facts for `/health/detailed` (`kind`, native
    /// snapshot `hash`, `deprecated_override`), or `None` when the state was
    /// built through a legacy constructor with no RSS selection.
    #[allow(dead_code)] // Consumed by the health handler once its fields ship.
    pub(crate) fn source_metadata(&self) -> Option<&AgentSourceMetadata> {
        self.source_metadata.as_deref()
    }

    /// Assembles one gateway state from an already-compiled runner, the
    /// optional live file entry (so live-tree freshness still applies), the
    /// optional public source metadata, and the optional native SQLite host.
    fn assemble(
        config: AgentGatewayConfig,
        runner: AgentRunner,
        entry: Option<PathBuf>,
        source_metadata: Option<AgentSourceMetadata>,
        sqlite_path: Option<&FsPath>,
        compaction_settings: CompactionSettings,
    ) -> Result<Self, String> {
        let http_config = config.http.clone();
        let metrics = Arc::new(Metrics::default());
        let (store, persistence) = open_gateway_store(&config, sqlite_path, &metrics)?;
        let service = Arc::new(AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            persistence,
            None,
            http_config.clone(),
            Arc::clone(&metrics),
            compaction_settings,
        ));
        if let Some(entry) = entry {
            service.install_agent_entry(entry);
        }
        service.install_agent_runner(runner);
        service
            .install_native_tool_runtime(
                sqlite_path.unwrap_or_else(|| std::path::Path::new(":memory:")),
            )
            .map_err(|error| format!("compile embedded tool runtime: {error}"))?;
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source: None,
            http_config,
            metrics,
            source_metadata: source_metadata.map(Arc::new),
        })
    }

    /// Assembles a gateway state whose entry is the immutable embedded
    /// bundled coding resource. The native closed-bundle compile and the
    /// tagged entry publication happen inside the service *before* the state
    /// is returned, so no worker ever sees a bundled tag without its admitted
    /// runner. The public hash is the installed runner's own native snapshot
    /// digest (never recomputed here).
    fn assemble_bundled(
        config: AgentGatewayConfig,
        key: &str,
        deprecated_override: bool,
        sqlite_path: Option<&FsPath>,
        compaction_settings: CompactionSettings,
    ) -> Result<Self, String> {
        let http_config = config.http.clone();
        let metrics = Arc::new(Metrics::default());
        let (store, persistence) = open_gateway_store(&config, sqlite_path, &metrics)?;
        let service = Arc::new(AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            persistence,
            None,
            http_config.clone(),
            Arc::clone(&metrics),
            compaction_settings,
        ));
        service.install_bundled_agent_entry(key)?;
        service
            .install_native_tool_runtime(
                sqlite_path.unwrap_or_else(|| std::path::Path::new(":memory:")),
            )
            .map_err(|error| format!("compile embedded tool runtime: {error}"))?;
        let hash = service
            .installed_runner_snapshot_digest()
            .ok_or_else(|| "native bundled agent source could not be compiled".to_string())?;
        let metadata = AgentSourceMetadata {
            kind: "bundled",
            hash,
            deprecated_override,
        };
        Ok(Self {
            config: Arc::clone(service.config()),
            store,
            service,
            agent_source: None,
            http_config,
            metrics,
            source_metadata: Some(Arc::new(metadata)),
        })
    }
}

/// The in-memory or SQLite-backed store plus its optional persistence handle.
type GatewayStoreHandle = (
    Arc<RwLock<store::GatewayStore>>,
    Option<Arc<store::GatewayPersistence>>,
);

/// Opens the in-memory or SQLite-backed gateway store for the given config.
fn open_gateway_store(
    config: &AgentGatewayConfig,
    sqlite_path: Option<&FsPath>,
    metrics: &Arc<Metrics>,
) -> Result<GatewayStoreHandle, String> {
    match sqlite_path {
        Some(path) => {
            let persistence = Arc::new(
                store::GatewayPersistence::open_with_metrics(config, path, Arc::clone(metrics))
                    .map_err(|error| format!("open gateway SQLite state: {error}"))?,
            );
            let loaded = persistence
                .load()
                .map_err(|error| format!("load gateway SQLite state: {error}"))?;
            Ok((Arc::new(RwLock::new(loaded)), Some(persistence)))
        }
        None => Ok((Arc::new(RwLock::new(store::GatewayStore::default())), None)),
    }
}

/// Compiles the generated catalog's standalone source policy and runs its
/// exported `run(context)` entry on the bounded public selection map.
fn run_source_policy(selection: &serde_json::Value) -> Result<AgentSourceDecision, String> {
    let serialized = serde_json::to_vec(selection)
        .map_err(|error| format!("invalid agent source selection: {error}"))?;
    if serialized.len() > MAX_AGENT_SELECTION_BYTES {
        return Err("agent source selection exceeds the bounded size".to_string());
    }
    let source = crate::bundled_rss_sources()
        .iter()
        .find(|(key, _)| *key == SOURCE_POLICY_KEY)
        .map(|(_, source)| *source)
        .ok_or_else(|| "agent source policy is unavailable".to_string())?;
    let runner = AgentRunner::from_source(source, AgentConfig::default())
        .map_err(|error| format!("compile RSS agent source policy: {error}"))?;
    let value = runner
        .run_with_context(json_to_vm_value(selection))
        .map_err(|error| format!("run RSS agent source policy: {error}"))?;
    let decision = vm_value_to_json(&value);
    let reply = serde_json::to_vec(&decision)
        .map_err(|_| "invalid_agent_source: policy returned an invalid decision".to_string())?;
    if reply.len() > MAX_AGENT_SELECTION_BYTES {
        return Err("agent source policy response exceeds the bounded size".to_string());
    }
    parse_source_decision(&decision)
}

/// Admits a source-policy decision. The native descriptors the policy can
/// return are the only recognized shapes; a failure decision keeps the
/// policy's own static code and message and is never converted into a
/// bundled fallback.
fn parse_source_decision(decision: &serde_json::Value) -> Result<AgentSourceDecision, String> {
    let deprecated_override = decision
        .get("deprecated_override")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| "invalid_agent_source: policy returned an invalid decision".to_string())?;
    match decision.get("ok").and_then(serde_json::Value::as_bool) {
        Some(true) => {}
        Some(false) => {
            let code = decision
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    "invalid_agent_source: policy returned an invalid decision".to_string()
                })?;
            let message = decision
                .get("error")
                .and_then(|error| error.get("message"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    "invalid_agent_source: policy returned an invalid decision".to_string()
                })?;
            return Err(format!("{code}: {message}"));
        }
        None => {
            return Err("invalid_agent_source: policy returned an invalid decision".to_string());
        }
    }
    let descriptor = decision
        .get("descriptor")
        .ok_or_else(|| "invalid_agent_source: policy returned no descriptor".to_string())?;
    match descriptor.get("kind").and_then(serde_json::Value::as_str) {
        Some("bundled") => {
            match descriptor
                .get("resource")
                .and_then(serde_json::Value::as_str)
            {
                Some("coding") => Ok(AgentSourceDecision::BundledCoding {
                    deprecated_override,
                }),
                _ => Err("unsupported_agent_source: descriptor is unsupported".to_string()),
            }
        }
        Some("file") => {
            let path = descriptor
                .get("path")
                .and_then(serde_json::Value::as_str)
                .filter(|path| !path.is_empty())
                .ok_or_else(|| "invalid_agent_source: file descriptor is invalid".to_string())?;
            Ok(AgentSourceDecision::File {
                path: path.to_string(),
                deprecated_override,
            })
        }
        _ => Err("unsupported_agent_source: descriptor is unsupported".to_string()),
    }
}
