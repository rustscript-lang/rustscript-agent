//! HTTP gateway: state construction, the API server router, and the
//! RSS-backed store. Platform adapters (API Server, later Telegram) consume
//! AgentService and cannot call providers or tools directly.

mod api_server;
mod effects;
mod plugins;
/// Native Telegram Bot API transport, poller, and adapter. Public so
/// integration tests can drive the client and adapter against a fixture
/// server.
pub mod telegram;
/// Canonical event → Telegram text rendering (pure; no I/O).
mod telegram_format;
mod telegram_render;
mod workspaces;
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

use crate::auth::{
    host::{RunOAuthCancel, SystemOAuthClock},
    native_https::NativeHttpsTransport,
    oauth::{
        BoundedHttpsTransport, BrowserOpener, CallbackMode, CallbackWaiter, OAuthError, OAuthHost,
        OAuthIoContext, PreparedCallbackSession, RawCallbackInput,
    },
};
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

/// Headless callback policy for operator provider transport. Login callbacks
/// are unavailable in the gateway process: no loopback listener is bound and
/// no manual input is read. The typed transport failure is the same one the
/// rest of the provider transport path already maps to `transport_error`.
struct HeadlessCallbackDeny;

impl CallbackWaiter for HeadlessCallbackDeny {
    fn prepare(
        &self,
        _mode: CallbackMode,
        _context: &OAuthIoContext,
    ) -> Result<Option<Arc<dyn PreparedCallbackSession>>, OAuthError> {
        Err(headless_oauth_unavailable())
    }

    fn wait_one(&self, _context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
        Err(headless_oauth_unavailable())
    }
}

/// Headless browser policy for operator provider transport. The service has no
/// user desktop session to open; this never executes a browser command.
struct HeadlessBrowserDeny;

impl BrowserOpener for HeadlessBrowserDeny {
    fn open(&self, _url: &str, _context: &OAuthIoContext) -> Result<(), OAuthError> {
        Err(headless_oauth_unavailable())
    }
}

fn headless_oauth_unavailable() -> OAuthError {
    OAuthError::Transport {
        message: "headless_oauth_unavailable".to_string(),
    }
}

/// Builds the single headless OAuth host shape used by the operator provider
/// factory. The transport is injected so the same construction can be driven
/// by a typed fixture; the deny policies have no state and never bind or exec.
fn headless_oauth_host(
    transport: Arc<dyn BoundedHttpsTransport>,
    cancellation: crate::runtime::RunCancellation,
) -> Arc<OAuthHost> {
    Arc::new(OAuthHost::new(
        transport,
        Arc::new(HeadlessCallbackDeny),
        Arc::new(HeadlessBrowserDeny),
        Arc::new(SystemOAuthClock),
        Arc::new(RunOAuthCancel::new(cancellation)),
    ))
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
    /// The provider factory receives the existing headless native HTTPS
    /// transport: no browser, callback listener, manual input, or scripted
    /// fixture enters this path.
    pub fn with_operator_auth_home(self, home: impl Into<PathBuf>) -> Result<Self, String> {
        let home = Self::validated_operator_home(home)?.home;
        let transport: Arc<dyn BoundedHttpsTransport> = Arc::new(NativeHttpsTransport::new());
        let factory: crate::runtime::agent_host::AuthHostFactory = Arc::new(move |cancellation| {
            let oauth = headless_oauth_host(Arc::clone(&transport), cancellation.clone());
            crate::auth::host::AuthHost::new(home.clone(), cancellation)
                .map(|host| host.with_oauth_host(oauth))
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
                let runner = AgentRunner::from_file(std::path::Path::new(&path), agent_config)
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
        let runner = AgentRunner::from_file(std::path::Path::new(&path), agent_config)
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
        let runner = AgentRunner::from_file(std::path::Path::new(&path), agent_config)
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
        let (store, persistence) = open_gateway_store(&config, Some(path.as_ref()), &metrics)?;
        let agent_source = Some(Arc::new(source));
        let service = Arc::new(AgentService::new(
            Arc::new(config),
            Arc::clone(&store),
            persistence,
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

    /// Fixture-only wrapper around the existing Telegram session producer.
    /// It creates the live synthetic telegram-addressed session and returns its
    /// deterministic id; no platform route or forged binding is added.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub async fn ensure_telegram_session_for_test(
        &self,
        account: &str,
        chat_id: i64,
        thread_id: Option<i64>,
        user_id: &str,
    ) -> Result<String, String> {
        let session_id = telegram::session_id_for(account, chat_id, thread_id);
        telegram::ensure_session(
            self,
            &session_id,
            account,
            &chat_id.to_string(),
            thread_id.map(|id| id.to_string()).as_deref(),
            user_id,
        )
        .await?;
        Ok(session_id)
    }

    /// Host startup or embedding binds plugin control. Request JSON cannot.
    pub fn with_plugin_control(
        self,
        authorization: crate::plugins::InstallAuthorization,
        source_root: PathBuf,
        deployment_space: impl Into<String>,
    ) -> Result<Self, String> {
        self.service
            .bind_plugin_control(authorization, source_root, deployment_space.into())?;
        Ok(self)
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
    if config.managed_workspace.is_some()
        && sqlite_path.is_none_or(|path| !path.is_absolute() || path == FsPath::new(":memory:"))
    {
        return Err(
            "managed workspace requires an absolute persistent database; persistence is mandatory"
                .into(),
        );
    }
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

#[cfg(test)]
mod headless_provider_transport_tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };

    use rustscript_vm::{
        CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
        compile_source_at_path_with_flavor_and_options,
    };

    use super::{HeadlessBrowserDeny, HeadlessCallbackDeny, headless_oauth_host};
    use crate::{
        auth::{
            host::{AuthHost, RunOAuthCancel, SystemOAuthClock, auth_host_catalog},
            oauth::{
                BrowserOpener, CallbackMode, CallbackWaiter, OAuthIoContext, ScriptedHttpsTransport,
            },
        },
        runtime::RunCancellation,
    };

    fn fixture_home() -> PathBuf {
        let base = PathBuf::from(
            std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned task lease temp"),
        );
        let home = base.join(format!(
            "gateway-headless-provider-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&home).expect("create private fixture home");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700))
                .expect("fixture home mode");
        }
        let config = format!(
            "version: 1\n\
             agent:\n  source: bundled:coding\n  max_turns: 64\n  max_tool_calls: 128\n  max_tool_output_bytes: 1048576\n\
             model:\n  provider: openai-codex\n  model: fixture-model\n\
             providers:\n  openai-codex:\n    protocol: openai-chat-completions\n    base_url: https://provider.synthetic.test/v1\n    auth: fixture-codex\n\
             workspaces:\n  allowed_roots:\n    - {base}\n  default: {base}\n\
             approvals:\n  read: allow\n  write: ask\n  process: ask\n",
            base = base.display()
        );
        fs::write(home.join("config.yaml"), config).expect("write synthetic config");
        // The exact repository fixture, with only its fixed expiry moved far
        // enough into the future to keep the synthetic credential active.
        let fixtures =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        let auth = fs::read_to_string(fixtures.join("auth.yaml"))
            .expect("read synthetic auth fixture")
            .replace("1788440000000", "1900000000000");
        fs::write(home.join("auth.yaml"), auth).expect("write synthetic auth fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                    .expect("fixture file mode");
            }
        }
        home
    }

    fn record(fields: Vec<(&str, Value)>) -> Value {
        Value::map(
            fields
                .into_iter()
                .map(|(name, value)| (Value::string(name), value))
                .collect(),
        )
    }

    fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
        let Value::Map(entries) = value else {
            panic!("expected RSS record, got {value:?}");
        };
        entries
            .iter()
            .find_map(|(key, value)| match key {
                Value::String(key) if key.as_ref() == name => Some(value),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing RSS field {name}"))
    }

    fn invoke(vm: &mut Vm, name: &str, args: &[Value]) -> Value {
        let callable = vm
            .resolve_exported_callable(name)
            .unwrap_or_else(|error| panic!("resolve RSS entry {name}: {error}"));
        vm.invoke_callable(callable, args)
            .unwrap_or_else(|error| panic!("invoke RSS entry {name}: {error}"))
    }

    fn compile_vm(home: &Path, transport: Arc<ScriptedHttpsTransport>) -> (Vm, AuthHost, Value) {
        let module_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/auth/fallible_contract.rss");
        let source = fs::read_to_string(&module_path).expect("read production fallible RSS");
        let catalog = auth_host_catalog();
        let compiled = compile_source_at_path_with_flavor_and_options(
            &module_path,
            &source,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
        )
        .unwrap_or_else(|error| panic!("compile production fallible RSS: {error}"));
        let mut vm = Vm::new_shared(Arc::new(compiled.program));
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let auth = AuthHost::new(home.to_path_buf(), cancellation.clone())
            .expect("native auth host")
            .with_oauth_host(headless_oauth_host(transport, cancellation));
        let mut registry = HostFunctionRegistry::restricted();
        auth.register(&mut registry, catalog.as_ref())
            .expect("register real auth host catalog");
        registry
            .bind_vm_cached(&mut vm)
            .expect("bind restricted production registry");
        assert!(matches!(vm.run().expect("run RSS root"), VmStatus::Halted));
        let bound = auth.bind_vm(&mut vm).expect("bind native host home");
        (vm, auth, field(&bound, "host_home").clone())
    }

    /// The production headless constructor sends one real provider request
    /// through the typed transport fixture: the configured authority/path,
    /// the synthetic access authorization, and no secret in the body. The
    /// cleanup entry runs after the send. This proves the send contract only;
    /// the packaged binary TCP/TLS test remains the production-wiring proof.
    #[test]
    fn headless_factory_sends_configured_provider_request_with_synthetic_authorization() {
        let home = fixture_home();
        let transport = Arc::new(ScriptedHttpsTransport::new());
        transport.push_raw(200, r#"{"object":"list","data":[]}"#);
        let (mut vm, _auth, host_home) = compile_vm(&home, transport.clone());
        let policy = invoke(&mut vm, "snapshot", std::slice::from_ref(&host_home));
        let access = invoke(&mut vm, "issue_access", std::slice::from_ref(&policy));
        let request = record(vec![
            ("policy_handle", policy.clone()),
            ("credential_id", Value::string("fixture-codex")),
            ("method", Value::string("POST")),
            ("path", Value::string("/v1/chat/completions")),
            (
                "public_headers",
                Value::array(vec![
                    record(vec![
                        ("name", Value::string("accept")),
                        ("value", Value::string("application/json")),
                    ]),
                    record(vec![
                        ("name", Value::string("content-type")),
                        ("value", Value::string("application/json")),
                    ]),
                ]),
            ),
            (
                "public_body",
                Value::string(r#"{"model":"fixture-model","messages":[]}"#),
            ),
        ]);
        let usage = record(vec![
            ("kind", Value::string("access")),
            ("access_handle", access),
            ("refresh_handle", Value::Null),
            ("code_handle", Value::Null),
            ("verifier_handle", Value::Null),
            ("device_handle", Value::Null),
        ]);
        let result = invoke(
            &mut vm,
            "transport_result_then_cleanup",
            &[request, usage, policy],
        );
        assert_eq!(
            field(&result, "cleanup_completed"),
            &Value::Bool(true),
            "the transport cleanup entry must run after the send"
        );
        let transport_result = field(&result, "transport");
        assert_eq!(
            field(transport_result, "ok"),
            &Value::Bool(true),
            "the typed transport fixture must accept the provider request"
        );
        assert_eq!(
            field(transport_result, "error"),
            &Value::Null,
            "a successful fixture send has no transport failure"
        );

        let sent = transport.take_sent();
        assert_eq!(sent.len(), 1, "exactly one provider request is sent");
        assert_eq!(sent[0].method, "POST");
        assert_eq!(
            sent[0].url, "https://provider.synthetic.test/v1/chat/completions",
            "the configured base_url supplies the admitted authority and path"
        );
        assert_eq!(
            sent[0].headers.get("authorization").map(String::as_str),
            Some("Bearer SYNTHETIC_ACCESS_TOKEN"),
            "the synthetic access credential is injected host-side"
        );
        assert!(
            !sent[0].body.contains("SYNTHETIC_ACCESS_TOKEN"),
            "the access secret must never enter the request body"
        );
        assert!(
            !sent[0].body.to_ascii_lowercase().contains("authorization"),
            "the body carries only the public provider payload"
        );
    }

    /// The private deny policies fail at the OAuth boundary with the existing
    /// typed transport error. They hold no state and have no bind/exec path.
    #[test]
    fn headless_denies_callback_and_browser_without_listener_or_exec() {
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let context = OAuthIoContext::new(
            cancellation
                .deadline_instant()
                .expect("finite OAuth context deadline"),
            Arc::new(SystemOAuthClock),
            Arc::new(RunOAuthCancel::new(cancellation)),
        );
        let prepare = match HeadlessCallbackDeny.prepare(CallbackMode::Browser, &context) {
            Ok(_) => panic!("headless callback preparation must fail closed"),
            Err(error) => error,
        };
        assert_eq!(prepare.code(), "transport_error");
        let wait = match HeadlessCallbackDeny.wait_one(&context) {
            Ok(_) => panic!("headless callback waiting must fail closed"),
            Err(error) => error,
        };
        assert_eq!(wait.code(), "transport_error");
        let open =
            match HeadlessBrowserDeny.open("https://synthetic.example/oauth/authorize", &context) {
                Ok(()) => panic!("headless browser opening must fail closed"),
                Err(error) => error,
            };
        assert_eq!(open.code(), "transport_error");
    }
}
