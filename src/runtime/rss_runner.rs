//! RSS run execution: one exported `run(context)` callable driven through the
//! core invocation item stream.
//!
//! The runner resolves the exported `run` entry, passes the exact structured
//! context as the sole callable argument, and consumes the ordered invocation
//! stream: zero or more `Event(Value)` items delivered through the embedding
//! sink, then exactly one `Complete(Value)` or one typed error, then a fused
//! end of stream. Only the `Complete` value is returned. Script-visible events
//! come exclusively from `stream::emit(value)`.
//!
//! Cancellation is authoritative and typed. A shared [`RunCancellation`]
//! carries the requested reason and wall-clock deadline; the runner observes
//! it between polls and calls the core cancellation API with the typed reason,
//! and a watcher thread jumps the epoch so pure CPU work is interrupted within
//! the configured epoch bound (surfacing as a typed deadline failure).

use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use rustscript_vm::{
    CallReturn, CancellationReason, CancellationToken, CompileSourceFileOptions, EpochHandle,
    HostAsyncBridge, HostFunctionRegistry, HostFuture, HostFutureOutput, HttpConfig, HttpHostExt,
    InvocationError, InvocationItem, InvocationPoll, SourceFlavor, SqliteHostExt, SqlitePolicy,
    Value, Vm, VmError, VmResult, VmStatus, VmYieldReason,
    compile_source_at_path_with_flavor_and_options, compile_source_with_flavor_and_options,
    register_http_builtin_module_from_catalog, register_sqlite_builtin_module_from_catalog,
};

use super::agent_host::{
    AgentHostBridges, AgentHostState, AgentProviderHost, agent_host_catalog,
    register_agent_host_functions,
};
use crate::capabilities::sha256_hex;
use crate::domain::{json_to_vm_value, vm_value_to_json};
use crate::registry::ToolRegistry;
use crate::tool_schema::ToolDescriptor;
use serde_json::json;

pub const MAX_AGENT_SOURCE_BYTES: usize = 1024 * 1024;
pub const COMPILE_CACHE_CAP: usize = 8;
pub const COMPILE_CACHE_WEIGHT_CAP: usize = COMPILE_CACHE_CAP * MAX_AGENT_SOURCE_BYTES;

thread_local! {
    static AFTER_SNAPSHOT_HOOK: Cell<Option<fn(&Path)>> = const { Cell::new(None) };
}

/// Test seam: invoked after `from_file` captures an immutable snapshot and
/// before the compiler reads the materialized sandbox copy.
pub fn set_after_snapshot_hook(hook: Option<fn(&Path)>) {
    AFTER_SNAPSHOT_HOOK.with(|cell| cell.set(hook));
}

fn invoke_after_snapshot(path: &Path) {
    AFTER_SNAPSHOT_HOOK.with(|cell| {
        if let Some(hook) = cell.get() {
            hook(path);
        }
    });
}

struct CachedProgram {
    program: rustscript_vm::Program,
    weight: usize,
}

struct ProgramLru {
    entries: HashMap<String, CachedProgram>,
    order: VecDeque<String>,
    total_weight: usize,
}

impl ProgramLru {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            total_weight: 0,
        }
    }

    fn get(&mut self, digest: &str) -> Option<rustscript_vm::Program> {
        if !self.entries.contains_key(digest) {
            return None;
        }
        if let Some(index) = self.order.iter().position(|key| key == digest) {
            self.order.remove(index);
        }
        self.order.push_back(digest.to_string());
        self.entries.get(digest).map(|entry| entry.program.clone())
    }

    fn insert(&mut self, digest: String, program: rustscript_vm::Program, weight: usize) {
        if self.entries.contains_key(&digest) {
            if let Some(index) = self.order.iter().position(|key| key == &digest) {
                self.order.remove(index);
            }
            self.order.push_back(digest);
            return;
        }
        if weight > COMPILE_CACHE_WEIGHT_CAP {
            return;
        }
        while !self.order.is_empty()
            && (self.order.len() >= COMPILE_CACHE_CAP
                || self.total_weight.saturating_add(weight) > COMPILE_CACHE_WEIGHT_CAP)
        {
            if let Some(old) = self.order.pop_front()
                && let Some(entry) = self.entries.remove(&old)
            {
                self.total_weight = self.total_weight.saturating_sub(entry.weight);
            }
        }
        self.total_weight = self.total_weight.saturating_add(weight);
        self.entries
            .insert(digest.clone(), CachedProgram { program, weight });
        self.order.push_back(digest);
    }
}

fn program_cache() -> std::sync::MutexGuard<'static, ProgramLru> {
    static CACHE: OnceLock<Mutex<ProgramLru>> = OnceLock::new();
    CACHE
        .get_or_init(|| Mutex::new(ProgramLru::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn snapshot_module_tree(entry: &Path) -> Result<String> {
    super::module_snapshot::module_tree_digest(entry)
}

fn redact_compile_error(error: impl Display, sandbox: &Path) -> AgentError {
    let mut text = error.to_string();
    if let Some(root) = sandbox.to_str()
        && !root.is_empty()
    {
        text = text.replace(root, "");
    }
    if let Some(tmp) = compile_temp_root().to_str()
        && !tmp.is_empty()
    {
        text = text.replace(tmp, "");
    }
    if let Some(tmp) = std::env::temp_dir().to_str()
        && !tmp.is_empty()
    {
        text = text.replace(tmp, "");
    }
    AgentError::Compile(text)
}

fn compile_temp_root() -> PathBuf {
    std::env::var_os("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

fn compiled_source_program(source: &str) -> Result<(rustscript_vm::Program, String)> {
    if source.len() > MAX_AGENT_SOURCE_BYTES {
        return Err(AgentError::Compile(format!(
            "agent source exceeds {} bytes",
            MAX_AGENT_SOURCE_BYTES
        )));
    }
    let digest = sha256_hex(source.as_bytes());
    {
        let mut cache = program_cache();
        if let Some(program) = cache.get(&digest) {
            return Ok((program, digest));
        }
    }
    let program =
        compile_source_with_flavor_and_options(source, SourceFlavor::RustScript, compile_options())
            .map_err(|error| AgentError::Compile(error.to_string()))?
            .program;
    {
        let mut cache = program_cache();
        if let Some(cached) = cache.get(&digest) {
            return Ok((cached, digest));
        }
        cache.insert(digest.clone(), program.clone(), source.len());
    }
    Ok((program, digest))
}

fn compiled_file_program(path: &Path) -> Result<(rustscript_vm::Program, String)> {
    let snapshot = super::module_snapshot::capture_module_snapshot(path)?;
    invoke_after_snapshot(path);
    let digest = snapshot.digest().to_string();
    {
        let mut cache = program_cache();
        if let Some(program) = cache.get(&digest) {
            return Ok((program, digest));
        }
    }
    let sandbox = snapshot.materialize()?;
    let mut options = compile_options();
    for (rel, bytes) in snapshot.files() {
        let source = std::str::from_utf8(bytes)
            .map_err(|_| AgentError::Compile("module tree file is not valid UTF-8".to_string()))?;
        for key in sandbox.override_source_keys(rel) {
            options = options.with_module_override_source(key, source);
        }
    }
    let program = compile_source_at_path_with_flavor_and_options(
        sandbox.entry(),
        snapshot.entry_source()?,
        SourceFlavor::RustScript,
        options,
    )
    .map_err(|error| redact_compile_error(error, sandbox.sandbox()))?
    .program;
    drop(sandbox);
    {
        let mut cache = program_cache();
        if let Some(cached) = cache.get(&digest) {
            return Ok((cached, digest));
        }
        cache.insert(
            digest.clone(),
            program.clone(),
            snapshot.total_source_bytes(),
        );
    }
    Ok((program, digest))
}

fn rss_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("rss")
}

/// Production bundled coding-agent entry (`rss/agent/main.rss`).
pub fn bundled_agent_main_path() -> PathBuf {
    rss_root().join("agent/main.rss")
}

pub(crate) fn module_tree_digest(path: impl AsRef<Path>) -> Result<String> {
    snapshot_module_tree(path.as_ref())
}

/// Admits the production RSS tool-registry descriptors after generic bounds.
pub fn bundled_tool_registry() -> std::result::Result<ToolRegistry, String> {
    load_bundled_tool_registry()
}

fn load_bundled_tool_registry() -> std::result::Result<ToolRegistry, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("rss/tools/registry.rss");
    let runner =
        AgentRunner::from_file(&path, AgentConfig::default()).map_err(|error| error.to_string())?;
    let result = runner
        .run_with_context(json_to_vm_value(
            &json!({"kind": "descriptors", "config": {}}),
        ))
        .map_err(|error| format!("run RSS registry: {error}"))?;
    let json = vm_value_to_json(&result);
    if json.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(format!("RSS registry failed: {json}"));
    }
    let descriptors = json
        .get("descriptors")
        .cloned()
        .ok_or_else(|| "RSS registry missing descriptors".to_string())?;
    let parsed: Vec<ToolDescriptor> =
        serde_json::from_value(descriptors).map_err(|error| error.to_string())?;
    ToolRegistry::from_descriptors(parsed).map_err(|error| error.to_string())
}

/// Admitted production RSS registry entries for tests that mutate a snapshot.
pub fn bundled_tool_entries() -> Vec<crate::registry::ToolRegistryEntry> {
    bundled_tool_registry()
        .expect("RSS tool registry validates")
        .snapshot()
        .entries()
        .to_vec()
}

/// Epoch ticks granted to one cancellable run. The cancellation watcher jumps
/// the epoch past this deadline, so the interpreter's next epoch check
/// interrupts pure CPU work within one check interval.
pub const RUN_EPOCH_DEADLINE_TICKS: u64 = 1_000_000_000;

/// Interpreter operations between epoch checks on cancellable runs.
pub const RUN_EPOCH_CHECK_INTERVAL: u32 = 1_000;

pub type Result<T> = std::result::Result<T, AgentError>;

/// Compiles one RSS agent source and drives its exported `run(context)` entry
/// with the given delivery sink and cancellation. Shared by the AgentService
/// worker and the legacy chat completion path.
pub(crate) fn execute_rss_source(
    source: &str,
    http_config: HttpConfig,
    sqlite_policy: SqlitePolicy,
    context: Value,
    sink: &mut dyn RunEventSink,
    cancellation: &RunCancellation,
) -> std::result::Result<Value, RunError> {
    if source.len() > MAX_AGENT_SOURCE_BYTES {
        return Err(RunError::Setup(VmError::HostError(format!(
            "RSS source exceeds {} bytes",
            MAX_AGENT_SOURCE_BYTES
        ))));
    }
    let runner = AgentRunner::from_source(
        source,
        AgentConfig {
            http: http_config,
            sqlite: sqlite_policy,
            fuel: None,
        },
    )
    .map_err(|error| {
        RunError::Vm(VmError::HostError(format!(
            "compile RSS run source: {error}"
        )))
    })?;
    runner.run_with_context_and_events(context, sink, cancellation)
}

#[derive(Debug)]
pub enum AgentError {
    Io(std::io::Error),
    Compile(String),
}

impl Display for AgentError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Compile(error) => write!(formatter, "RustScript compile error: {error}"),
        }
    }
}

impl Error for AgentError {}

impl From<std::io::Error> for AgentError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentConfig {
    pub http: HttpConfig,
    pub sqlite: SqlitePolicy,
    pub fuel: Option<u64>,
}

impl AgentConfig {
    pub fn new(http: HttpConfig) -> Self {
        Self {
            http,
            sqlite: SqlitePolicy::default(),
            fuel: Some(10_000_000),
        }
    }

    pub fn for_hosts<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let allowed_hosts = hosts
            .into_iter()
            .map(|host| host.as_ref().to_ascii_lowercase())
            .collect();
        Self {
            http: HttpConfig {
                allowed_hosts,
                ..HttpConfig::default()
            },
            sqlite: SqlitePolicy::default(),
            fuel: Some(10_000_000),
        }
    }

    pub fn with_sqlite_root(mut self, root: impl AsRef<Path>) -> Self {
        self.sqlite.database_root = Some(root.as_ref().to_string_lossy().into_owned());
        self
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self::new(HttpConfig::default())
    }
}

/// Typed terminal failure of one run.
///
/// The categories mirror the core invocation stream so the service can commit
/// typed transitions without string comparison.
#[derive(Debug)]
pub enum RunError {
    /// The program does not export a `run` callable.
    NoEntry,
    /// The exported `run` entry has an incompatible signature.
    EntryArity { expected: usize, got: usize },
    /// A typed terminal failure from the core invocation stream.
    Invocation(InvocationError),
    /// The invocation stream fused without delivering a terminal item.
    EarlyEnd,
    /// The event sink closed before completion (a terminal was committed
    /// elsewhere, or delivery is unavailable).
    DeliveryClosed,
    /// The event sink rejected an event with a typed code.
    DeliveryRejected { code: &'static str, message: String },
    /// The invocation could not be started or driven (VM configuration or
    /// frame-state failure).
    Setup(VmError),
    /// The root frame failed before the invocation started.
    Vm(VmError),
}

impl Display for RunError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoEntry => formatter.write_str("agent script does not export run(context)"),
            Self::EntryArity { expected, got } => write!(
                formatter,
                "exported run takes {got} parameter(s); expected exactly {expected}"
            ),
            Self::Invocation(error) => match error {
                InvocationError::Cancelled(reason) => {
                    write!(formatter, "run cancelled ({})", reason.as_str())
                }
                InvocationError::OutOfFuel { needed, remaining } => write!(
                    formatter,
                    "run exceeded its fuel budget (needed {needed}, remaining {remaining})"
                ),
                InvocationError::DeadlineReached { current, deadline } => write!(
                    formatter,
                    "run exceeded its deadline (current {current}, deadline {deadline})"
                ),
                InvocationError::Capability(error) => {
                    write!(formatter, "run capability failure: {}", error.message())
                }
                InvocationError::Host { message } => {
                    write!(formatter, "run host failure: {message}")
                }
                InvocationError::Vm(error) => write!(formatter, "run vm failure: {error}"),
            },
            Self::EarlyEnd => {
                formatter.write_str("invocation stream ended without a terminal item")
            }
            Self::DeliveryClosed => {
                formatter.write_str("event delivery closed before the run completed")
            }
            Self::DeliveryRejected { code, message } => {
                write!(formatter, "event rejected ({code}): {message}")
            }
            Self::Setup(error) => write!(formatter, "run setup failure: {error}"),
            Self::Vm(error) => write!(formatter, "root frame failure: {error}"),
        }
    }
}

impl Error for RunError {}

/// One rejected event delivery. `Closed` means the bounded delivery path was
/// closed (a terminal was committed elsewhere); `Rejected` carries a typed
/// machine-readable code from the embedding.
#[derive(Debug)]
pub enum RunDeliveryError {
    Closed,
    Rejected { code: &'static str, message: String },
}

/// Event delivery sink owned by the embedding. `deliver` blocks while the
/// bounded delivery path is full, which pauses invocation polling and therefore
/// script execution (backpressure).
pub trait RunEventSink {
    fn deliver(&mut self, value: Value) -> std::result::Result<(), RunDeliveryError>;
}

/// Authoritative run cancellation shared between the service and the worker.
///
/// `request` records the first typed reason; the watcher thread (armed by the
/// runner once the VM exists) jumps the epoch so a pure CPU loop is interrupted
/// within the configured epoch bound. The runner also observes the request
/// between polls and cancels through the core invocation API, preserving the
/// exact typed reason.
#[derive(Clone)]
pub struct RunCancellation {
    inner: Arc<RunCancellationInner>,
}

struct RunCancellationInner {
    requested: Arc<Mutex<Option<CancellationReason>>>,
    deadline: Arc<Mutex<Option<Instant>>>,
    epoch: Arc<Mutex<Option<EpochHandle>>>,
    watcher: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
    stop: Arc<AtomicBool>,
    /// Process token linked to this root. `request` and deadline fire cancel it.
    token: CancellationToken,
    /// Set when a timeout/deadline cannot be represented as `Instant`.
    deadline_overflow: AtomicBool,
}

/// RAII guard that disarms the epoch watcher on every exit path, including panic.
struct EpochWatcherGuard<'a> {
    cancellation: &'a RunCancellation,
}

impl Drop for EpochWatcherGuard<'_> {
    fn drop(&mut self) {
        self.cancellation.disarm();
    }
}

/// Injected runner fault used to prove watcher cleanup on error/panic paths.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RunnerPrepareFault {
    #[default]
    None,
    PanicAfterArm,
    ErrorAfterArm,
    PanicDuringDrive,
}

pub const MAX_RUN_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

impl RunCancellation {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RunCancellationInner {
                requested: Arc::new(Mutex::new(None)),
                deadline: Arc::new(Mutex::new(None)),
                epoch: Arc::new(Mutex::new(None)),
                watcher: Arc::new(Mutex::new(None)),
                stop: Arc::new(AtomicBool::new(false)),
                token: CancellationToken::new(),
                deadline_overflow: AtomicBool::new(false),
            }),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        if timeout > MAX_RUN_TIMEOUT {
            let cancellation = Self::new();
            cancellation
                .inner
                .deadline_overflow
                .store(true, Ordering::SeqCst);
            return cancellation;
        }
        match Instant::now().checked_add(timeout) {
            Some(deadline) => Self::with_deadline(deadline),
            None => {
                let cancellation = Self::new();
                cancellation
                    .inner
                    .deadline_overflow
                    .store(true, Ordering::SeqCst);
                cancellation
            }
        }
    }

    pub fn with_deadline(deadline: Instant) -> Self {
        let cancellation = Self::new();
        *cancellation.inner.deadline.lock().expect("deadline lock") = Some(deadline);
        cancellation
    }

    /// Rebuilds cancellation from a persisted wall-clock deadline. Expired
    /// deadlines fail immediately and never grant a fresh full timeout.
    /// Enormous remaining durations never panic; they mark overflow instead.
    pub fn from_wall_deadline_ms(deadline_at_ms: u64, now_ms: u64) -> Self {
        if now_ms >= deadline_at_ms {
            let cancellation = Self::new();
            cancellation.request(CancellationReason::Deadline);
            cancellation
        } else {
            Self::with_timeout(Duration::from_millis(deadline_at_ms - now_ms))
        }
    }

    /// True when a timeout or persisted deadline could not be converted to Instant.
    pub fn has_deadline_overflow(&self) -> bool {
        self.inner.deadline_overflow.load(Ordering::SeqCst)
    }

    /// True while an epoch watcher thread is armed.
    pub fn watcher_is_armed(&self) -> bool {
        self.inner.watcher.lock().expect("watcher lock").is_some()
    }

    pub fn request(&self, reason: CancellationReason) {
        let mut requested = self.inner.requested.lock().expect("requested lock");
        if requested.is_none() {
            *requested = Some(reason);
        }
        drop(requested);
        self.inner.token.cancel();
    }

    pub fn requested(&self) -> Option<CancellationReason> {
        *self.inner.requested.lock().expect("requested lock")
    }

    /// Native dispatcher parent token linked to this cancellation root.
    pub fn token(&self) -> CancellationToken {
        self.inner.token.clone()
    }

    pub fn deadline_passed(&self) -> bool {
        self.deadline_instant()
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    pub fn deadline_instant(&self) -> Option<Instant> {
        *self.inner.deadline.lock().expect("deadline lock")
    }

    pub fn remaining_deadline(&self) -> Option<Duration> {
        self.deadline_instant()
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    /// Nested adapter runs share request/deadline/token flags but own their epoch
    /// watcher so the parent run is not disarmed when the nested invocation ends.
    pub(crate) fn child(&self) -> Self {
        Self {
            inner: Arc::new(RunCancellationInner {
                requested: Arc::clone(&self.inner.requested),
                deadline: Arc::clone(&self.inner.deadline),
                epoch: Arc::new(Mutex::new(None)),
                watcher: Arc::new(Mutex::new(None)),
                stop: Arc::new(AtomicBool::new(false)),
                token: self.inner.token.clone(),
                deadline_overflow: AtomicBool::new(
                    self.inner.deadline_overflow.load(Ordering::SeqCst),
                ),
            }),
        }
    }

    /// Spawns the epoch watcher once the VM (and its epoch handle) exists.
    pub(crate) fn arm(&self, epoch: EpochHandle) {
        *self.inner.epoch.lock().expect("epoch lock") = Some(epoch);
        let stop = Arc::clone(&self.inner.stop);
        let epoch = self
            .inner
            .epoch
            .lock()
            .expect("epoch lock")
            .clone()
            .expect("armed epoch");
        let requested = Arc::clone(&self.inner.requested);
        let deadline = Arc::clone(&self.inner.deadline);
        let token = self.inner.token.clone();
        let watcher = thread::Builder::new()
            .name("run-epoch-watcher".to_string())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let fire = requested.lock().expect("requested lock").is_some()
                        || deadline
                            .lock()
                            .expect("deadline lock")
                            .is_some_and(|deadline| Instant::now() >= deadline);
                    if fire {
                        token.cancel();
                        epoch.increment_by(RUN_EPOCH_DEADLINE_TICKS);
                        return;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            })
            .expect("spawn run-epoch-watcher");
        *self.inner.watcher.lock().expect("watcher lock") = Some(watcher);
    }

    /// Stops and joins the watcher; the run is over.
    pub(crate) fn disarm(&self) {
        self.inner.stop.store(true, Ordering::Release);
        if let Some(watcher) = self.inner.watcher.lock().expect("watcher lock").take() {
            let _ = watcher.join();
        }
    }
}

impl Default for RunCancellation {
    fn default() -> Self {
        Self::new()
    }
}

/// Compiles and drives one exported `run(context)` callable per run.
#[derive(Clone)]
pub struct AgentRunner {
    program: rustscript_vm::Program,
    config: AgentConfig,
    registry: Arc<HostFunctionRegistry>,
    host: AgentHostBridges,
    prepare_fault: RunnerPrepareFault,
    snapshot_digest: String,
}

impl AgentRunner {
    pub fn from_source(source: &str, config: AgentConfig) -> Result<Self> {
        let (program, digest) = compiled_source_program(source)?;
        Self::from_program(program, config, digest)
    }

    pub fn from_file(path: impl AsRef<Path>, config: AgentConfig) -> Result<Self> {
        let (program, digest) = compiled_file_program(path.as_ref())?;
        Self::from_program(program, config, digest)
    }

    fn from_program(
        program: rustscript_vm::Program,
        config: AgentConfig,
        snapshot_digest: String,
    ) -> Result<Self> {
        let registry = build_restricted_registry()
            .map_err(|error| AgentError::Compile(format!("host registry: {error}")))?;
        Ok(Self {
            program,
            config,
            registry: Arc::new(registry),
            host: AgentHostBridges::default(),
            prepare_fault: RunnerPrepareFault::None,
            snapshot_digest,
        })
    }

    /// Digest of the snapshot or source bytes this runner compiled.
    pub fn snapshot_digest(&self) -> &str {
        &self.snapshot_digest
    }

    /// Effective HTTP/SQLite/fuel policy compiled into this runner.
    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    /// Injects a prepare/drive fault for watcher RAII tests.
    pub fn with_prepare_fault(mut self, fault: RunnerPrepareFault) -> Self {
        self.prepare_fault = fault;
        self
    }

    /// Installs a scripted or custom provider for the serial loop host bridge.
    pub fn with_provider(mut self, provider: Arc<dyn AgentProviderHost>) -> Self {
        self.host.provider = Some(provider);
        self
    }

    /// Replaces the full host-bridge bundle for one run.
    pub fn with_host(mut self, host: AgentHostBridges) -> Self {
        self.host = host;
        self
    }

    /// Installs the sole run cancellation root onto the host bridges.
    pub fn with_cancellation(mut self, cancellation: RunCancellation) -> Self {
        self.host.cancellation = Some(cancellation);
        self
    }

    /// Records backoff delays without sleeping (loop tests).
    pub fn with_skip_sleep(mut self, skip: bool) -> Self {
        self.host.skip_sleep = skip;
        self
    }

    /// Backoff delays requested by the RSS loop, in milliseconds.
    pub fn recorded_sleeps(&self) -> Vec<i64> {
        self.host.sleeps.lock().expect("sleep log lock").requested()
    }

    /// Number of backoff records dropped after the bounded sleep ring filled.
    pub fn recorded_sleep_dropped(&self) -> u64 {
        self.host.sleeps.lock().expect("sleep log lock").dropped()
    }

    /// Runs the exported `run(context)` entry with no event sink and no
    /// cancellation. Returns only the `Complete` value.
    pub fn run_with_context(&self, context: Value) -> std::result::Result<Value, RunError> {
        let (mut vm, callable) = self.prepare_vm(None)?;
        self.run_invocation(&mut vm, callable, context, None, None)
    }

    /// Runs the exported `run(context)` entry, delivering each `Event(Value)`
    /// item through the sink before the terminal item. Blocking inside
    /// `deliver` pauses polling and therefore script execution.
    pub fn run_with_context_and_events(
        &self,
        context: Value,
        sink: &mut dyn RunEventSink,
        cancellation: &RunCancellation,
    ) -> std::result::Result<Value, RunError> {
        let _watcher_guard = EpochWatcherGuard { cancellation };
        let (mut vm, callable) = self.prepare_vm(Some(cancellation))?;
        if self.prepare_fault == RunnerPrepareFault::PanicDuringDrive {
            panic!("injected drive panic");
        }
        self.run_invocation(&mut vm, callable, context, Some(sink), Some(cancellation))
    }

    fn prepare_vm(
        &self,
        cancellation: Option<&RunCancellation>,
    ) -> std::result::Result<(Vm, Value), RunError> {
        let mut vm = Vm::try_new(self.program.clone()).map_err(RunError::Vm)?;
        vm.set_async_bridge(Box::new(AgentAsyncBridge::new()));
        vm.configure_http(self.config.http.clone())
            .map_err(RunError::Setup)?;
        vm.configure_sqlite(self.config.sqlite.clone());
        self.registry
            .bind_vm_cached(&mut vm)
            .map_err(RunError::Setup)?;
        let provider: Arc<dyn AgentProviderHost> = self
            .host
            .provider
            .clone()
            .unwrap_or_else(|| Arc::new(RssAdapterProvider));
        vm.host_context().set_module_state(AgentHostState {
            provider,
            cancellation: cancellation
                .cloned()
                .or_else(|| self.host.cancellation.clone())
                .unwrap_or_default(),
            sleeps: Arc::clone(&self.host.sleeps),
            skip_sleep: self.host.skip_sleep,
            metrics: self.host.metrics.clone(),
            lifecycle: self.host.lifecycle.clone(),
            capability_owner: self.host.capability_owner.clone(),
            filesystem: self.host.filesystem.clone(),
            processes: self.host.processes.clone(),
            artifacts: self.host.artifacts.clone(),
            leases: Arc::new(Mutex::new(HashMap::new())),
            control_hook: self.host.control_hook.clone(),
        });
        if let Some(cancellation) = cancellation {
            vm.set_epoch_check_interval(RUN_EPOCH_CHECK_INTERVAL)
                .map_err(RunError::Setup)?;
            vm.set_epoch_deadline(RUN_EPOCH_DEADLINE_TICKS)
                .map_err(RunError::Setup)?;
            cancellation.arm(vm.epoch_handle());
            match self.prepare_fault {
                RunnerPrepareFault::PanicAfterArm => panic!("injected prepare panic"),
                RunnerPrepareFault::ErrorAfterArm => {
                    return Err(RunError::Setup(VmError::HostError(
                        "injected prepare error".to_string(),
                    )));
                }
                RunnerPrepareFault::None | RunnerPrepareFault::PanicDuringDrive => {}
            }
        } else if let Some(fuel) = self.config.fuel {
            vm.set_fuel(fuel);
        }
        self.drive_root_frame(&mut vm, cancellation)?;
        let callable = vm
            .resolve_exported_callable("run")
            .map_err(|_| RunError::NoEntry)?;
        let arity = match &callable {
            Value::Callable(callable) => self
                .program
                .callable_prototypes
                .get(callable.prototype_id as usize)
                .map(|prototype| prototype.arity as usize)
                .unwrap_or(0),
            _ => 0,
        };
        if arity != 1 {
            return Err(RunError::EntryArity {
                expected: 1,
                got: arity,
            });
        }
        Ok((vm, callable))
    }

    /// Halts the root frame so the exported callable can be started.
    fn drive_root_frame(
        &self,
        vm: &mut Vm,
        cancellation: Option<&RunCancellation>,
    ) -> std::result::Result<(), RunError> {
        loop {
            match vm.run() {
                Ok(VmStatus::Halted) => return Ok(()),
                Ok(VmStatus::Waiting(_)) => {
                    vm.wait_for_host_op_blocking_with_cancel(|| {
                        cancellation.is_some_and(|cancel| {
                            cancel.requested().is_some() || cancel.deadline_passed()
                        })
                    })
                    .map_err(|error| {
                        if let Some(reason) = cancellation.and_then(|cancel| cancel.requested()) {
                            RunError::Invocation(InvocationError::Cancelled(reason))
                        } else if cancellation.is_some_and(|cancel| cancel.deadline_passed()) {
                            RunError::Invocation(InvocationError::Cancelled(
                                CancellationReason::Deadline,
                            ))
                        } else {
                            RunError::Vm(error)
                        }
                    })?;
                }
                Ok(VmStatus::Yielded) => match vm.last_yield_reason() {
                    Some(VmYieldReason::Fuel) => {
                        return Err(RunError::Invocation(InvocationError::OutOfFuel {
                            needed: 1,
                            remaining: vm.get_fuel().unwrap_or(0),
                        }));
                    }
                    Some(VmYieldReason::Epoch) => {
                        if let Some(reason) = cancellation.and_then(|cancel| cancel.requested()) {
                            return Err(RunError::Invocation(InvocationError::Cancelled(reason)));
                        }
                        return Err(RunError::Invocation(InvocationError::DeadlineReached {
                            current: vm.current_epoch(),
                            deadline: vm.epoch_deadline().unwrap_or(0),
                        }));
                    }
                    _ => {
                        return Err(RunError::Vm(VmError::HostError(
                            "root frame yielded unexpectedly".to_string(),
                        )));
                    }
                },
                Err(error) => return Err(RunError::Vm(error)),
            }
        }
    }

    fn run_invocation(
        &self,
        vm: &mut Vm,
        callable: Value,
        context: Value,
        mut sink: Option<&mut dyn RunEventSink>,
        cancellation: Option<&RunCancellation>,
    ) -> std::result::Result<Value, RunError> {
        if matches!(self.prepare_fault, RunnerPrepareFault::PanicDuringDrive) {
            panic!("injected drive panic");
        }
        let result = (|| {
            let mut invocation = vm
                .start_invocation(callable, vec![context])
                .map_err(RunError::Setup)?;
            loop {
                if let Some(reason) = cancellation.and_then(|cancel| cancel.requested()) {
                    invocation.cancel(reason).map_err(RunError::Setup)?;
                } else if cancellation.is_some_and(|cancel| cancel.deadline_passed()) {
                    invocation
                        .cancel(CancellationReason::Deadline)
                        .map_err(RunError::Setup)?;
                }
                // The callable stream pump polls its transport driver inside
                // the VM, so the polling thread must hold a Tokio runtime
                // context for the duration of each poll.
                let runtime = agent_runtime_handle();
                let guard = runtime.enter();
                let poll = invocation.poll_next().map_err(RunError::Setup);
                drop(guard);
                match poll? {
                    InvocationPoll::Pending => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    InvocationPoll::Ready(Some(Ok(InvocationItem::Event(value)))) => {
                        if let Some(sink) = sink.as_deref_mut() {
                            sink.deliver(value).map_err(|error| match error {
                                RunDeliveryError::Closed => RunError::DeliveryClosed,
                                RunDeliveryError::Rejected { code, message } => {
                                    RunError::DeliveryRejected { code, message }
                                }
                            })?;
                        }
                    }
                    InvocationPoll::Ready(Some(Ok(InvocationItem::Complete(value)))) => {
                        return Ok(value);
                    }
                    InvocationPoll::Ready(Some(Err(error))) => {
                        return Err(RunError::Invocation(error));
                    }
                    InvocationPoll::Ready(None) => return Err(RunError::EarlyEnd),
                }
            }
        })();
        if let Some(cancellation) = cancellation {
            cancellation.disarm();
        }
        result
    }
}

/// Binds the restricted capability registry: JSON, bytes conversion, the
/// invocation stream emit builtin, generic SQLite, the HTTP client, and the
/// bounded agent provider/tool host bridges. Ambient runtime input/emit
/// builtins are intentionally absent from agent execution.
fn build_restricted_registry() -> std::result::Result<HostFunctionRegistry, VmError> {
    let catalog = agent_host_catalog();
    let mut registry = HostFunctionRegistry::restricted();
    register_sqlite_builtin_module_from_catalog(&mut registry, catalog.as_ref())?;
    register_http_builtin_module_from_catalog(&mut registry, catalog.as_ref())?;
    register_agent_host_functions(&mut registry, catalog.as_ref())?;
    for name in [
        "json::encode",
        "json::decode",
        "stream::emit",
        "bytes::to_utf8",
        "bytes::to_utf8_lossy",
        "bytes::to_array_u8",
        "bytes::from_utf8",
        "sqlite::open",
        "sqlite::execute",
        "sqlite::query",
        "sqlite::transaction",
        "sqlite::close",
        "sqlite::rows_affected",
        "sqlite::truncated",
        "sqlite::next_cursor",
        "http::client::request",
        "http::client::sse",
    ] {
        registry.allow_builtin(name)?;
    }
    Ok(registry)
}

fn compile_options() -> CompileSourceFileOptions {
    CompileSourceFileOptions::default().with_host_api_catalog(agent_host_catalog())
}

/// Default production provider: invoke the existing RSS adapter harness.
pub(crate) fn default_agent_provider_host() -> Arc<dyn AgentProviderHost> {
    Arc::new(RssAdapterProvider)
}

struct RssAdapterProvider;

impl AgentProviderHost for RssAdapterProvider {
    fn call(
        &self,
        request: &serde_json::Value,
        cancellation: &RunCancellation,
    ) -> serde_json::Value {
        invoke_existing_adapter(request, cancellation)
    }
}

fn invoke_existing_adapter(
    request: &serde_json::Value,
    cancellation: &RunCancellation,
) -> serde_json::Value {
    let provider = request
        .get("provider")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("openai");
    let kind = adapter_kind(provider);
    let mut config = AgentConfig::default();
    if let Some(base_url) = request
        .pointer("/provider_options/base_url")
        .and_then(serde_json::Value::as_str)
    {
        match adapter_http_config(base_url) {
            Ok(parsed) => config = parsed,
            Err(error) => return error,
        }
    }
    let harness_path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/llm/harness.rss");
    let runner = match AgentRunner::from_file(harness_path, config) {
        Ok(runner) => runner,
        Err(error) => {
            return adapter_fail("adapter_unavailable", &error.to_string());
        }
    };
    let mut forwarded = request.clone();
    if let Some(object) = forwarded.as_object_mut() {
        object.remove("provider");
    }
    let profile = serde_json::json!({
        "provider": provider,
        "base_url": request.pointer("/provider_options/base_url").cloned().unwrap_or(serde_json::Value::Null),
        "api_key": request.pointer("/provider_options/api_key").cloned().unwrap_or(serde_json::Value::Null),
        "model": request.get("model").cloned().unwrap_or(serde_json::Value::Null),
    });
    let context = json_to_vm_value(&serde_json::json!({
        "kind": kind,
        "request": forwarded,
        "profile": profile,
    }));
    let child = cancellation.child();
    match runner.run_with_context_and_events(context, &mut DiscardSink, &child) {
        Ok(value) => vm_value_to_json(&value),
        Err(RunError::Invocation(InvocationError::Cancelled(reason))) => {
            if matches!(reason, CancellationReason::Deadline) {
                adapter_fail("deadline_elapsed", "run deadline elapsed")
            } else {
                adapter_fail("cancelled", "run was cancelled")
            }
        }
        Err(RunError::Invocation(InvocationError::DeadlineReached { .. })) => {
            adapter_fail("deadline_elapsed", "run deadline elapsed")
        }
        Err(error) => adapter_fail("adapter_failed", &error.to_string()),
    }
}

fn adapter_http_config(base_url: &str) -> std::result::Result<AgentConfig, serde_json::Value> {
    let url = url::Url::parse(base_url)
        .map_err(|error| adapter_fail("config", &format!("invalid provider base_url: {error}")))?;
    let Some(host) = url.host_str() else {
        return Err(adapter_fail("config", "provider base_url has no host"));
    };
    let Some(port) = url.port_or_known_default() else {
        return Err(adapter_fail(
            "config",
            &format!(
                "provider base_url scheme '{}' has no known default port",
                url.scheme()
            ),
        ));
    };
    let mut config = AgentConfig::for_hosts([host]);
    config.http.allowed_schemes = vec![url.scheme().to_string()];
    config.http.allowed_ports = vec![port];
    if host == "127.0.0.1" || host == "localhost" {
        config.http.allow_private_ips = true;
    }
    Ok(config)
}

struct DiscardSink;

impl RunEventSink for DiscardSink {
    fn deliver(&mut self, _value: Value) -> std::result::Result<(), RunDeliveryError> {
        Ok(())
    }
}

fn adapter_kind(provider: &str) -> &'static str {
    match provider {
        "openai_responses" | "responses" => "openai_responses",
        "anthropic" | "anthropic_messages" => "anthropic_messages",
        "profile:openrouter" => "profile:openrouter",
        "profile:deepseek" => "profile:deepseek",
        "profile:opencode_zen" => "profile:opencode_zen",
        "profile:opencode_go" => "profile:opencode_go",
        "profile:custom" => "profile:custom",
        _ => "openai_chat",
    }
}

fn adapter_fail(code: &str, message: &str) -> serde_json::Value {
    serde_json::json!({
        "ok": false,
        "response": {},
        "error": {
            "status": 0,
            "type": "api_error",
            "code": code,
            "message": message,
            "param": "",
            "request_id": "",
            "retryable": false
        }
    })
}

/// Drives futures submitted by async host builtins (for example the HTTP
/// client) on the shared agent Tokio runtime.
///
/// The VM polls the bridge on its own cadence; the runtime advances timers and
/// I/O readiness in the background so submitted futures make progress without
/// blocking the VM thread. The runtime is process-lifetime (it must never be
/// dropped inside an asynchronous context); dropping the bridge drops the
/// outstanding owned host operations.
struct AgentAsyncBridge {
    runtime: tokio::runtime::Handle,
    futures: HashMap<rustscript_vm::HostOpId, HostFuture>,
}

static AGENT_RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();

fn agent_runtime_handle() -> tokio::runtime::Handle {
    AGENT_RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("agent async bridge runtime should build")
        })
        .handle()
        .clone()
}

impl AgentAsyncBridge {
    fn new() -> Self {
        Self {
            runtime: agent_runtime_handle(),
            futures: HashMap::new(),
        }
    }
}

impl HostAsyncBridge for AgentAsyncBridge {
    fn submit_op(&mut self, op_id: rustscript_vm::HostOpId, future: HostFuture) -> VmResult<()> {
        if self.futures.insert(op_id, future).is_some() {
            return Err(VmError::HostError(format!(
                "duplicate submitted host op {op_id}"
            )));
        }
        Ok(())
    }

    fn poll_op(
        &mut self,
        _op_id: rustscript_vm::HostOpId,
        _cx: &mut Context<'_>,
    ) -> Poll<VmResult<CallReturn>> {
        Poll::Ready(Err(VmError::HostError(
            "unexpected external host op".to_string(),
        )))
    }

    fn poll_submitted_op(
        &mut self,
        op_id: rustscript_vm::HostOpId,
        cx: &mut Context<'_>,
    ) -> Poll<VmResult<HostFutureOutput<CallReturn>>> {
        let poll = {
            let future = match self.futures.get_mut(&op_id) {
                Some(future) => future,
                None => {
                    return Poll::Ready(Err(VmError::HostError(format!(
                        "unknown submitted host op {op_id}"
                    ))));
                }
            };
            let _guard = self.runtime.enter();
            future.as_mut().poll(cx)
        };
        if poll.is_ready() {
            self.futures.remove(&op_id);
        }
        poll
    }

    fn cancel_op(&mut self, op_id: rustscript_vm::HostOpId) {
        self.futures.remove(&op_id);
    }
}

#[cfg(test)]
mod compile_cache_tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn tiny_source(tag: &str) -> String {
        format!(
            "pub fn run(context: map) -> map {{ let _x: string = \"{tag}\"; {{ ok: true }} }}\n"
        )
    }

    #[test]
    fn compile_cache_recovers_from_poison_and_compiles_outside_lock() {
        let _ = thread::spawn(|| {
            let _guard = program_cache();
            panic!("poison cache");
        })
        .join();
        compiled_source_program(&tiny_source("poison")).expect("poison recovery");
    }

    #[test]
    fn compile_cache_bounds_entries_and_weight() {
        let program = compiled_source_program(&tiny_source("seed"))
            .expect("compile")
            .0;
        let mut cache = ProgramLru::new();
        for i in 0..COMPILE_CACHE_CAP {
            cache.insert(format!("d{i}"), program.clone(), MAX_AGENT_SOURCE_BYTES);
        }
        assert_eq!(cache.entries.len(), COMPILE_CACHE_CAP);
        assert_eq!(cache.total_weight, COMPILE_CACHE_WEIGHT_CAP);
        cache.insert(
            "overflow".to_string(),
            program.clone(),
            MAX_AGENT_SOURCE_BYTES,
        );
        assert_eq!(cache.entries.len(), COMPILE_CACHE_CAP);
        assert!(!cache.entries.contains_key("d0"));
        assert!(cache.entries.contains_key("overflow"));
        cache.insert(
            "too-heavy".to_string(),
            program,
            COMPILE_CACHE_WEIGHT_CAP + 1,
        );
        assert!(!cache.entries.contains_key("too-heavy"));
    }

    #[test]
    fn compile_cache_concurrent_same_digest_is_safe() {
        let source = tiny_source("concurrent");
        let source = Arc::new(source);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let source = Arc::clone(&source);
            handles.push(thread::spawn(move || compiled_source_program(&source)));
        }
        let mut digests = Vec::new();
        for handle in handles {
            let (_, digest) = handle.join().expect("thread").expect("compile");
            digests.push(digest);
        }
        assert!(digests.iter().all(|digest| digest == &digests[0]));
        {
            let cache = program_cache();
            assert!(cache.entries.contains_key(&digests[0]));
        }
    }
}
