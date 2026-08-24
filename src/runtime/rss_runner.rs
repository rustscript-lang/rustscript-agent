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

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::Path;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use rustscript_vm::{
    CallReturn, CancellationReason, EpochHandle, HostAsyncBridge, HostFunctionRegistry, HostFuture,
    HostFutureOutput, HttpConfig, HttpHostExt, InvocationError, InvocationItem, InvocationPoll,
    SqliteHostExt, SqlitePolicy, Value, Vm, VmError, VmResult, VmStatus, VmYieldReason,
    compile_source, register_http_builtin_module, register_sqlite_builtin_module,
};

pub const MAX_AGENT_SOURCE_BYTES: usize = 1024 * 1024;

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

#[derive(Clone, Debug)]
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
}

impl RunCancellation {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RunCancellationInner {
                requested: Arc::new(Mutex::new(None)),
                deadline: Arc::new(Mutex::new(None)),
                epoch: Arc::new(Mutex::new(None)),
                watcher: Arc::new(Mutex::new(None)),
                stop: Arc::new(AtomicBool::new(false)),
            }),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        let cancellation = Self::new();
        *cancellation.inner.deadline.lock().expect("deadline lock") =
            Some(Instant::now() + timeout);
        cancellation
    }

    pub fn request(&self, reason: CancellationReason) {
        let mut requested = self.inner.requested.lock().expect("requested lock");
        if requested.is_none() {
            *requested = Some(reason);
        }
    }

    pub fn requested(&self) -> Option<CancellationReason> {
        *self.inner.requested.lock().expect("requested lock")
    }

    pub(crate) fn deadline_passed(&self) -> bool {
        self.inner
            .deadline
            .lock()
            .expect("deadline lock")
            .is_some_and(|deadline| Instant::now() >= deadline)
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
        let watcher = thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let fire = requested.lock().expect("requested lock").is_some()
                    || deadline
                        .lock()
                        .expect("deadline lock")
                        .is_some_and(|deadline| Instant::now() >= deadline);
                if fire {
                    epoch.increment_by(RUN_EPOCH_DEADLINE_TICKS);
                    return;
                }
                thread::sleep(Duration::from_millis(1));
            }
        });
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
}

impl AgentRunner {
    pub fn from_source(source: &str, config: AgentConfig) -> Result<Self> {
        if source.len() > MAX_AGENT_SOURCE_BYTES {
            return Err(AgentError::Compile(format!(
                "agent source exceeds {} bytes",
                MAX_AGENT_SOURCE_BYTES
            )));
        }
        let program = compile_source(source)
            .map_err(|error| AgentError::Compile(error.to_string()))?
            .program;
        let registry = build_restricted_registry()
            .map_err(|error| AgentError::Compile(format!("host registry: {error}")))?;
        Ok(Self {
            program,
            config,
            registry: Arc::new(registry),
        })
    }

    pub fn from_file(path: impl AsRef<Path>, config: AgentConfig) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let source_bytes = std::fs::metadata(&path)?.len() as usize;
        if source_bytes > MAX_AGENT_SOURCE_BYTES {
            return Err(AgentError::Compile(format!(
                "agent source exceeds {} bytes",
                MAX_AGENT_SOURCE_BYTES
            )));
        }
        let program = rustscript_vm::compile_source_file(&path)
            .map_err(|error| AgentError::Compile(error.to_string()))?
            .program;
        let registry = build_restricted_registry()
            .map_err(|error| AgentError::Compile(format!("host registry: {error}")))?;
        Ok(Self {
            program,
            config,
            registry: Arc::new(registry),
        })
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
        let (mut vm, callable) = self.prepare_vm(Some(cancellation))?;
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
        if let Some(cancellation) = cancellation {
            vm.set_epoch_check_interval(RUN_EPOCH_CHECK_INTERVAL)
                .map_err(RunError::Setup)?;
            vm.set_epoch_deadline(RUN_EPOCH_DEADLINE_TICKS)
                .map_err(RunError::Setup)?;
            cancellation.arm(vm.epoch_handle());
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
                        // The VM is paused on an outstanding host operation.
                        // Polling drives the operation; the cancellation
                        // checks above cancel it with the typed reason.
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
/// invocation stream emit builtin, generic SQLite, and the HTTP client
/// (buffered request plus the callable SSE stream, consumed by the
/// `openai_chat` streaming adapter since core revision fd4b570; see
/// plans/2026-08-14_a3-rustscript-core-unblock.md). Ambient runtime
/// input/emit builtins are intentionally absent from agent execution.
fn build_restricted_registry() -> std::result::Result<HostFunctionRegistry, VmError> {
    let mut registry = HostFunctionRegistry::restricted();
    register_sqlite_builtin_module(&mut registry)?;
    register_http_builtin_module(&mut registry)?;
    for name in [
        "json::encode",
        "json::decode",
        "stream::emit",
        "bytes::to_utf8",
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
