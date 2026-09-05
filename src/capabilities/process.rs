//! Run-scoped bounded process primitives.
//!
//! Handles are opaque and isolated by owner/run/generation. Capability code
//! does not embed terminal or process public-tool dispatch policy.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use rustscript_vm::{
    BoundedProcess, BoundedProcessError, BoundedProcessHandle, BoundedProcessRequest,
    CancellationToken as ProcessCancel, ConfinedFsLimits, ConfinedFsRoot, LogSnapshot,
    MAX_COMPONENT_BYTES, MAX_ENUM_ENTRIES, MAX_READ_BYTES, MAX_WRITE_BYTES, ProcessStatus,
};

use super::{
    lifecycle::{CapabilityLifecycle, TokenOwnedResource},
    types::{CapabilityError, CapabilityOwner, CapabilityRisk, TokenClaims},
};

const ALLOWED_ENV: &[&str] = &["PATH", "HOME", "LANG", "TZ", "USER", "TERM"];
const WAIT_POLL_SLICE: Duration = Duration::from_millis(5);
const WRITE_POLL_SLICE: Duration = Duration::from_millis(5);
const WRITE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

type ProcessOpHook = Arc<dyn Fn() + Send + Sync>;

/// Per-spawn resource ceilings. Host values are admitted ceilings; caller
/// arguments may only reduce them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLimits {
    pub timeout_ms: u64,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
    pub total_limit: usize,
    pub stdin_limit: usize,
    pub log_limit: usize,
    /// Foreground spawns wait for the initial stdin payload, then close.
    /// Background spawns keep native `with_stdin` semantics (stdin stays open).
    pub close_after_initial: bool,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            stdout_limit: 64 * 1024,
            stderr_limit: 64 * 1024,
            total_limit: 64 * 1024,
            stdin_limit: 64 * 1024,
            log_limit: 64 * 1024,
            close_after_initial: false,
        }
    }
}

/// Opaque handle returned by spawn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessSpawn {
    pub handle: String,
    pub pid: u32,
}

/// Cursor metadata for one captured stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessLogCursor {
    pub offset: u64,
    pub next_offset: u64,
    pub truncated: bool,
    pub gap: bool,
    pub eof: bool,
}

/// Bounded process snapshot used by poll/wait/log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessSnapshot {
    pub handle: String,
    pub running: bool,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_bytes: Vec<u8>,
    pub stderr_bytes: Vec<u8>,
    pub truncated: bool,
    pub stdout_cursor: ProcessLogCursor,
    pub stderr_cursor: ProcessLogCursor,
    pub signaled: bool,
    pub unknown: bool,
    pub deadline_elapsed: bool,
    pub cancelled: bool,
}

struct OwnedProcess {
    owner_key: String,
    generation: u64,
    handle: BoundedProcessHandle,
    cancel: ProcessCancel,
}

struct ProcessReaper {
    inner: Weak<ProcessInner>,
    id: String,
    handle: BoundedProcessHandle,
    cancel: ProcessCancel,
    released: AtomicBool,
}

impl ProcessReaper {
    fn shutdown_and_forget(&self) {
        if self.released.swap(true, Ordering::SeqCst) {
            return;
        }
        self.cancel.cancel();
        if let Some(inner) = self.inner.upgrade() {
            let _ = inner
                .table
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&self.id);
        }
        let _ = self.handle.shutdown();
    }
}

impl TokenOwnedResource for ProcessReaper {
    fn release(&self) {
        self.shutdown_and_forget();
    }

    fn rollback_unpublished_side_effects(&self) {
        self.shutdown_and_forget();
    }
}

struct ProcessInner {
    lifecycle: CapabilityLifecycle,
    owner: CapabilityOwner,
    host_limits: ProcessLimits,
    root: ConfinedFsRoot,
    table: Mutex<HashMap<String, OwnedProcess>>,
    closing: AtomicBool,
    generation: AtomicU64,
    after_running_poll_hook: Mutex<Option<ProcessOpHook>>,
    write_blocked_hook: Mutex<Option<ProcessOpHook>>,
    before_write_cycle_hook: Mutex<Option<ProcessOpHook>>,
    before_os_spawn_hook: Mutex<Option<ProcessOpHook>>,
    after_os_spawn_hook: Mutex<Option<ProcessOpHook>>,
    stdin_workers: AtomicUsize,
}

impl Drop for ProcessInner {
    fn drop(&mut self) {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for owned in table.values() {
            terminate_owned(owned);
        }
        table.clear();
    }
}

/// Bounded process table bound to one lifecycle owner.
#[derive(Clone)]
pub struct ProcessCapability {
    inner: Arc<ProcessInner>,
}

impl ProcessCapability {
    /// Constructs an empty run-scoped process table with admitted host ceilings.
    pub fn new(
        lifecycle: CapabilityLifecycle,
        owner: CapabilityOwner,
        host_limits: ProcessLimits,
    ) -> Result<Self, CapabilityError> {
        if host_limits.timeout_ms == 0
            || host_limits.stdout_limit == 0
            || host_limits.stderr_limit == 0
            || host_limits.total_limit == 0
            || host_limits.stdin_limit == 0
            || host_limits.log_limit == 0
        {
            return Err(CapabilityError::new(
                "invalid_configuration",
                "process limits must be positive",
            ));
        }
        let root = ConfinedFsRoot::with_limits(
            lifecycle.workspace(),
            ConfinedFsLimits {
                max_read_bytes: MAX_READ_BYTES,
                max_write_bytes: MAX_WRITE_BYTES,
                max_entries: MAX_ENUM_ENTRIES,
                max_entry_name_bytes: MAX_COMPONENT_BYTES,
                max_temp_attempts: 32,
            },
        )
        .map_err(|error| CapabilityError::new("path_denied", error.to_string()))?;
        Ok(Self {
            inner: Arc::new(ProcessInner {
                lifecycle,
                owner,
                host_limits,
                root,
                table: Mutex::new(HashMap::new()),
                closing: AtomicBool::new(false),
                generation: AtomicU64::new(1),
                after_running_poll_hook: Mutex::new(None),
                write_blocked_hook: Mutex::new(None),
                before_write_cycle_hook: Mutex::new(None),
                before_os_spawn_hook: Mutex::new(None),
                after_os_spawn_hook: Mutex::new(None),
                stdin_workers: AtomicUsize::new(0),
            }),
        })
    }

    /// Spawns argv with a confined workspace cwd.
    pub fn spawn(
        &self,
        token: &str,
        argv: &[String],
        cwd: &str,
        env_names: &[String],
        limits: ProcessLimits,
    ) -> Result<ProcessSpawn, CapabilityError> {
        self.spawn_with(token, argv, cwd, env_names, limits, None)
    }

    /// Spawns argv with optional stdin bytes attached at start.
    pub fn spawn_with(
        &self,
        token: &str,
        argv: &[String],
        cwd: &str,
        env_names: &[String],
        limits: ProcessLimits,
        stdin: Option<&[u8]>,
    ) -> Result<ProcessSpawn, CapabilityError> {
        let claims = self.authorize(token, CapabilityRisk::Execute)?;
        if self.is_closing() {
            return Err(closing_error());
        }
        if argv.is_empty() {
            return Err(CapabilityError::new(
                "invalid_request",
                "argv must not be empty",
            ));
        }
        let limits = self.clamp_limits(limits, &claims);
        if stdin.is_some_and(|stdin| stdin.len() > limits.stdin_limit) {
            return Err(CapabilityError::new(
                "budget_exceeded",
                "stdin exceeds the configured bound",
            ));
        }
        let directory = self
            .inner
            .root
            .open_directory(cwd)
            .map_err(|error| CapabilityError::new("path_denied", error.to_string()))?;
        let cancel = ProcessCancel::new();
        let mut request = BoundedProcessRequest::new(argv.to_vec())
            .with_confined_cwd(directory)
            .with_deadline(claims.deadline)
            .with_timeout(Duration::from_millis(limits.timeout_ms.max(1)))
            .with_output_limits(limits.stdout_limit, limits.stderr_limit, limits.total_limit)
            .with_cancellation_token(cancel.clone());
        for name in env_names {
            if !ALLOWED_ENV.contains(&name.as_str()) {
                return Err(CapabilityError::new(
                    "invalid_request",
                    "environment name is not allowlisted",
                ));
            }
            if let Ok(value) = std::env::var(name) {
                request = request.with_env(name.clone(), value);
            }
        }
        if !limits.close_after_initial
            && let Some(stdin) = stdin
            && !stdin.is_empty()
        {
            request = request.with_stdin(stdin.to_vec());
        }
        if self.is_closing() {
            return Err(closing_error());
        }
        fire_hook(&self.inner.before_os_spawn_hook);
        if self.is_closing() {
            return Err(closing_error());
        }
        let fence = self.inner.generation.load(Ordering::SeqCst);
        let process = BoundedProcess::spawn(request).map_err(map_process_error)?;
        fire_hook(&self.inner.after_os_spawn_hook);
        let handle = process.lifecycle_handle();
        let write_handle = handle.clone();
        let pid = handle.pid();
        let id = uuid::Uuid::new_v4().simple().to_string();
        {
            let mut table = self
                .inner
                .table
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.is_closing() || self.inner.generation.load(Ordering::SeqCst) != fence {
                drop(table);
                let _ = handle.shutdown();
                return Err(closing_error());
            }
            table.insert(
                id.clone(),
                OwnedProcess {
                    owner_key: claims.owner.key(),
                    generation: claims.generation,
                    handle: handle.clone(),
                    cancel: cancel.clone(),
                },
            );
        }
        let reaper = Arc::new(ProcessReaper {
            inner: Arc::downgrade(&self.inner),
            id: id.clone(),
            handle,
            cancel,
            released: AtomicBool::new(false),
        });
        if let Err(error) = self.inner.lifecycle.register_resource(token, reaper) {
            self.remove_and_terminate(&id);
            return Err(CapabilityError::from(error));
        }
        if limits.close_after_initial {
            if let Some(bytes) = stdin.filter(|bytes| !bytes.is_empty()) {
                let mut deadline = claims.deadline;
                if let Some(bound) =
                    Instant::now().checked_add(Duration::from_millis(limits.timeout_ms))
                    && bound < deadline
                {
                    deadline = bound;
                }
                match self.write_stdin_until(token, &write_handle, bytes, deadline) {
                    Ok(_) => {}
                    Err(error)
                        if error.code() == "stdin_closed" || error.code() == "process_failed" => {}
                    Err(error) => {
                        self.remove_and_terminate(&id);
                        return Err(error);
                    }
                }
            }
            match write_handle.close_stdin() {
                Ok(())
                | Err(BoundedProcessError::StdinClosed)
                | Err(BoundedProcessError::StdinWriteFailed { .. }) => {}
                Err(error) => {
                    self.remove_and_terminate(&id);
                    return Err(map_process_error(error));
                }
            }
        }
        Ok(ProcessSpawn { handle: id, pid })
    }

    /// Non-blocking status and bounded logs.
    pub fn poll(
        &self,
        token: &str,
        handle: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<ProcessSnapshot, CapabilityError> {
        if limit == 0 {
            return Err(CapabilityError::new(
                "invalid_request",
                "limit must be positive",
            ));
        }
        let _ = cursor;
        let owned = self.lookup(token, handle)?;
        let poll_result = owned.handle.poll();
        let mut snap = snapshot(&owned.handle, handle, None, None);
        match poll_result {
            Ok(_) => {}
            Err(BoundedProcessError::DeadlineElapsed) => {
                snap.deadline_elapsed = true;
            }
            Err(BoundedProcessError::Cancelled) => {
                snap.cancelled = true;
            }
            Err(error) => return Err(map_process_error(error)),
        }
        if snap.running {
            fire_hook(&self.inner.after_running_poll_hook);
        }
        Ok(snap)
    }

    /// Waits until exit, caller timeout, deadline, or cancellation.
    ///
    /// A wait-own timeout sets `deadline_elapsed` and preserves a running
    /// snapshot. It does not kill the child. Process-deadline and cancel stay
    /// distinct: process deadline also sets the flag after the child is reaped;
    /// cancel still surfaces as an error.
    pub fn wait(
        &self,
        token: &str,
        handle: &str,
        timeout_ms: Option<u64>,
    ) -> Result<ProcessSnapshot, CapabilityError> {
        let timeout_ms = timeout_ms.map(|ms| ms.min(self.inner.host_limits.timeout_ms));
        let wait_deadline = timeout_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        loop {
            let owned = self.lookup(token, handle)?;
            match owned.handle.poll() {
                Ok(_) => {
                    let mut snap = snapshot(&owned.handle, handle, None, None);
                    if !snap.running {
                        return Ok(snap);
                    }
                    if wait_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        snap.deadline_elapsed = true;
                        return Ok(snap);
                    }
                    thread::sleep(WAIT_POLL_SLICE);
                }
                Err(BoundedProcessError::DeadlineElapsed) => {
                    let mut snap = snapshot(&owned.handle, handle, None, None);
                    snap.deadline_elapsed = true;
                    return Ok(snap);
                }
                Err(error) => return Err(map_process_error(error)),
            }
        }
    }

    /// Count currently tracked handles. Used by lifecycle tests.
    pub fn table_len(&self) -> usize {
        self.inner
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Test-only count of stdin write workers spawned but not joined.
    pub fn active_stdin_workers(&self) -> usize {
        self.inner.stdin_workers.load(Ordering::SeqCst)
    }

    /// PIDs currently recorded in the process table. Used by lifecycle tests.
    pub fn live_pids(&self) -> Vec<u32> {
        self.inner
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|owned| owned.handle.pid())
            .collect()
    }

    /// Test barrier: fires once after a successful poll of a still-running child.
    pub fn set_after_running_poll_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self
            .inner
            .after_running_poll_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }

    /// Test barrier: fires once after a timed write observes a full pipe / EAGAIN.
    pub fn set_write_blocked_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self
            .inner
            .write_blocked_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }

    /// Test barrier: fires once at the start of the timed-write observation loop.
    pub fn set_before_write_cycle_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self
            .inner
            .before_write_cycle_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }

    /// Test barrier: fires immediately before the OS spawn syscall.
    pub fn set_before_os_spawn_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self
            .inner
            .before_os_spawn_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }

    /// Test barrier: fires after OS spawn and before table insert.
    pub fn set_after_os_spawn_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self
            .inner
            .after_os_spawn_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }

    /// Returns a bounded log window.
    pub fn log(
        &self,
        token: &str,
        handle: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<ProcessSnapshot, CapabilityError> {
        if limit == 0 {
            return Err(CapabilityError::new(
                "invalid_request",
                "limit must be positive",
            ));
        }
        let owned = self.lookup(token, handle)?;
        Ok(snapshot(&owned.handle, handle, Some(cursor), Some(limit)))
    }

    /// Writes bytes to child stdin, honoring caller timeout, cancel, and deadline.
    pub fn write_stdin(
        &self,
        token: &str,
        handle: &str,
        bytes: &[u8],
        timeout_ms: Option<u64>,
    ) -> Result<usize, CapabilityError> {
        let owned = self.lookup(token, handle)?;
        if bytes.len() > self.inner.host_limits.stdin_limit {
            return Err(CapabilityError::new(
                "budget_exceeded",
                "stdin write exceeds the configured bound",
            ));
        }
        let mut deadline = owned.handle.deadline();
        if let Some(ms) = timeout_ms {
            match Instant::now().checked_add(Duration::from_millis(ms)) {
                Some(bound) if bound < deadline => deadline = bound,
                None => deadline = Instant::now(),
                Some(_) => {}
            }
        }
        self.write_stdin_until(token, &owned.handle, bytes, deadline)
    }

    /// Closes child stdin.
    pub fn close_stdin(&self, token: &str, handle: &str) -> Result<(), CapabilityError> {
        let owned = self.lookup(token, handle)?;
        match owned.handle.close_stdin() {
            Ok(())
            | Err(BoundedProcessError::StdinClosed)
            | Err(BoundedProcessError::StdinWriteFailed { .. }) => Ok(()),
            Err(error) => Err(map_process_error(error)),
        }
    }

    /// Kills the process tree bound to `handle`.
    pub fn kill(&self, token: &str, handle: &str) -> Result<(), CapabilityError> {
        let owned = self.lookup(token, handle)?;
        terminate_owned(&owned);
        Ok(())
    }

    /// Cancels every owned child with the same process-tree path as [`Self::kill`].
    pub fn cancel_all(&self) {
        let owned: Vec<OwnedProcess> = self
            .inner
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|owned| OwnedProcess {
                owner_key: owned.owner_key.clone(),
                generation: owned.generation,
                handle: owned.handle.clone(),
                cancel: owned.cancel.clone(),
            })
            .collect();
        for process in owned {
            terminate_owned(&process);
        }
    }

    /// Terminates every owned child and drops table entries.
    ///
    /// Closing is irreversible: later spawns refuse insert and terminate any
    /// OS process created after the fence. Run cleanup must drain committed
    /// background residue; `cancel_all` kills the process tree but leaves
    /// handles observable in the table.
    pub fn shutdown_all(&self) {
        self.inner.closing.store(true, Ordering::SeqCst);
        self.inner.generation.fetch_add(1, Ordering::SeqCst);
        let owned: Vec<OwnedProcess> = {
            let mut table = self
                .inner
                .table
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            table.drain().map(|(_, process)| process).collect()
        };
        for process in owned {
            terminate_owned(&process);
        }
    }

    /// True after [`Self::shutdown_all`] has started. The fence is irreversible.
    pub fn is_closing(&self) -> bool {
        self.inner.closing.load(Ordering::SeqCst)
    }

    fn authorize(&self, token: &str, risk: CapabilityRisk) -> Result<TokenClaims, CapabilityError> {
        match self
            .inner
            .lifecycle
            .authorize(&self.inner.owner, token, risk)
        {
            Ok(claims) => Ok(claims),
            Err(error) => Err(CapabilityError::from(error)),
        }
    }

    fn lookup(&self, token: &str, handle: &str) -> Result<OwnedProcess, CapabilityError> {
        if self.is_closing() {
            return Err(closing_error());
        }
        let claims = self.authorize(token, CapabilityRisk::Execute)?;
        let table = self
            .inner
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let owned = table.get(handle).ok_or_else(|| {
            CapabilityError::new("process_not_found", "process handle is unknown")
        })?;
        if owned.owner_key != claims.owner.key() || owned.generation != claims.generation {
            return Err(CapabilityError::new(
                "process_not_found",
                "process handle is unknown",
            ));
        }
        Ok(OwnedProcess {
            owner_key: owned.owner_key.clone(),
            generation: owned.generation,
            handle: owned.handle.clone(),
            cancel: owned.cancel.clone(),
        })
    }

    fn remove_and_terminate(&self, handle: &str) {
        if let Some(owned) = self
            .inner
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(handle)
        {
            terminate_owned(&owned);
        }
    }

    fn write_stdin_until(
        &self,
        token: &str,
        handle: &BoundedProcessHandle,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<usize, CapabilityError> {
        if bytes.is_empty() {
            self.authorize(token, CapabilityRisk::Execute)?;
            return Ok(0);
        }
        let (tx, rx) = mpsc::sync_channel(1);
        let writer = handle.clone();
        let payload = bytes.to_vec();
        let worker = thread::Builder::new()
            .name("process-cap-write".to_string())
            .spawn(move || {
                let _ = tx.send(writer.write_stdin(&payload));
            })
            .map_err(|_| {
                CapabilityError::new("process_failed", "stdin write worker failed to start")
            })?;
        self.inner.stdin_workers.fetch_add(1, Ordering::SeqCst);
        let workers = &self.inner.stdin_workers;
        loop {
            fire_hook(&self.inner.before_write_cycle_hook);
            if let Err(error) = self.authorize(token, CapabilityRisk::Execute) {
                return interrupt_write_worker(handle, worker, &rx, error, workers);
            }
            let now = Instant::now();
            if now >= deadline {
                return interrupt_write_worker(
                    handle,
                    worker,
                    &rx,
                    CapabilityError::new("deadline_elapsed", "process deadline elapsed"),
                    workers,
                );
            }
            let slice = WRITE_POLL_SLICE.min(deadline.saturating_duration_since(now));
            match rx.recv_timeout(slice) {
                Ok(Ok(wrote)) => {
                    join_write_worker(worker, workers);
                    return Ok(wrote);
                }
                Ok(Err(error)) => {
                    join_write_worker(worker, workers);
                    return Err(map_process_error(error));
                }
                Err(RecvTimeoutError::Timeout) => {
                    fire_hook(&self.inner.write_blocked_hook);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    join_write_worker(worker, workers);
                    return Err(CapabilityError::new(
                        "process_failed",
                        "stdin write worker ended",
                    ));
                }
            }
        }
    }

    fn clamp_limits(&self, caller: ProcessLimits, claims: &TokenClaims) -> ProcessLimits {
        let host = self.inner.host_limits;
        let remaining_ms = u64::try_from(
            claims
                .deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        let timeout_ms = caller
            .timeout_ms
            .min(host.timeout_ms)
            .min(remaining_ms)
            .max(1);
        ProcessLimits {
            timeout_ms,
            stdout_limit: caller.stdout_limit.min(host.stdout_limit).max(1),
            stderr_limit: caller.stderr_limit.min(host.stderr_limit).max(1),
            total_limit: caller.total_limit.min(host.total_limit).max(1),
            stdin_limit: caller.stdin_limit.min(host.stdin_limit).max(1),
            log_limit: caller.log_limit.min(host.log_limit).max(1),
            close_after_initial: caller.close_after_initial,
        }
    }
}

fn fire_hook(slot: &Mutex<Option<ProcessOpHook>>) {
    if let Some(hook) = slot
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
    {
        hook();
    }
}

fn closing_error() -> CapabilityError {
    CapabilityError::new("capability_unavailable", "process capability is closing")
}

fn interrupt_write_worker(
    handle: &BoundedProcessHandle,
    worker: thread::JoinHandle<()>,
    rx: &mpsc::Receiver<Result<usize, BoundedProcessError>>,
    interrupt: CapabilityError,
    workers: &AtomicUsize,
) -> Result<usize, CapabilityError> {
    let _ = handle.close_stdin();
    let outcome = match rx.recv_timeout(WRITE_CLEANUP_TIMEOUT) {
        Ok(Ok(wrote)) => Ok(wrote),
        Ok(Err(_)) | Err(_) => Err(interrupt),
    };
    join_write_worker(worker, workers);
    outcome
}

fn join_write_worker(worker: thread::JoinHandle<()>, workers: &AtomicUsize) {
    let _ = worker.join();
    workers.fetch_sub(1, Ordering::SeqCst);
}

fn terminate_owned(owned: &OwnedProcess) {
    owned.cancel.cancel();
    let _ = owned.handle.shutdown();
}

fn snapshot(
    handle: &BoundedProcessHandle,
    id: &str,
    offset: Option<u64>,
    limit: Option<usize>,
) -> ProcessSnapshot {
    let mut stdout = match offset {
        Some(offset) => handle.stdout_snapshot_from(offset),
        None => handle.stdout_snapshot(),
    };
    let mut stderr = match offset {
        Some(offset) => handle.stderr_snapshot_from(offset),
        None => handle.stderr_snapshot(),
    };
    if let Some(limit) = limit {
        stdout = truncate_log_snapshot(stdout, limit);
        stderr = truncate_log_snapshot(stderr, limit);
    }
    let status = handle.terminal_status();
    let running = status.is_none();
    let signaled = matches!(status, Some(ProcessStatus::Signaled { .. }));
    let unknown = matches!(status, Some(ProcessStatus::Unknown));
    ProcessSnapshot {
        handle: id.to_string(),
        running,
        exit_code: status.and_then(ProcessStatus::exit_code),
        signal: status.and_then(ProcessStatus::signal),
        stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr.bytes).into_owned(),
        stdout_bytes: stdout.bytes.clone(),
        stderr_bytes: stderr.bytes.clone(),
        truncated: stdout.truncated || stderr.truncated,
        stdout_cursor: ProcessLogCursor {
            offset: stdout.offset,
            next_offset: stdout.next_offset,
            truncated: stdout.truncated,
            gap: stdout.gap,
            eof: stdout.eof,
        },
        stderr_cursor: ProcessLogCursor {
            offset: stderr.offset,
            next_offset: stderr.next_offset,
            truncated: stderr.truncated,
            gap: stderr.gap,
            eof: stderr.eof,
        },
        signaled,
        unknown,
        deadline_elapsed: false,
        cancelled: false,
    }
}

fn truncate_log_snapshot(snapshot: LogSnapshot, limit: usize) -> LogSnapshot {
    if snapshot.bytes.len() <= limit {
        return snapshot;
    }
    let mut bytes = snapshot.bytes;
    bytes.truncate(limit);
    LogSnapshot {
        bytes,
        offset: snapshot.offset,
        next_offset: snapshot.offset.saturating_add(limit as u64),
        truncated: true,
        gap: snapshot.gap,
        eof: false,
    }
}

fn map_process_error(error: BoundedProcessError) -> CapabilityError {
    let code = match error {
        BoundedProcessError::DeadlineElapsed => "deadline_elapsed",
        BoundedProcessError::Cancelled => "cancelled",
        BoundedProcessError::InvalidRequest(_) => "invalid_request",
        BoundedProcessError::StdinClosed => "stdin_closed",
        BoundedProcessError::StdinTooLarge => "budget_exceeded",
        _ => "process_failed",
    };
    CapabilityError::new(code, error.to_string())
}
