//! Run-scoped bounded process primitives.
//!
//! Handles are opaque and isolated by owner/run/generation. Capability code
//! does not embed terminal or process public-tool dispatch policy.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use rustscript_vm::{
    BoundedProcess, BoundedProcessError, BoundedProcessHandle, BoundedProcessRequest,
    CancellationToken as ProcessCancel, ConfinedFsLimits, ConfinedFsRoot, LogSnapshot,
    MAX_COMPONENT_BYTES, MAX_ENUM_ENTRIES, MAX_READ_BYTES, MAX_WRITE_BYTES, ProcessStatus,
};

use super::{
    lifecycle::{CapabilityLifecycle, TokenOwnedResource},
    types::{CapabilityError, CapabilityOwner, CapabilityRisk, LifecycleError, TokenClaims},
};

const ALLOWED_ENV: &[&str] = &["PATH", "HOME", "LANG", "TZ", "USER", "TERM"];

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
    handle: BoundedProcessHandle,
    cancel: ProcessCancel,
    released: AtomicBool,
}

impl TokenOwnedResource for ProcessReaper {
    fn release(&self) {
        if self.released.swap(true, Ordering::SeqCst) {
            return;
        }
        self.cancel.cancel();
        let _ = self.handle.shutdown();
    }
}

struct ProcessInner {
    lifecycle: CapabilityLifecycle,
    owner: CapabilityOwner,
    host_limits: ProcessLimits,
    root: ConfinedFsRoot,
    table: Mutex<HashMap<String, OwnedProcess>>,
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
        let process = BoundedProcess::spawn(request).map_err(map_process_error)?;
        let handle = process.lifecycle_handle();
        let pid = handle.pid();
        let id = uuid::Uuid::new_v4().simple().to_string();
        self.inner
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                id.clone(),
                OwnedProcess {
                    owner_key: claims.owner.key(),
                    generation: claims.generation,
                    handle: handle.clone(),
                    cancel: cancel.clone(),
                },
            );
        let reaper = Arc::new(ProcessReaper {
            handle,
            cancel,
            released: AtomicBool::new(false),
        });
        if let Err(error) = self.inner.lifecycle.register_resource(token, reaper) {
            self.remove_and_terminate(&id);
            return Err(CapabilityError::from(error));
        }
        match stdin {
            Some(stdin) if !stdin.is_empty() => {
                if let Err(error) = self.write_stdin(token, &id, stdin, Some(limits.timeout_ms)) {
                    let still_running = self
                        .lookup(token, &id)
                        .ok()
                        .map(|owned| owned.handle.terminal_status().is_none())
                        .unwrap_or(false);
                    if still_running || error.code() != "stdin_closed" {
                        self.remove_and_terminate(&id);
                        return Err(error);
                    }
                }
            }
            _ => {}
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
            Ok(_) => Ok(snap),
            Err(BoundedProcessError::DeadlineElapsed) => {
                snap.deadline_elapsed = true;
                Ok(snap)
            }
            Err(BoundedProcessError::Cancelled) => {
                snap.cancelled = true;
                Ok(snap)
            }
            Err(error) => Err(map_process_error(error)),
        }
    }

    /// Waits until exit, caller timeout, deadline, or cancellation.
    pub fn wait(
        &self,
        token: &str,
        handle: &str,
        timeout_ms: Option<u64>,
    ) -> Result<ProcessSnapshot, CapabilityError> {
        let owned = self.lookup(token, handle)?;
        let timeout_ms = timeout_ms.map(|ms| ms.min(self.inner.host_limits.timeout_ms));
        let deadline = timeout_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        match owned.handle.wait(deadline) {
            Ok(_) | Err(BoundedProcessError::DeadlineElapsed) => {}
            Err(error) => return Err(map_process_error(error)),
        }
        Ok(snapshot(&owned.handle, handle, None, None))
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
            Ok(()) | Err(BoundedProcessError::StdinClosed) => Ok(()),
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

    fn authorize(&self, token: &str, risk: CapabilityRisk) -> Result<TokenClaims, CapabilityError> {
        match self
            .inner
            .lifecycle
            .authorize(&self.inner.owner, token, risk)
        {
            Ok(claims) => Ok(claims),
            Err(error) => {
                if matches!(
                    error,
                    LifecycleError::Cancelled
                        | LifecycleError::DeadlineElapsed
                        | LifecycleError::Interrupted
                ) {
                    self.cancel_all();
                }
                Err(CapabilityError::from(error))
            }
        }
    }

    fn lookup(&self, token: &str, handle: &str) -> Result<OwnedProcess, CapabilityError> {
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
        const WRITE_POLL_SLICE: Duration = Duration::from_millis(5);
        const WRITE_JOIN_GRACE: Duration = Duration::from_millis(200);
        if bytes.is_empty() {
            self.authorize(token, CapabilityRisk::Execute)?;
            return Ok(0);
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let _ = tx.send(handle.write_stdin(bytes));
            });
            loop {
                if let Err(error) = self.authorize(token, CapabilityRisk::Execute) {
                    let _ = handle.close_stdin();
                    let _ = rx.recv_timeout(WRITE_JOIN_GRACE);
                    return Err(error);
                }
                let now = Instant::now();
                if now >= deadline {
                    let _ = handle.close_stdin();
                    return match rx.recv_timeout(WRITE_JOIN_GRACE) {
                        Ok(Ok(wrote)) => Ok(wrote),
                        Ok(Err(_)) | Err(_) => Err(CapabilityError::new(
                            "deadline_elapsed",
                            "process deadline elapsed",
                        )),
                    };
                }
                let slice = WRITE_POLL_SLICE.min(deadline.saturating_duration_since(now));
                match rx.recv_timeout(slice) {
                    Ok(Ok(wrote)) => return Ok(wrote),
                    Ok(Err(error)) => return Err(map_process_error(error)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(CapabilityError::new(
                            "process_failed",
                            "stdin write worker ended",
                        ));
                    }
                }
            }
        })
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
        }
    }
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
