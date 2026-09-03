//! Run-scoped bounded process primitives.
//!
//! Handles are opaque and isolated by owner/run/generation. Capability code
//! does not embed terminal or process public-tool dispatch policy.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustscript_vm::{
    BoundedProcess, BoundedProcessError, BoundedProcessHandle, BoundedProcessRequest,
    CancellationToken as ProcessCancel, ConfinedFsLimits, ConfinedFsRoot, MAX_COMPONENT_BYTES,
    MAX_ENUM_ENTRIES, MAX_READ_BYTES, MAX_WRITE_BYTES, ProcessStatus,
};

use super::lifecycle::CapabilityLifecycle;
use super::types::{CapabilityError, CapabilityOwner, CapabilityRisk, LifecycleError, TokenClaims};

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

/// Bounded process snapshot used by poll/wait/log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessSnapshot {
    pub handle: String,
    pub running: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

struct OwnedProcess {
    owner_key: String,
    generation: u64,
    handle: BoundedProcessHandle,
    cancel: ProcessCancel,
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
        let claims = self.authorize(token, CapabilityRisk::Execute)?;
        if argv.is_empty() {
            return Err(CapabilityError::new(
                "invalid_request",
                "argv must not be empty",
            ));
        }
        let limits = self.clamp_limits(limits, &claims);
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
        let id = uuid::Uuid::new_v4().to_string();
        self.inner
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                id.clone(),
                OwnedProcess {
                    owner_key: claims.owner.key(),
                    generation: claims.generation,
                    handle,
                    cancel,
                },
            );
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
        let owned = self.lookup(token, handle)?;
        let _ = owned.handle.poll().map_err(map_process_error)?;
        Ok(snapshot(
            &owned.handle,
            handle,
            cursor,
            limit.min(self.inner.host_limits.log_limit),
        ))
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
        Ok(snapshot(
            &owned.handle,
            handle,
            0,
            self.inner.host_limits.log_limit,
        ))
    }

    /// Returns a bounded log window.
    pub fn log(
        &self,
        token: &str,
        handle: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<ProcessSnapshot, CapabilityError> {
        let owned = self.lookup(token, handle)?;
        Ok(snapshot(
            &owned.handle,
            handle,
            cursor,
            limit.min(self.inner.host_limits.log_limit),
        ))
    }

    /// Writes bytes to child stdin.
    pub fn write_stdin(
        &self,
        token: &str,
        handle: &str,
        bytes: &[u8],
    ) -> Result<(), CapabilityError> {
        let owned = self.lookup(token, handle)?;
        if bytes.len() > self.inner.host_limits.stdin_limit {
            return Err(CapabilityError::new(
                "budget_exceeded",
                "stdin write exceeds the configured bound",
            ));
        }
        owned.handle.write_stdin(bytes).map_err(map_process_error)?;
        Ok(())
    }

    /// Closes child stdin.
    pub fn close_stdin(&self, token: &str, handle: &str) -> Result<(), CapabilityError> {
        let owned = self.lookup(token, handle)?;
        owned.handle.close_stdin().map_err(map_process_error)
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

fn snapshot(handle: &BoundedProcessHandle, id: &str, cursor: u64, limit: usize) -> ProcessSnapshot {
    let stdout = handle.stdout_snapshot_from(cursor);
    let stderr = handle.stderr_snapshot_from(cursor);
    let stdout_truncated = stdout.truncated;
    let stderr_truncated = stderr.truncated;
    let stdout_len = stdout.len();
    let stderr_len = stderr.len();
    let mut stdout_bytes = stdout.bytes;
    let mut stderr_bytes = stderr.bytes;
    if limit != usize::MAX {
        stdout_bytes.truncate(limit);
        stderr_bytes.truncate(limit);
    }
    let truncated = stdout_truncated
        || stderr_truncated
        || stdout_bytes.len() < stdout_len
        || stderr_bytes.len() < stderr_len;
    let running = handle.terminal_status().is_none();
    let exit_code = handle.terminal_status().and_then(ProcessStatus::exit_code);
    ProcessSnapshot {
        handle: id.to_string(),
        running,
        exit_code,
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        truncated,
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
