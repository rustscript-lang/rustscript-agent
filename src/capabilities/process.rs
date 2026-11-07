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

use crate::capabilities::vm_io::{
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

/// Result of one bounded managed reaping pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedReapProof {
    /// Not all handles were proven within the cutoff; nothing was invalidated.
    Pending,
    /// A reap/drain/worker failure occurred; owner handles stay reachable.
    Failed,
    /// Every child is terminal, reaped, drained and stdin workers are zero.
    Quiescent,
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

#[derive(Default)]
struct CallProcessLedger {
    attempts: usize,
    handles: Vec<(String, BoundedProcessHandle)>,
    settled: bool,
    /// A live background child was handed to the run registry instead of being
    /// reaped with this call's token.
    transferred: bool,
    /// Per-call close fence: the call's own writer obligation is settled, so no
    /// further native operation may be admitted through its facade. The run
    /// registry stays open for later same-run calls.
    closed: bool,
}

struct ProcessInner {
    lifecycle: CapabilityLifecycle,
    owner: CapabilityOwner,
    host_limits: ProcessLimits,
    root: ConfinedFsRoot,
    workspace: Option<Arc<crate::auth::host::workspace::WorkspaceGrant>>,
    table: Mutex<HashMap<String, OwnedProcess>>,
    closing: AtomicBool,
    generation: AtomicU64,
    /// Actual OS spawn attempts for this run, cumulative across calls and never
    /// refunded: an attempt that failed after the syscall still counts.
    spawn_attempts: AtomicUsize,
    /// Test-only count of real kill signals, so a repeated kill can prove it
    /// sent none.
    #[cfg(test)]
    kill_signals: AtomicUsize,
    /// Test-only one-shot: the next managed cleanup reap proof is withheld.
    #[cfg(test)]
    reject_reap_proof: AtomicBool,
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
    /// The immutable Native call this facade belongs to. A facade never adopts
    /// another call's sealed policy, handles or closing state.
    call: Option<Weak<crate::effects::broker::ManagedCallContext>>,
    ledger: Arc<Mutex<CallProcessLedger>>,
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
                workspace: None,
                table: Mutex::new(HashMap::new()),
                closing: AtomicBool::new(false),
                generation: AtomicU64::new(1),
                spawn_attempts: AtomicUsize::new(0),
                #[cfg(test)]
                kill_signals: AtomicUsize::new(0),
                #[cfg(test)]
                reject_reap_proof: AtomicBool::new(false),
                after_running_poll_hook: Mutex::new(None),
                write_blocked_hook: Mutex::new(None),
                before_write_cycle_hook: Mutex::new(None),
                before_os_spawn_hook: Mutex::new(None),
                after_os_spawn_hook: Mutex::new(None),
                stdin_workers: AtomicUsize::new(0),
            }),
            call: None,
            ledger: Arc::new(Mutex::new(CallProcessLedger::default())),
        })
    }

    /// Constructs a run-scoped process table by adopting a live workspace root.
    pub(crate) fn new_adopted(
        lifecycle: CapabilityLifecycle,
        owner: CapabilityOwner,
        host_limits: ProcessLimits,
        workspace: Arc<crate::auth::host::workspace::WorkspaceGrant>,
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
        workspace
            .check()
            .map_err(|_| CapabilityError::new("workspace_denied", "workspace is unavailable"))?;
        let root = workspace
            .held()
            .root()
            .adopt(ConfinedFsLimits {
                max_read_bytes: MAX_READ_BYTES,
                max_write_bytes: MAX_WRITE_BYTES,
                max_entries: MAX_ENUM_ENTRIES,
                max_entry_name_bytes: MAX_COMPONENT_BYTES,
                max_temp_attempts: 32,
            })
            .map_err(|_| CapabilityError::new("workspace_denied", "workspace is unavailable"))?;
        Ok(Self {
            inner: Arc::new(ProcessInner {
                lifecycle,
                owner,
                host_limits,
                root,
                workspace: Some(workspace),
                table: Mutex::new(HashMap::new()),
                closing: AtomicBool::new(false),
                generation: AtomicU64::new(1),
                spawn_attempts: AtomicUsize::new(0),
                #[cfg(test)]
                kill_signals: AtomicUsize::new(0),
                #[cfg(test)]
                reject_reap_proof: AtomicBool::new(false),
                after_running_poll_hook: Mutex::new(None),
                write_blocked_hook: Mutex::new(None),
                before_write_cycle_hook: Mutex::new(None),
                before_os_spawn_hook: Mutex::new(None),
                after_os_spawn_hook: Mutex::new(None),
                stdin_workers: AtomicUsize::new(0),
            }),
            call: None,
            ledger: Arc::new(Mutex::new(CallProcessLedger::default())),
        })
    }

    pub(crate) fn new_managed(
        lifecycle: CapabilityLifecycle,
        owner: CapabilityOwner,
        limits: ProcessLimits,
        view: Arc<ConfinedFsRoot>,
        workspace: Arc<crate::auth::host::workspace::WorkspaceGrant>,
        managed: std::sync::Weak<crate::effects::broker::ManagedCallContext>,
    ) -> Result<Self, CapabilityError> {
        let mut capability = Self::new_adopted(lifecycle, owner, limits, workspace)?;
        let inner = Arc::get_mut(&mut capability.inner).ok_or_else(|| {
            CapabilityError::new(
                "managed_view_unavailable",
                "new process owner unexpectedly shared",
            )
        })?;
        inner.root = view
            .adopt(view.limits())
            .map_err(|e| CapabilityError::new("managed_view_unavailable", e.to_string()))?;
        capability.call = Some(managed);
        Ok(capability)
    }

    /// A fresh per-call facade over the same run-owned process resources. The
    /// run table, spawn budget, counters and shutdown fence are shared; the
    /// Native authorization context, spawn ledger and close fence are not.
    pub(crate) fn managed_facade(
        &self,
        managed: std::sync::Weak<crate::effects::broker::ManagedCallContext>,
    ) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            call: Some(managed),
            ledger: Arc::new(Mutex::new(CallProcessLedger::default())),
        }
    }

    /// The immutable Native call bound to this facade, if it is managed.
    pub(crate) fn managed_call(&self) -> Option<Arc<crate::effects::broker::ManagedCallContext>> {
        self.call.as_ref().and_then(|call| call.upgrade())
    }

    #[cfg(test)]
    pub(crate) fn bound_call_id(&self) -> Option<String> {
        self.managed_call()
            .map(|call| call.identity.call_id.clone())
    }

    /// Actual OS spawn attempts charged to this run so far, cumulative across
    /// calls and never refunded.
    pub fn spawn_attempts(&self) -> usize {
        self.inner.spawn_attempts.load(Ordering::SeqCst)
    }

    pub(crate) fn settle_managed_call(
        &self,
        token: &str,
    ) -> Result<crate::effects::ManagedWriterState, CapabilityError> {
        use crate::capabilities::vm_io::ProcessStatus;
        self.inner
            .lifecycle
            .authorize(&self.inner.owner, token, CapabilityRisk::Read)
            .map_err(CapabilityError::from)?;
        let Some(call) = self.managed_call() else {
            return Err(CapabilityError::new(
                "managed_writer_required",
                "managed writer owner required",
            ));
        };
        let _ = &call;
        let (attempts, owned, settled, transferred) = {
            let ledger = self.ledger.lock().unwrap_or_else(|p| p.into_inner());
            (
                ledger.attempts,
                ledger.handles.clone(),
                ledger.settled,
                ledger.transferred,
            )
        };
        if settled {
            return Ok(crate::effects::ManagedWriterState::Settled);
        }
        if transferred {
            // The producing call transferred a live child to the run registry.
            // Its own writer obligation is discharged without reaping, closing
            // or advancing this run's lifecycle generation.
            let mut ledger = self.ledger.lock().unwrap_or_else(|p| p.into_inner());
            ledger.settled = true;
            ledger.closed = true;
            return Ok(crate::effects::ManagedWriterState::Settled);
        }
        // Close this call, never the run: later same-run control calls must
        // still consume the same owned handles.
        {
            let mut ledger = self.ledger.lock().unwrap_or_else(|p| p.into_inner());
            ledger.closed = true;
        }
        if attempts != owned.len() {
            return Err(CapabilityError::new(
                "managed_writer_indeterminate",
                "Native spawn attempt has no positively settled owned handle",
            ));
        }
        for (id, handle) in &owned {
            if !matches!(
                handle.terminal_status(),
                Some(ProcessStatus::Exited { .. } | ProcessStatus::Signaled { .. })
            ) {
                return Err(CapabilityError::new(
                    "managed_writer_indeterminate",
                    "owned child has no known terminal status",
                ));
            }
            #[cfg(feature = "workspace-io-fault")]
            if self.managed_settle_fault(crate::effects::ManagedEffectFault::WriterReap) {
                return Err(CapabilityError::new(
                    "managed_writer_indeterminate",
                    "managed owned child reap: EIO",
                ));
            }
            handle.reap().map_err(map_process_error)?;
            #[cfg(feature = "workspace-io-fault")]
            if self.managed_settle_fault(crate::effects::ManagedEffectFault::WriterDrain) {
                return Err(CapabilityError::new(
                    "managed_writer_indeterminate",
                    "managed owned child drain: EIO",
                ));
            }
            handle.shutdown().map_err(map_process_error)?;
            // Remove only this call's own entries: a sibling call's handle in
            // the shared run table is not this call's to destroy.
            self.inner
                .table
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(id);
        }
        if self.active_stdin_workers() != 0 {
            return Err(CapabilityError::new(
                "managed_writer_indeterminate",
                "owned stdin workers remain",
            ));
        }
        let retired = {
            let mut ledger = self.ledger.lock().unwrap_or_else(|p| p.into_inner());
            ledger.settled = attempts > 0;
            std::mem::take(&mut ledger.handles)
        };
        drop(retired);
        Ok(if attempts == 0 {
            crate::effects::ManagedWriterState::NoProcess
        } else {
            crate::effects::ManagedWriterState::Settled
        })
    }

    /// Terminal quiescence of the run's owned children without destroying the
    /// table: a publisher needs every child reaped and every stdin worker
    /// finished, while later control calls must still observe the final entry.
    pub(crate) fn run_quiescence(
        &self,
        token: &str,
    ) -> Result<crate::effects::ManagedWriterState, CapabilityError> {
        use crate::capabilities::vm_io::ProcessStatus;
        self.inner
            .lifecycle
            .authorize(&self.inner.owner, token, CapabilityRisk::Read)
            .map_err(CapabilityError::from)?;
        let Some(call) = self.managed_call() else {
            return Err(CapabilityError::new(
                "managed_writer_required",
                "managed writer owner required",
            ));
        };
        let _ = &call;
        if self.is_closing() {
            return Err(closing_error());
        }
        let owned: Vec<OwnedProcess> = self
            .inner
            .table
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|owned| OwnedProcess {
                owner_key: owned.owner_key.clone(),
                generation: owned.generation,
                handle: owned.handle.clone(),
                cancel: owned.cancel.clone(),
            })
            .collect();
        if owned.is_empty() {
            return Ok(crate::effects::ManagedWriterState::NoProcess);
        }
        for process in &owned {
            if !matches!(
                process.handle.terminal_status(),
                Some(ProcessStatus::Exited { .. } | ProcessStatus::Signaled { .. })
            ) {
                return Err(CapabilityError::new(
                    "managed_writer_busy",
                    "a live child still holds the run writer view",
                ));
            }
            process.handle.reap().map_err(map_process_error)?;
        }
        if self.active_stdin_workers() != 0 {
            return Err(CapabilityError::new(
                "managed_writer_indeterminate",
                "owned stdin workers remain",
            ));
        }
        Ok(crate::effects::ManagedWriterState::Settled)
    }

    /// Phase-independent completion proof over the run's existing owned table.
    ///
    /// It only observes: a non-reaping exit observation of each owned root and,
    /// once that root was seen exited, the natural EOF completion of that
    /// handle's exact output drainers (a `DrainFailed` recorded by a real
    /// drainer is propagated and keeps priority, while a drainer that stopped
    /// reading at its own deadline is pending, never completion) plus zero
    /// owned stdin workers. A live child, undrained or abandoned output,
    /// a closing table, an empty table or the caller's remaining deadline are
    /// not proof. It removes no entry, advances no generation, retires no view,
    /// closes no stdin, reaps no exited root and signals no process, so the
    /// retained zombie and group identity stay available to the authorized
    /// cleanup. The caller's original `deadline` bounds every wait and join;
    /// zero remaining time returns `managed_completion_busy` without starting a
    /// fresh cleanup grace.
    pub(crate) fn probe_completion_quiescence(
        &self,
        deadline: Instant,
    ) -> Result<(), CapabilityError> {
        let busy = |message: &str| CapabilityError::new("managed_completion_busy", message);
        if self.is_closing() {
            // Cleanup already began: this table is no longer an observable run
            // writer proof.
            return Err(busy("managed process table is closing"));
        }
        let owned: Vec<BoundedProcessHandle> = self
            .inner
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|process| process.handle.clone())
            .collect();
        if owned.is_empty() {
            // An empty registry is not a proof of an owned group.
            return Err(busy("no owned process group to prove"));
        }
        for handle in &owned {
            if Instant::now() >= deadline {
                return Err(busy("managed completion deadline elapsed"));
            }
            match handle
                .completion_proof_terminal(deadline)
                .map_err(map_process_error)?
            {
                Some(_terminal) => {}
                None => {
                    return Err(busy("an owned child or its output is still pending"));
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(busy("managed completion deadline elapsed"));
        }
        if self.active_stdin_workers() != 0 {
            return Err(busy("owned stdin workers remain"));
        }
        Ok(())
    }

    #[cfg(feature = "workspace-io-fault")]
    fn managed_settle_fault(&self, fault: crate::effects::ManagedEffectFault) -> bool {
        self.managed_call()
            .and_then(|call| call.binding().ok())
            .is_some_and(|binding| binding.runtime.take_fault(fault))
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
        let _operation = self.enter_managed_operation(
            token,
            crate::effects::authority::ManagedNativeOperation::ProcessSpawn,
        )?;
        let managed_call = self.managed_call();
        let managed_background = managed_call.is_some() && !limits.close_after_initial;
        if managed_background
            && !managed_call
                .as_ref()
                .is_some_and(|call| call.allows_open_process())
        {
            return Err(CapabilityError::new(
                "managed_open_effect_unsupported",
                "managed process must close after initial foreground execution",
            ));
        }
        if self.ledger.lock().unwrap_or_else(|p| p.into_inner()).closed {
            return Err(CapabilityError::new(
                "managed_writer_closed",
                "this call already settled its managed writer obligation",
            ));
        }
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
        if managed_call.is_some() {
            // The run's spawn budget is cumulative across every call and an
            // attempt is charged before the syscall, never refunded.
            let attempted = self.inner.spawn_attempts.try_update(
                Ordering::SeqCst,
                Ordering::SeqCst,
                |attempts| (attempts < 32).then_some(attempts + 1),
            );
            if attempted.is_err() {
                return Err(CapabilityError::new(
                    "budget_exceeded",
                    "managed owned spawn bound exceeded",
                ));
            }
            self.ledger
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .attempts += 1;
        }
        let process = BoundedProcess::spawn(request).map_err(map_process_error)?;
        fire_hook(&self.inner.after_os_spawn_hook);
        let handle = process.lifecycle_handle();
        let write_handle = handle.clone();
        let pid = handle.pid();
        let id = uuid::Uuid::new_v4().simple().to_string();
        if managed_call.is_some() {
            let mut ledger = self.ledger.lock().unwrap_or_else(|p| p.into_inner());
            ledger
                .handles
                .push((id.clone(), process.lifecycle_handle()));
            ledger.transferred |= managed_background;
        }
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
        // A managed background child outlives this call's token: the run
        // registry (this capability) owns termination, so no token-scoped
        // reaper may kill it when the producing call's lease is released.
        if !managed_background {
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
        let _operation = self.enter_managed_operation(
            token,
            crate::effects::authority::ManagedNativeOperation::OwnedProcessUse,
        )?;
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
        let _operation = self.enter_managed_operation(
            token,
            crate::effects::authority::ManagedNativeOperation::OwnedProcessUse,
        )?;
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

    /// Test-only view of the exact owned handles, so a producer-level
    /// observation can inspect the real group it already owns.
    #[cfg(all(test, unix))]
    pub(crate) fn handles_for_test(&self) -> Vec<BoundedProcessHandle> {
        self.inner
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|process| process.handle.clone())
            .collect()
    }

    /// Test-only deterministic drain failure for the real owned handles of
    /// this group. The failure is produced by each handle's own drainer.
    #[cfg(all(test, unix))]
    pub(crate) fn force_drain_error_for_test(&self) {
        for handle in self.handles_for_test() {
            handle.force_drain_error_for_test();
        }
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
        let _operation = self.enter_managed_operation(
            token,
            crate::effects::authority::ManagedNativeOperation::OwnedProcessUse,
        )?;
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
        let _operation = self.enter_managed_operation(
            token,
            crate::effects::authority::ManagedNativeOperation::OwnedProcessUse,
        )?;
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
        let _operation = self.enter_managed_operation(
            token,
            crate::effects::authority::ManagedNativeOperation::OwnedProcessUse,
        )?;
        let owned = self.lookup(token, handle)?;
        match owned.handle.close_stdin() {
            Ok(())
            | Err(BoundedProcessError::StdinClosed)
            | Err(BoundedProcessError::StdinWriteFailed { .. }) => Ok(()),
            Err(error) => Err(map_process_error(error)),
        }
    }

    /// Kills the process tree bound to `handle`.
    ///
    /// A repeated kill observes the already-terminal entry and sends no second
    /// signal; only an entry without a known terminal status is terminated.
    pub fn kill(&self, token: &str, handle: &str) -> Result<(), CapabilityError> {
        use crate::capabilities::vm_io::ProcessStatus;
        let _operation = self.enter_managed_operation(
            token,
            crate::effects::authority::ManagedNativeOperation::OwnedProcessUse,
        )?;
        let owned = self.lookup(token, handle)?;
        if matches!(
            owned.handle.terminal_status(),
            Some(ProcessStatus::Exited { .. } | ProcessStatus::Signaled { .. })
        ) {
            return Ok(());
        }
        #[cfg(test)]
        self.inner.kill_signals.fetch_add(1, Ordering::SeqCst);
        terminate_owned(&owned);
        Ok(())
    }

    /// Test-only count of real kill signals this run actually sent. A repeated
    /// kill must not increase it.
    #[cfg(test)]
    pub fn kill_signals(&self) -> usize {
        self.inner.kill_signals.load(Ordering::SeqCst)
    }

    /// Test-only reap-proof suppression for the bounded cleanup path. It
    /// stays active until the fixture explicitly allows the proof again.
    #[cfg(test)]
    pub(crate) fn reject_next_reap_proof_for_test(&self) {
        self.inner.reject_reap_proof.store(true, Ordering::SeqCst);
    }

    /// Test-only: allow the bounded cleanup proof again for a retry.
    #[cfg(test)]
    pub(crate) fn allow_reap_proof_for_test(&self) {
        self.inner.reject_reap_proof.store(false, Ordering::SeqCst);
    }

    /// Test-only owner generation for cleanup fence assertions.
    #[cfg(test)]
    pub(crate) fn generation_for_test(&self) -> u64 {
        self.inner.generation.load(Ordering::SeqCst)
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
    /// Seals managed admissions without touching the owner generation or the
    /// handle table. Managed cleanup calls this first, then proves each child
    /// reap and output drain under its own grace bound.
    pub(crate) fn begin_managed_shutdown(&self) {
        self.inner.closing.store(true, Ordering::SeqCst);
    }

    /// One bounded managed reaping pass. Each owned handle is killed and must
    /// present its reaped, drain-joined terminal status before its table entry
    /// is removed. `None` status within the cutoff keeps the handle reachable
    /// and reports `Pending`; a drain/reap error reports `Failed`. Generation
    /// and table are untouched here.
    pub(crate) fn reap_managed_within(&self, cutoff: Instant) -> ManagedReapProof {
        #[cfg(test)]
        if self.inner.reject_reap_proof.load(Ordering::SeqCst) {
            return ManagedReapProof::Pending;
        }
        let owned: Vec<(String, u64, BoundedProcessHandle)> = self
            .inner
            .table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(id, process)| (id.clone(), process.generation, process.handle.clone()))
            .collect();
        let mut failed = false;
        for (id, generation, handle) in owned {
            match handle.shutdown_within(cutoff) {
                Ok(Some(_)) => {
                    let mut table = self
                        .inner
                        .table
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let matches = table
                        .get(&id)
                        .is_some_and(|owned| owned.generation == generation);
                    if matches {
                        table.remove(&id);
                    }
                }
                Ok(None) => return ManagedReapProof::Pending,
                Err(_) => failed = true,
            }
        }
        if failed {
            return ManagedReapProof::Failed;
        }
        if self.table_len() != 0 || self.active_stdin_workers() != 0 {
            return ManagedReapProof::Pending;
        }
        ManagedReapProof::Quiescent
    }

    /// Advance the owner generation only after every handle was reaped, both
    /// output streams joined and all stdin workers returned.
    pub(crate) fn complete_managed_shutdown(&self) -> bool {
        if self.table_len() == 0 && self.active_stdin_workers() == 0 {
            self.inner.closing.store(true, Ordering::SeqCst);
            self.inner.generation.fetch_add(1, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

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

    fn enter_managed_operation(
        &self,
        token: &str,
        operation: crate::effects::authority::ManagedNativeOperation,
    ) -> Result<Option<crate::effects::broker::ManagedOperationEvidence>, CapabilityError> {
        self.call
            .as_ref()
            .map(|_| {
                let claims = self
                    .inner
                    .lifecycle
                    .authorize(&self.inner.owner, token, operation.required_risk())
                    .map_err(CapabilityError::from)?;
                // Resolve only this facade's own call context. A sibling
                // same-run call can never lend its sealed authority here.
                self.managed_call()
                    .ok_or_else(|| {
                        CapabilityError::new("managed_call_unavailable", "managed call unavailable")
                    })?
                    .enter_operation(&claims, operation)
                    .map_err(|error| CapabilityError::new("managed_operation_denied", error))
            })
            .transpose()
    }
    fn authorize(&self, token: &str, risk: CapabilityRisk) -> Result<TokenClaims, CapabilityError> {
        if let Some(workspace) = &self.inner.workspace {
            workspace.check().map_err(|_| {
                CapabilityError::new("workspace_denied", "workspace is unavailable")
            })?;
        }
        match self
            .inner
            .lifecycle
            .authorize(&self.inner.owner, token, risk)
        {
            Ok(claims) => {
                if self.call.is_some() {
                    self.managed_call()
                        .ok_or_else(|| {
                            CapabilityError::new(
                                "managed_call_unavailable",
                                "managed call unavailable",
                            )
                        })?
                        .authorize(&claims, risk)
                        .map_err(|e| CapabilityError::new("managed_operation_denied", e))?;
                }
                Ok(claims)
            }
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
