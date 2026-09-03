use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rustscript_vm::{
    BoundedProcess, BoundedProcessError, BoundedProcessHandle, CancellationToken, LogSnapshot,
    ProcessStatus, ProcessValidationError,
};
use serde_json::{Map, Value, json};

use crate::config::ProcessToolConfig;

use super::{
    NativeToolExecutor, ToolDescriptor, ToolOwner, ToolResult, builtin_descriptor,
    enforce_serialized_tool_result_cap, serialized_tool_result_len,
};

const PROCESS_NOT_FOUND_MESSAGE: &str = "process not found";
const WRITE_POLL_SLICE: Duration = Duration::from_millis(5);

#[derive(Clone, Debug)]
pub(crate) struct ToolFailure {
    code: &'static str,
    message: String,
}

impl ToolFailure {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub(crate) fn into_result(self) -> ToolResult {
        ToolResult::failure(self.code, self.message)
    }
}

/// Owner scope that binds an opaque process id to profile/session/run.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ProcessOwner {
    owner: ToolOwner,
}

impl ProcessOwner {
    pub fn new(
        profile_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Result<Self, String> {
        Ok(Self {
            owner: ToolOwner::new(profile_id, session_id, run_id)?,
        })
    }

    pub fn profile_id(&self) -> &str {
        self.owner.profile()
    }

    pub fn session_id(&self) -> &str {
        self.owner.session()
    }

    pub fn run_id(&self) -> &str {
        self.owner.run()
    }
}

impl From<ToolOwner> for ProcessOwner {
    fn from(owner: ToolOwner) -> Self {
        Self { owner }
    }
}

impl From<ProcessOwner> for ToolOwner {
    fn from(owner: ProcessOwner) -> Self {
        owner.owner
    }
}

impl From<&ProcessOwner> for ToolOwner {
    fn from(owner: &ProcessOwner) -> Self {
        owner.owner.clone()
    }
}

/// Optional overflow sink for owner-scoped artifact publication.
pub trait ProcessArtifactSink: Send + Sync {
    fn store(&self, owner: &ProcessOwner, bytes: &[u8]) -> Result<String, String>;
}

struct OwnedProcess {
    owner: ProcessOwner,
    process: BoundedProcess,
    draining: bool,
}

struct ForegroundOp {
    owner: ProcessOwner,
    token: CancellationToken,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CleanupMask {
    All,
    Profile(String),
    Session {
        profile_id: String,
        session_id: String,
    },
    Run {
        profile_id: String,
        session_id: String,
        run_id: String,
    },
}

impl CleanupMask {
    fn matches(&self, owner: &ProcessOwner) -> bool {
        match self {
            Self::All => true,
            Self::Profile(profile_id) => owner.profile_id() == *profile_id,
            Self::Session {
                profile_id,
                session_id,
            } => owner.profile_id() == *profile_id && owner.session_id() == *session_id,
            Self::Run {
                profile_id,
                session_id,
                run_id,
            } => {
                owner.profile_id() == *profile_id
                    && owner.session_id() == *session_id
                    && owner.run_id() == *run_id
            }
        }
    }
}

struct TableState {
    processes: HashMap<String, OwnedProcess>,
    foreground: HashMap<u64, ForegroundOp>,
    next_foreground_id: u64,
    shutdown: bool,
    cleaning: Vec<CleanupMask>,
}

fn owner_blocked(state: &TableState, owner: &ProcessOwner) -> bool {
    state.shutdown || state.cleaning.iter().any(|mask| mask.matches(owner))
}

/// RAII unregister for an in-flight foreground cancellation token.
pub(crate) struct ForegroundGuard {
    table: Arc<ProcessTable>,
    id: u64,
}

impl Drop for ForegroundGuard {
    fn drop(&mut self) {
        self.table.unregister_foreground(self.id);
    }
}

/// Service-owned table of opaque, owner-scoped process records.
pub struct ProcessTable {
    config: ProcessToolConfig,
    inner: Mutex<TableState>,
}

impl ProcessTable {
    pub fn new(config: ProcessToolConfig) -> Result<Self, String> {
        Ok(Self {
            config: config.validated()?,
            inner: Mutex::new(TableState {
                processes: HashMap::new(),
                foreground: HashMap::new(),
                next_foreground_id: 1,
                shutdown: false,
                cleaning: Vec::new(),
            }),
        })
    }

    pub fn config(&self) -> &ProcessToolConfig {
        &self.config
    }

    pub fn len(&self) -> usize {
        self.inner.lock().processes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Live process plus in-flight foreground ops owned by `owner`.
    pub fn owner_count(&self, owner: &ProcessOwner) -> usize {
        let state = self.inner.lock();
        let processes = state
            .processes
            .values()
            .filter(|entry| entry.owner == *owner)
            .count();
        let foreground = state
            .foreground
            .values()
            .filter(|op| op.owner == *owner)
            .count();
        processes + foreground
    }

    /// OS PIDs still retained for this owner, including draining residue.
    pub fn owner_pids(&self, owner: &ProcessOwner) -> Vec<u32> {
        self.inner
            .lock()
            .processes
            .values()
            .filter(|entry| entry.owner == *owner)
            .map(|entry| entry.process.lifecycle_handle().pid())
            .collect()
    }

    pub fn cleanup_owner(&self, owner: &ProcessOwner) -> Result<usize, String> {
        Ok(self.cleanup_scope(CleanupMask::Run {
            profile_id: owner.profile_id().to_string(),
            session_id: owner.session_id().to_string(),
            run_id: owner.run_id().to_string(),
        }))
    }

    pub fn cleanup_run(&self, profile_id: &str, session_id: &str, run_id: &str) -> usize {
        self.cleanup_scope(CleanupMask::Run {
            profile_id: profile_id.to_string(),
            session_id: session_id.to_string(),
            run_id: run_id.to_string(),
        })
    }

    pub fn cleanup_session(&self, profile_id: &str, session_id: &str) -> usize {
        self.cleanup_scope(CleanupMask::Session {
            profile_id: profile_id.to_string(),
            session_id: session_id.to_string(),
        })
    }

    pub fn cleanup_profile(&self, profile_id: &str) -> usize {
        self.cleanup_scope(CleanupMask::Profile(profile_id.to_string()))
    }

    pub fn shutdown(&self) {
        let taken = {
            let mut state = self.inner.lock();
            state.shutdown = true;
            state.cleaning.push(CleanupMask::All);
            let tokens: Vec<CancellationToken> = state
                .foreground
                .values()
                .map(|op| op.token.clone())
                .collect();
            for token in tokens {
                token.cancel();
            }
            std::mem::take(&mut state.processes)
        };
        bounded_shutdown(
            taken.into_values().map(|entry| entry.process).collect(),
            self.config.cleanup_timeout,
        );
    }

    pub(crate) fn register_foreground(
        table: &Arc<Self>,
        owner: &ProcessOwner,
        token: CancellationToken,
    ) -> Result<(CancellationToken, ForegroundGuard), ToolFailure> {
        let mut state = table.inner.lock();
        if owner_blocked(&state, owner) {
            token.cancel();
            return Err(ToolFailure::new(
                "cancelled",
                "process table is shutting down",
            ));
        }
        let id = state.next_foreground_id;
        state.next_foreground_id = state.next_foreground_id.saturating_add(1);
        state.foreground.insert(
            id,
            ForegroundOp {
                owner: owner.clone(),
                token: token.clone(),
            },
        );
        drop(state);
        Ok((
            token,
            ForegroundGuard {
                table: Arc::clone(table),
                id,
            },
        ))
    }

    fn unregister_foreground(&self, id: u64) {
        self.inner.lock().foreground.remove(&id);
    }

    pub(crate) fn insert(
        &self,
        owner: ProcessOwner,
        process: BoundedProcess,
    ) -> Result<String, ToolFailure> {
        let mut state = self.inner.lock();
        if owner_blocked(&state, &owner) {
            drop(state);
            return self.reject_insert(
                process,
                ToolFailure::new("cancelled", "process table is shutting down"),
            );
        }
        if state.processes.len() >= self.config.max_processes {
            drop(state);
            return self.reject_insert(
                process,
                ToolFailure::new("process_limit_exceeded", "process table is full"),
            );
        }
        let owner_count = state
            .processes
            .values()
            .filter(|entry| entry.owner == owner)
            .count();
        if owner_count >= self.config.max_processes_per_owner {
            drop(state);
            return self.reject_insert(
                process,
                ToolFailure::new("process_limit_exceeded", "owner process limit exceeded"),
            );
        }
        let id = match allocate_process_id(&state.processes) {
            Ok(id) => id,
            Err(failure) => {
                drop(state);
                return self.reject_insert(process, failure);
            }
        };
        state.processes.insert(
            id.clone(),
            OwnedProcess {
                owner,
                process,
                draining: false,
            },
        );
        Ok(id)
    }

    fn reject_insert(
        &self,
        process: BoundedProcess,
        failure: ToolFailure,
    ) -> Result<String, ToolFailure> {
        bounded_shutdown(vec![process], self.config.cleanup_timeout);
        Err(failure)
    }

    pub(crate) fn lookup_handle(
        &self,
        owner: &ProcessOwner,
        process_id: &str,
    ) -> Result<BoundedProcessHandle, ToolFailure> {
        let state = self.inner.lock();
        match state.processes.get(process_id) {
            Some(entry) if &entry.owner == owner => Ok(entry.process.lifecycle_handle()),
            _ => Err(process_not_found()),
        }
    }

    fn cleanup_scope(&self, mask: CleanupMask) -> usize {
        let ids = {
            let mut state = self.inner.lock();
            if !state.cleaning.iter().any(|existing| existing == &mask) {
                state.cleaning.push(mask.clone());
            }
            for op in state.foreground.values() {
                if mask.matches(&op.owner) {
                    op.token.cancel();
                }
            }
            let mut ids = Vec::new();
            for (id, entry) in state.processes.iter_mut() {
                if mask.matches(&entry.owner) {
                    entry.draining = true;
                    entry.process.lifecycle_handle().cancel();
                    ids.push(id.clone());
                }
            }
            ids
        };
        if ids.is_empty() {
            let mut state = self.inner.lock();
            if let Some(index) = state.cleaning.iter().rposition(|item| item == &mask) {
                state.cleaning.remove(index);
            }
            return 0;
        }
        let deadline = saturating_instant_add(Instant::now(), self.config.cleanup_timeout);
        loop {
            {
                let mut state = self.inner.lock();
                let mut remove = Vec::new();
                for id in &ids {
                    if let Some(entry) = state.processes.get(id)
                        && matches!(entry.process.lifecycle_handle().try_wait(), Ok(Some(_)))
                    {
                        remove.push(id.clone());
                    }
                }
                for id in &remove {
                    state.processes.remove(id);
                }
                let remaining = ids
                    .iter()
                    .filter(|id| state.processes.contains_key(*id))
                    .count();
                if remaining == 0 {
                    if let Some(index) = state.cleaning.iter().rposition(|item| item == &mask) {
                        state.cleaning.remove(index);
                    }
                    return ids.len();
                }
                if Instant::now() >= deadline {
                    return ids.len();
                }
            }
            thread::sleep(Duration::from_millis(5).min(self.config.cleanup_timeout));
        }
    }
}

impl Drop for ProcessTable {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn allocate_process_id(existing: &HashMap<String, OwnedProcess>) -> Result<String, ToolFailure> {
    for _ in 0..8 {
        let id = uuid::Uuid::new_v4().simple().to_string();
        if !existing.contains_key(&id) {
            return Ok(id);
        }
    }
    Err(ToolFailure::new(
        "spawn_failed",
        "could not allocate a process id",
    ))
}

fn bounded_shutdown(processes: Vec<BoundedProcess>, timeout: Duration) {
    if processes.is_empty() {
        return;
    }
    let deadline = Instant::now() + timeout;
    for process in &processes {
        process.lifecycle_handle().cancel();
    }
    let mut remaining = processes;
    while Instant::now() < deadline && !remaining.is_empty() {
        remaining.retain(|process| match process.lifecycle_handle().try_wait() {
            Ok(Some(_)) => false,
            Ok(None) | Err(_) => true,
        });
        if remaining.is_empty() {
            break;
        }
        let slice =
            Duration::from_millis(5).min(deadline.saturating_duration_since(Instant::now()));
        if slice.is_zero() {
            break;
        }
        thread::sleep(slice);
    }
    drop(remaining);
}

fn process_not_found() -> ToolFailure {
    ToolFailure::new("process_not_found", PROCESS_NOT_FOUND_MESSAGE)
}

/// Native process-tool action. IDs stay opaque; numeric PIDs are never used.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProcessAction {
    #[default]
    Poll,
    Wait,
    Log,
    Write,
    Close,
    Kill,
}

impl ProcessAction {
    fn parse(value: &str) -> Result<Self, ToolFailure> {
        match value {
            "poll" => Ok(Self::Poll),
            "wait" => Ok(Self::Wait),
            "log" => Ok(Self::Log),
            "write" => Ok(Self::Write),
            "close" => Ok(Self::Close),
            "kill" => Ok(Self::Kill),
            _ => Err(ToolFailure::new(
                "invalid_action",
                "unsupported process action",
            )),
        }
    }
}

/// Typed process-tool request used by tests and later dispatch.
#[derive(Clone, Debug, Default)]
pub struct ProcessRequest {
    pub action: ProcessAction,
    pub process_id: String,
    pub data: Option<String>,
    pub timeout_ms: Option<u64>,
    pub offset: Option<u64>,
    pub limit: Option<u64>,
}

#[derive(Clone)]
pub(crate) struct ProcessExecutorState {
    pub config: ProcessToolConfig,
    pub table: Arc<ProcessTable>,
    pub owner: ProcessOwner,
    pub artifact_sink: Option<Arc<dyn ProcessArtifactSink>>,
}

/// Outer deadline for wrappers that do not receive caller run controls.
///
/// `default_timeout` is only the omitted-`timeout_ms` request/spawn/action default.
/// The wrapper deadline must not be tighter than any validated request timeout, so
/// this uses `max_timeout` with checked Instant arithmetic that saturates on overflow.
pub(crate) fn no_controls_deadline(config: &ProcessToolConfig) -> Instant {
    saturating_instant_add(Instant::now(), config.max_timeout)
}

pub(crate) fn saturating_instant_add(now: Instant, duration: Duration) -> Instant {
    now.checked_add(duration).unwrap_or(now)
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn resolve_action_timeout(
    config: &ProcessToolConfig,
    timeout_ms: Option<u64>,
) -> Result<Option<Duration>, ToolFailure> {
    match timeout_ms {
        None => Ok(None),
        Some(0) => Err(ToolFailure::new(
            "invalid_timeout",
            "timeout_ms must be positive",
        )),
        Some(ms) => {
            if ms > duration_millis(config.max_timeout) {
                return Err(ToolFailure::new(
                    "invalid_timeout",
                    "timeout exceeds the configured bound",
                ));
            }
            Ok(Some(Duration::from_millis(ms)))
        }
    }
}

/// Owner-scoped executor for the `process` native slot.
#[derive(Clone)]
pub struct ProcessExecutor {
    inner: Arc<ProcessExecutorState>,
}

impl ProcessExecutor {
    pub fn new(
        config: ProcessToolConfig,
        table: Arc<ProcessTable>,
        owner: ProcessOwner,
    ) -> Result<Self, String> {
        Ok(Self {
            inner: Arc::new(ProcessExecutorState {
                config: config.validated()?,
                table,
                owner,
                artifact_sink: None,
            }),
        })
    }

    pub fn with_artifact_sink(&self, sink: Arc<dyn ProcessArtifactSink>) -> Self {
        Self {
            inner: Arc::new(ProcessExecutorState {
                artifact_sink: Some(sink),
                ..(*self.inner).clone()
            }),
        }
    }

    pub fn slot(&self) -> NativeToolExecutor {
        NativeToolExecutor::Process
    }

    pub fn descriptor(&self) -> ToolDescriptor {
        builtin_descriptor("process")
    }

    pub fn table(&self) -> &ProcessTable {
        &self.inner.table
    }

    pub fn execute(&self, arguments: &Value) -> ToolResult {
        self.execute_with_controls(
            arguments,
            &CancellationToken::new(),
            no_controls_deadline(&self.inner.config),
        )
    }

    pub fn execute_with_controls(
        &self,
        arguments: &Value,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> ToolResult {
        match parse_process_request(arguments) {
            Ok(request) => self.run_with_controls(request, cancellation, deadline),
            Err(failure) => failure.into_result(),
        }
    }

    pub fn run(&self, request: ProcessRequest) -> ToolResult {
        self.run_with_controls(
            request,
            &CancellationToken::new(),
            no_controls_deadline(&self.inner.config),
        )
    }

    pub fn run_with_controls(
        &self,
        request: ProcessRequest,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> ToolResult {
        if cancellation.is_cancelled() {
            return ToolResult::failure("cancelled", "process was cancelled");
        }
        if Instant::now() >= deadline {
            return ToolResult::failure("deadline_elapsed", "process deadline elapsed");
        }
        if request.process_id.is_empty() {
            return process_not_found().into_result();
        }
        let handle = match self
            .inner
            .table
            .lookup_handle(&self.inner.owner, &request.process_id)
        {
            Ok(handle) => handle,
            Err(failure) => return failure.into_result(),
        };
        match request.action {
            ProcessAction::Poll => self.poll(&handle),
            ProcessAction::Wait => self.wait(&handle, request.timeout_ms, cancellation, deadline),
            ProcessAction::Log => self.log(&handle, request.offset, request.limit),
            ProcessAction::Write => self.write(
                &handle,
                request.data.as_deref().unwrap_or(""),
                request.timeout_ms,
                cancellation,
                deadline,
            ),
            ProcessAction::Close => self.close(&handle),
            ProcessAction::Kill => self.kill(&handle),
        }
    }

    fn poll(&self, handle: &BoundedProcessHandle) -> ToolResult {
        match handle.poll() {
            Ok(status) => self.view(handle, status, true),
            Err(error) => map_handle_error(handle, error, &self.inner),
        }
    }

    fn wait(
        &self,
        handle: &BoundedProcessHandle,
        timeout_ms: Option<u64>,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> ToolResult {
        let timeout = match resolve_action_timeout(&self.inner.config, timeout_ms) {
            Ok(timeout) => timeout,
            Err(failure) => return failure.into_result(),
        };
        if cancellation.is_cancelled() {
            return ToolResult::failure("cancelled", "process was cancelled");
        }
        if Instant::now() >= deadline {
            return ToolResult::failure("deadline_elapsed", "process deadline elapsed");
        }
        let process_deadline = handle.deadline();
        let wait_timeout_deadline =
            timeout.map(|timeout| saturating_instant_add(Instant::now(), timeout));
        loop {
            if cancellation.is_cancelled() {
                return ToolResult::failure("cancelled", "process was cancelled");
            }
            if Instant::now() >= deadline {
                return ToolResult::failure("deadline_elapsed", "process deadline elapsed");
            }
            match handle.poll() {
                Ok(Some(status)) => return self.view(handle, Some(status), true),
                Ok(None) => {
                    if wait_timeout_deadline.is_some_and(|bound| Instant::now() >= bound) {
                        return self.view(handle, None, true);
                    }
                    if Instant::now() >= process_deadline {
                        return map_handle_error(
                            handle,
                            BoundedProcessError::DeadlineElapsed,
                            &self.inner,
                        );
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return map_handle_error(handle, error, &self.inner),
            }
        }
    }

    fn log(
        &self,
        handle: &BoundedProcessHandle,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> ToolResult {
        if let Some(0) = limit {
            return ToolResult::failure("invalid_output_limit", "limit must be positive");
        }
        let offset = offset.unwrap_or(0);
        let mut stdout = handle.stdout_snapshot_from(offset);
        let mut stderr = handle.stderr_snapshot_from(offset);
        if let Some(limit) = limit {
            stdout = truncate_snapshot(stdout, limit);
            stderr = truncate_snapshot(stderr, limit);
        }
        let status = handle.terminal_status();
        self.view_from_snapshots(handle, status, stdout, stderr, true)
    }

    fn write(
        &self,
        handle: &BoundedProcessHandle,
        data: &str,
        timeout_ms: Option<u64>,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> ToolResult {
        if cancellation.is_cancelled() {
            return ToolResult::failure("cancelled", "process was cancelled");
        }
        if Instant::now() >= deadline {
            return ToolResult::failure("deadline_elapsed", "process deadline elapsed");
        }
        let timeout = match resolve_action_timeout(&self.inner.config, timeout_ms) {
            Ok(timeout) => timeout,
            Err(failure) => return failure.into_result(),
        };
        match write_stdin_with_deadline(
            handle,
            data.as_bytes(),
            timeout,
            cancellation,
            deadline,
            self.inner.config.cleanup_timeout,
        ) {
            Ok(wrote) => ToolResult::success(String::new(), json!({ "wrote_bytes": wrote as u64 })),
            Err(BoundedProcessError::StdinClosed) => {
                ToolResult::failure("stdin_closed", "process stdin is closed")
            }
            Err(error) => map_handle_error(handle, error, &self.inner),
        }
    }

    fn close(&self, handle: &BoundedProcessHandle) -> ToolResult {
        match handle.close_stdin() {
            Ok(()) | Err(BoundedProcessError::StdinClosed) => {
                ToolResult::success(String::new(), json!({ "stdin_closed": true }))
            }
            Err(error) => map_handle_error(handle, error, &self.inner),
        }
    }

    fn kill(&self, handle: &BoundedProcessHandle) -> ToolResult {
        match handle.shutdown() {
            Ok(())
            | Err(BoundedProcessError::StdinClosed)
            | Err(BoundedProcessError::DeadlineElapsed)
            | Err(BoundedProcessError::Cancelled) => {
                self.view(handle, handle.terminal_status(), true)
            }
            Err(error) => map_handle_error(handle, error, &self.inner),
        }
    }

    fn view(
        &self,
        handle: &BoundedProcessHandle,
        status: Option<ProcessStatus>,
        ok: bool,
    ) -> ToolResult {
        self.view_from_snapshots(
            handle,
            status,
            handle.stdout_snapshot(),
            handle.stderr_snapshot(),
            ok,
        )
    }

    fn view_from_snapshots(
        &self,
        _handle: &BoundedProcessHandle,
        status: Option<ProcessStatus>,
        stdout: LogSnapshot,
        stderr: LogSnapshot,
        ok: bool,
    ) -> ToolResult {
        assemble_process_result(&self.inner, status, &stdout, &stderr, ok, None)
    }
}

fn parse_process_request(arguments: &Value) -> Result<ProcessRequest, ToolFailure> {
    let action = arguments
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| ToolFailure::new("invalid_action", "action is required"))?;
    let process_id = arguments
        .get("process_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Ok(ProcessRequest {
        action: ProcessAction::parse(action)?,
        process_id,
        data: arguments
            .get("data")
            .and_then(Value::as_str)
            .map(str::to_string),
        timeout_ms: optional_positive_u64(arguments, "timeout_ms", "invalid_timeout")?,
        offset: optional_u64(arguments, "offset", "invalid_output_limit")?,
        limit: optional_positive_u64(arguments, "limit", "invalid_output_limit")?,
    })
}

pub(crate) fn optional_u64(
    arguments: &Value,
    key: &str,
    code: &'static str,
) -> Result<Option<u64>, ToolFailure> {
    match arguments.get(key) {
        None => Ok(None),
        Some(value) if value.is_null() => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| ToolFailure::new(code, format!("{key} must be a non-negative integer"))),
    }
}

pub(crate) fn optional_positive_u64(
    arguments: &Value,
    key: &str,
    code: &'static str,
) -> Result<Option<u64>, ToolFailure> {
    match optional_u64(arguments, key, code)? {
        None => Ok(None),
        Some(0) => Err(ToolFailure::new(code, format!("{key} must be positive"))),
        Some(value) => Ok(Some(value)),
    }
}

fn truncate_snapshot(mut snapshot: LogSnapshot, limit: u64) -> LogSnapshot {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    if snapshot.bytes.len() > limit {
        snapshot.bytes.truncate(limit);
        snapshot.truncated = true;
        snapshot.eof = false;
        snapshot.next_offset = snapshot
            .offset
            .saturating_add(u64::try_from(snapshot.bytes.len()).unwrap_or(u64::MAX));
    }
    snapshot
}

fn write_stdin_with_deadline(
    handle: &BoundedProcessHandle,
    data: &[u8],
    timeout: Option<Duration>,
    cancellation: &CancellationToken,
    deadline: Instant,
    cleanup_timeout: Duration,
) -> Result<usize, BoundedProcessError> {
    if cancellation.is_cancelled() {
        return Err(BoundedProcessError::Cancelled);
    }
    let process_deadline = handle.deadline();
    let action_deadline = timeout
        .map(|timeout| saturating_instant_add(Instant::now(), timeout))
        .unwrap_or(process_deadline)
        .min(process_deadline)
        .min(deadline);
    if Instant::now() >= action_deadline {
        return Err(BoundedProcessError::DeadlineElapsed);
    }
    let (tx, rx) = mpsc::sync_channel(1);
    let writer = handle.clone();
    let payload = data.to_vec();
    let worker = thread::Builder::new()
        .name("process-tool-write".to_string())
        .spawn(move || {
            let result = writer.write_stdin(&payload);
            let _ = tx.send(result);
        })
        .map_err(|_| BoundedProcessError::StdinWriteFailed { os_code: None })?;
    loop {
        if cancellation.is_cancelled() {
            return interrupt_write_worker(
                handle,
                worker,
                &rx,
                cleanup_timeout,
                BoundedProcessError::Cancelled,
            );
        }
        let now = Instant::now();
        if now >= action_deadline {
            return interrupt_write_worker(
                handle,
                worker,
                &rx,
                cleanup_timeout,
                BoundedProcessError::DeadlineElapsed,
            );
        }
        let slice = action_deadline
            .saturating_duration_since(now)
            .min(WRITE_POLL_SLICE);
        match rx.recv_timeout(slice) {
            Ok(result) => {
                let _ = worker.join();
                return result;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = worker.join();
                return Err(BoundedProcessError::StdinWriteFailed { os_code: None });
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

fn interrupt_write_worker(
    handle: &BoundedProcessHandle,
    worker: thread::JoinHandle<()>,
    rx: &mpsc::Receiver<Result<usize, BoundedProcessError>>,
    cleanup_timeout: Duration,
    interrupt: BoundedProcessError,
) -> Result<usize, BoundedProcessError> {
    let _ = handle.close_stdin();
    let outcome = match rx.recv_timeout(cleanup_timeout) {
        Ok(Ok(wrote)) => Ok(wrote),
        Ok(Err(_)) | Err(_) => Err(interrupt),
    };
    let _ = worker.join();
    outcome
}

fn map_handle_error(
    handle: &BoundedProcessHandle,
    error: BoundedProcessError,
    state: &ProcessExecutorState,
) -> ToolResult {
    let stdout = handle.stdout_snapshot();
    let stderr = handle.stderr_snapshot();
    let (code, message) = process_error_code(&error);
    assemble_process_result(
        state,
        handle.terminal_status(),
        &stdout,
        &stderr,
        false,
        Some((code, message)),
    )
}

pub(crate) fn process_error_code(error: &BoundedProcessError) -> (&'static str, String) {
    match error {
        BoundedProcessError::InvalidRequest(error) => validation_error_code(error),
        BoundedProcessError::Spawn(_) => ("spawn_failed", error.to_string()),
        BoundedProcessError::DeadlineElapsed => {
            ("deadline_elapsed", "process deadline elapsed".to_string())
        }
        BoundedProcessError::Cancelled => ("cancelled", "process was cancelled".to_string()),
        BoundedProcessError::StdinClosed => ("stdin_closed", "process stdin is closed".to_string()),
        BoundedProcessError::StdinTooLarge => (
            "invalid_stdin",
            "stdin exceeds the configured bound".to_string(),
        ),
        _ => ("spawn_failed", "process operation failed".to_string()),
    }
}

pub(crate) fn validation_error_code(error: &ProcessValidationError) -> (&'static str, String) {
    let code = match error {
        ProcessValidationError::EmptyArgv
        | ProcessValidationError::EmptyProgram
        | ProcessValidationError::ArgCountExceeded
        | ProcessValidationError::ArgContainsNul { .. }
        | ProcessValidationError::ArgItemTooLong { .. }
        | ProcessValidationError::ArgTotalTooLarge => "invalid_argv",
        ProcessValidationError::EmptyCwd
        | ProcessValidationError::CwdRequired
        | ProcessValidationError::CwdNotAbsolute
        | ProcessValidationError::CwdTooLong
        | ProcessValidationError::CwdContainsNul
        | ProcessValidationError::ConflictingCwd
        | ProcessValidationError::ConfinedCwdUnsupported => "invalid_cwd",
        ProcessValidationError::EnvCountExceeded
        | ProcessValidationError::InvalidEnvKey
        | ProcessValidationError::EnvKeyTooLong
        | ProcessValidationError::EnvValueContainsNul
        | ProcessValidationError::EnvValueTooLong
        | ProcessValidationError::EnvTotalTooLarge
        | ProcessValidationError::InheritEnvForbidden => "invalid_env",
        ProcessValidationError::StdinTooLarge => "invalid_stdin",
        ProcessValidationError::TimeoutMissing
        | ProcessValidationError::TimeoutNonPositive
        | ProcessValidationError::TimeoutTooLarge
        | ProcessValidationError::DeadlineElapsed
        | ProcessValidationError::DeadlineTooFar => "invalid_timeout",
        ProcessValidationError::OutputLimitNonPositive { .. }
        | ProcessValidationError::OutputLimitTooLarge { .. } => "invalid_output_limit",
    };
    (code, error.to_string())
}

fn assemble_process_result(
    state: &ProcessExecutorState,
    status: Option<ProcessStatus>,
    stdout: &LogSnapshot,
    stderr: &LogSnapshot,
    ok: bool,
    error: Option<(&str, String)>,
) -> ToolResult {
    let mut data = snapshot_data(stdout, stderr);
    insert_status(&mut data, status);
    let content = model_content(&stdout.bytes, &stderr.bytes);
    let truncated = stdout.truncated || stderr.truncated;
    let mut result = if let Some((code, message)) = error {
        ToolResult::failure_with(code, message, content, Value::Object(data), truncated)
    } else if ok {
        let mut result = ToolResult::success(content, Value::Object(data));
        result.truncated = truncated;
        result
    } else {
        ToolResult::failure_with(
            "spawn_failed",
            "process operation failed",
            content,
            Value::Object(data),
            truncated,
        )
    };
    apply_output_bounds(
        &mut result,
        &state.config,
        &state.owner,
        state.artifact_sink.as_deref(),
        &stdout.bytes,
        &stderr.bytes,
    );
    result
}

pub(crate) fn snapshot_data(stdout: &LogSnapshot, stderr: &LogSnapshot) -> Map<String, Value> {
    let mut data = Map::new();
    insert_snapshot_fields(&mut data, "stdout", stdout);
    insert_snapshot_fields(&mut data, "stderr", stderr);
    data
}

fn insert_snapshot_fields(data: &mut Map<String, Value>, prefix: &str, snapshot: &LogSnapshot) {
    data.insert(
        prefix.to_string(),
        json!(String::from_utf8_lossy(&snapshot.bytes)),
    );
    data.insert(format!("{prefix}_offset"), json!(snapshot.offset));
    data.insert(format!("{prefix}_next_offset"), json!(snapshot.next_offset));
    data.insert(format!("{prefix}_truncated"), json!(snapshot.truncated));
    data.insert(format!("{prefix}_gap"), json!(snapshot.gap));
    data.insert(format!("{prefix}_eof"), json!(snapshot.eof));
}

fn insert_status(data: &mut Map<String, Value>, status: Option<ProcessStatus>) {
    match status {
        None => {
            data.insert("status".into(), json!("running"));
        }
        Some(ProcessStatus::Exited { code }) => {
            data.insert("status".into(), json!("exited"));
            if let Some(code) = code {
                data.insert("exit_code".into(), json!(code));
            }
        }
        Some(ProcessStatus::Signaled { signal }) => {
            data.insert("status".into(), json!("signaled"));
            data.insert("signal".into(), json!(signal));
        }
        Some(ProcessStatus::Unknown) => {
            data.insert("status".into(), json!("unknown"));
        }
    }
}

pub(crate) fn model_content(stdout: &[u8], stderr: &[u8]) -> String {
    if stdout.is_empty() && !stderr.is_empty() {
        return String::from_utf8_lossy(stderr).into_owned();
    }
    String::from_utf8_lossy(stdout).into_owned()
}

pub(crate) fn apply_output_bounds(
    result: &mut ToolResult,
    config: &ProcessToolConfig,
    owner: &ProcessOwner,
    sink: Option<&dyn ProcessArtifactSink>,
    stdout: &[u8],
    stderr: &[u8],
) {
    let ring_truncated = result.truncated
        || result
            .data
            .get("stdout_truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || result
            .data
            .get("stderr_truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    result.truncated = ring_truncated;
    if serialized_tool_result_len(result) <= config.max_output_bytes {
        return;
    }

    result.truncated = true;
    let payload = overflow_artifact_payload(stdout, stderr, overflow_artifact_cap(config));
    if let Value::Object(data) = &mut result.data {
        data.insert("overflow_encoding".into(), json!("labeled-utf8"));
        data.insert("overflow_stdout_bytes".into(), json!(stdout.len() as u64));
        data.insert("overflow_stderr_bytes".into(), json!(stderr.len() as u64));
    }
    let stored_artifact = match sink.map(|sink| sink.store(owner, &payload)) {
        Some(Ok(id)) => {
            result.artifacts.push(id);
            compact_overflow_envelope(result);
            true
        }
        Some(Err(_)) | None => false,
    };
    if serialized_tool_result_len(result) <= config.max_output_bytes {
        return;
    }
    if !stored_artifact && let Value::Object(data) = &mut result.data {
        data.insert("overflow".into(), json!(true));
        data.insert("overflow_reason".into(), json!("artifact_unavailable"));
        data.insert("retained_bytes".into(), json!(payload.len() as u64));
    }
    enforce_serialized_tool_result_cap(result, config.max_output_bytes);
}

const STDOUT_OVERFLOW_LABEL: &str = "stdout:\n";
const STDERR_OVERFLOW_LABEL: &str = "stderr:\n";

fn compact_overflow_envelope(result: &mut ToolResult) {
    result.content.clear();
    if let Value::Object(data) = &mut result.data {
        data.insert("stdout".into(), json!(""));
        data.insert("stderr".into(), json!(""));
    }
}

fn overflow_artifact_cap(config: &ProcessToolConfig) -> usize {
    config
        .max_stream_bytes
        .saturating_mul(2)
        .saturating_add(STDOUT_OVERFLOW_LABEL.len() + STDERR_OVERFLOW_LABEL.len() + 2)
        .max(STDOUT_OVERFLOW_LABEL.len() + STDERR_OVERFLOW_LABEL.len() + 1)
}

pub(crate) fn overflow_artifact_payload(stdout: &[u8], stderr: &[u8], cap: usize) -> Vec<u8> {
    let cap = cap.max(STDOUT_OVERFLOW_LABEL.len() + STDERR_OVERFLOW_LABEL.len() + 1);
    let mut out = Vec::new();
    append_label_and_bytes(&mut out, STDOUT_OVERFLOW_LABEL, stdout, cap);
    if out.len() < cap {
        if !out.ends_with(b"\n") {
            out.push(b'\n');
        }
        append_label_and_bytes(&mut out, STDERR_OVERFLOW_LABEL, stderr, cap);
    }
    if out.len() > cap {
        out.truncate(cap);
        while !out.is_empty() && std::str::from_utf8(&out).is_err() {
            out.pop();
        }
    }
    out
}

fn append_label_and_bytes(out: &mut Vec<u8>, label: &str, bytes: &[u8], cap: usize) {
    if out.len() >= cap {
        return;
    }
    let room = cap - out.len();
    let take = label.len().min(room);
    out.extend_from_slice(&label.as_bytes()[..take]);
    if take < label.len() {
        return;
    }
    append_lossy_bounded(out, bytes, cap);
}

fn append_lossy_bounded(out: &mut Vec<u8>, bytes: &[u8], cap: usize) {
    if out.len() >= cap {
        return;
    }
    let room = cap - out.len();
    let lossy = String::from_utf8_lossy(bytes);
    let mut end = lossy.len().min(room);
    while end > 0 && !lossy.is_char_boundary(end) {
        end -= 1;
    }
    out.extend_from_slice(&lossy.as_bytes()[..end]);
}
