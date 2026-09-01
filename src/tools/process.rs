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

use super::{NativeToolExecutor, ToolDescriptor, ToolResult, builtin_descriptor};

const OWNER_FIELD_LIMIT: usize = 128;
const PROCESS_NOT_FOUND_MESSAGE: &str = "process not found";

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
    profile_id: String,
    session_id: String,
    run_id: String,
}

impl ProcessOwner {
    pub fn new(
        profile_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Result<Self, String> {
        Ok(Self {
            profile_id: validate_owner_field(profile_id.into(), "profile_id")?,
            session_id: validate_owner_field(session_id.into(), "session_id")?,
            run_id: validate_owner_field(run_id.into(), "run_id")?,
        })
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }
}

fn validate_owner_field(value: String, name: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    if value.contains('\0') {
        return Err(format!("{name} is invalid"));
    }
    if value.len() > OWNER_FIELD_LIMIT {
        return Err(format!("{name} exceeds the configured bound"));
    }
    Ok(value)
}

/// Optional overflow sink. Task 3 artifacts are not implemented here.
pub trait ProcessArtifactSink: Send + Sync {
    fn store(&self, owner: &ProcessOwner, bytes: &[u8]) -> Result<String, String>;
}

struct OwnedProcess {
    owner: ProcessOwner,
    process: BoundedProcess,
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
            Self::Profile(profile_id) => owner.profile_id == *profile_id,
            Self::Session {
                profile_id,
                session_id,
            } => owner.profile_id == *profile_id && owner.session_id == *session_id,
            Self::Run {
                profile_id,
                session_id,
                run_id,
            } => {
                owner.profile_id == *profile_id
                    && owner.session_id == *session_id
                    && owner.run_id == *run_id
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

    pub fn cleanup_owner(&self, owner: &ProcessOwner) -> Result<usize, String> {
        Ok(self.cleanup_scope(CleanupMask::Run {
            profile_id: owner.profile_id.clone(),
            session_id: owner.session_id.clone(),
            run_id: owner.run_id.clone(),
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
    ) -> Result<(CancellationToken, ForegroundGuard), ToolFailure> {
        let token = CancellationToken::new();
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
        state
            .processes
            .insert(id.clone(), OwnedProcess { owner, process });
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
        let taken = {
            let mut state = self.inner.lock();
            state.cleaning.push(mask.clone());
            for op in state.foreground.values() {
                if mask.matches(&op.owner) {
                    op.token.cancel();
                }
            }
            let ids: Vec<String> = state
                .processes
                .iter()
                .filter(|(_, entry)| mask.matches(&entry.owner))
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| state.processes.remove(&id))
                .collect::<Vec<_>>()
        };
        let count = taken.len();
        bounded_shutdown(
            taken.into_iter().map(|entry| entry.process).collect(),
            self.config.cleanup_timeout,
        );
        let mut state = self.inner.lock();
        for op in state.foreground.values() {
            if mask.matches(&op.owner) {
                op.token.cancel();
            }
        }
        if let Some(index) = state.cleaning.iter().rposition(|item| item == &mask) {
            state.cleaning.remove(index);
        }
        count
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
        match parse_process_request(arguments) {
            Ok(request) => self.run(request),
            Err(failure) => failure.into_result(),
        }
    }

    pub fn run(&self, request: ProcessRequest) -> ToolResult {
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
            ProcessAction::Wait => self.wait(&handle, request.timeout_ms),
            ProcessAction::Log => self.log(&handle, request.offset, request.limit),
            ProcessAction::Write => self.write(
                &handle,
                request.data.as_deref().unwrap_or(""),
                request.timeout_ms,
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

    fn wait(&self, handle: &BoundedProcessHandle, timeout_ms: Option<u64>) -> ToolResult {
        if let Some(timeout_ms) = timeout_ms
            && timeout_ms == 0
        {
            return ToolResult::failure("invalid_timeout", "timeout_ms must be positive");
        }
        let process_deadline = handle.deadline();
        let action_deadline = timeout_ms
            .map(|ms| Instant::now() + Duration::from_millis(ms))
            .unwrap_or(process_deadline);
        if action_deadline >= process_deadline {
            match handle.wait(None) {
                Ok(status) => self.view(handle, Some(status), true),
                Err(error) => map_handle_error(handle, error, &self.inner),
            }
        } else {
            loop {
                match handle.poll() {
                    Ok(Some(status)) => return self.view(handle, Some(status), true),
                    Ok(None) => {
                        if Instant::now() >= action_deadline {
                            return self.view(handle, None, true);
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return map_handle_error(handle, error, &self.inner),
                }
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
    ) -> ToolResult {
        if let Some(0) = timeout_ms {
            return ToolResult::failure("invalid_timeout", "timeout_ms must be positive");
        }
        match write_stdin_with_deadline(handle, data.as_bytes(), timeout_ms) {
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
    timeout_ms: Option<u64>,
) -> Result<usize, BoundedProcessError> {
    let process_deadline = handle.deadline();
    let action_deadline = timeout_ms
        .map(|ms| Instant::now() + Duration::from_millis(ms))
        .unwrap_or(process_deadline)
        .min(process_deadline);
    if Instant::now() >= action_deadline {
        return Err(BoundedProcessError::DeadlineElapsed);
    }
    if action_deadline >= process_deadline {
        return handle.write_stdin(data);
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
    let remaining = action_deadline.saturating_duration_since(Instant::now());
    match rx.recv_timeout(remaining) {
        Ok(result) => {
            let _ = worker.join();
            result
        }
        Err(_) => {
            let _ = handle.close_stdin();
            let _ = worker.join();
            Err(BoundedProcessError::DeadlineElapsed)
        }
    }
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
        | ProcessValidationError::CwdContainsNul => "invalid_cwd",
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
    retained: &[u8],
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
    if envelope_len(result) <= config.max_output_bytes {
        return;
    }

    result.truncated = true;
    let payload = if retained.is_empty() {
        result.content.as_bytes().to_vec()
    } else {
        retained.to_vec()
    };
    let stored_artifact = match sink.map(|sink| sink.store(owner, &payload)) {
        Some(Ok(id)) => {
            result.artifacts.push(id);
            true
        }
        Some(Err(_)) | None => false,
    };
    if envelope_len(result) <= config.max_output_bytes {
        return;
    }
    if !stored_artifact && let Value::Object(data) = &mut result.data {
        data.insert("overflow".into(), json!(true));
        data.insert("overflow_reason".into(), json!("artifact_unavailable"));
        data.insert("retained_bytes".into(), json!(payload.len() as u64));
    }
    if envelope_len(result) <= config.max_output_bytes {
        return;
    }
    shrink_envelope_to_cap(result, config.max_output_bytes);
}

fn envelope_len(result: &ToolResult) -> usize {
    serde_json::to_vec(result)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

fn stream_string(result: &ToolResult, key: &str) -> String {
    result
        .data
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn set_stream_string(result: &mut ToolResult, key: &str, value: String) {
    if let Value::Object(data) = &mut result.data
        && data.get(key).and_then(Value::as_str).is_some()
    {
        data.insert(key.to_string(), json!(value));
    }
}

fn clear_stream_strings(result: &mut ToolResult) {
    set_stream_string(result, "stdout", String::new());
    set_stream_string(result, "stderr", String::new());
}

fn allocate_payload_budget(
    budget: usize,
    content: &str,
    stdout: &str,
    stderr: &str,
) -> (usize, usize, usize) {
    let mut shares = 0usize;
    if !content.is_empty() {
        shares += 1;
    }
    if !stdout.is_empty() {
        shares += 1;
    }
    if !stderr.is_empty() {
        shares += 1;
    }
    let shares = shares.max(1);
    let each = budget / shares;
    let mut content_budget = if content.is_empty() {
        0
    } else {
        each.min(content.len())
    };
    let mut stdout_budget = if stdout.is_empty() {
        0
    } else {
        each.min(stdout.len())
    };
    let mut stderr_budget = if stderr.is_empty() {
        0
    } else {
        each.min(stderr.len())
    };
    let mut leftover = budget.saturating_sub(content_budget + stdout_budget + stderr_budget);
    for (slot, source) in [
        (&mut content_budget, content),
        (&mut stdout_budget, stdout),
        (&mut stderr_budget, stderr),
    ] {
        let extra = source.len().saturating_sub(*slot).min(leftover);
        *slot += extra;
        leftover -= extra;
    }
    (content_budget, stdout_budget, stderr_budget)
}

fn shrink_envelope_to_cap(result: &mut ToolResult, cap: usize) {
    let original_content = result.content.clone();
    let original_stdout = stream_string(result, "stdout");
    let original_stderr = stream_string(result, "stderr");

    let mut skeleton = result.clone();
    skeleton.content.clear();
    clear_stream_strings(&mut skeleton);
    let skeleton_len = envelope_len(&skeleton);
    if skeleton_len > cap {
        *result = minimal_bounded_error(cap);
        return;
    }

    let mut budget = cap.saturating_sub(skeleton_len);
    loop {
        let (content_budget, stdout_budget, stderr_budget) = allocate_payload_budget(
            budget,
            &original_content,
            &original_stdout,
            &original_stderr,
        );
        result.content = truncate_to_bytes(&original_content, content_budget);
        let stdout = truncate_to_bytes(&original_stdout, stdout_budget);
        let stderr = truncate_to_bytes(&original_stderr, stderr_budget);
        if stdout.len() < original_stdout.len()
            && let Value::Object(data) = &mut result.data
        {
            data.insert("stdout_truncated".into(), json!(true));
        }
        if stderr.len() < original_stderr.len()
            && let Value::Object(data) = &mut result.data
        {
            data.insert("stderr_truncated".into(), json!(true));
        }
        set_stream_string(result, "stdout", stdout);
        set_stream_string(result, "stderr", stderr);
        result.truncated = true;
        if envelope_len(result) <= cap {
            return;
        }
        if budget == 0 {
            *result = minimal_bounded_error(cap);
            return;
        }
        budget /= 2;
    }
}

fn minimal_bounded_error(cap: usize) -> ToolResult {
    for message in ["tool result exceeds the configured bound", "bounded", ""] {
        let candidate =
            ToolResult::failure_with("output_truncated", message, String::new(), json!({}), true);
        if envelope_len(&candidate) <= cap {
            return candidate;
        }
    }
    ToolResult::failure_with("output_truncated", "", String::new(), json!({}), true)
}

fn truncate_to_bytes(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}
