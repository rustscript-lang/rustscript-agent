use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustscript_vm::{
    BoundedExecError, BoundedExecOutput, BoundedProcess, BoundedProcessRequest, CancellationToken,
    ConfinedFsRoot, LogSnapshot, ProcessStatus, exec_bounded,
};
use serde_json::{Map, Value, json};

use crate::config::ProcessToolConfig;

use super::process::{
    ProcessArtifactSink, ProcessExecutorState, ProcessOwner, ProcessTable, ToolFailure,
    apply_output_bounds, model_content, no_controls_deadline, optional_positive_u64,
    process_error_code, snapshot_data,
};
use super::{NativeToolExecutor, ToolDescriptor, ToolResult, builtin_descriptor};

/// Typed terminal request. `argv` is executed directly; no shell string exists.
#[derive(Clone, Debug, Default)]
pub struct TerminalRequest {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    pub stdin: Option<Vec<u8>>,
    pub timeout_ms: Option<u64>,
    pub deadline: Option<Instant>,
    pub max_output_bytes: Option<u64>,
    pub background: bool,
}

/// Native executor for the `terminal` slot.
#[derive(Clone)]
pub struct TerminalExecutor {
    inner: Arc<ProcessExecutorState>,
    root: Arc<ConfinedFsRoot>,
}

impl TerminalExecutor {
    pub fn new(
        config: ProcessToolConfig,
        table: Arc<ProcessTable>,
        owner: ProcessOwner,
    ) -> Result<Self, String> {
        let config = config.validated()?;
        let root = ConfinedFsRoot::new(&config.workspace_root)
            .map_err(|error| error.message().to_string())?;
        Ok(Self {
            inner: Arc::new(ProcessExecutorState {
                config,
                table,
                owner,
                artifact_sink: None,
            }),
            root: Arc::new(root),
        })
    }

    pub fn with_artifact_sink(&self, sink: Arc<dyn ProcessArtifactSink>) -> Self {
        Self {
            inner: Arc::new(ProcessExecutorState {
                artifact_sink: Some(sink),
                ..(*self.inner).clone()
            }),
            root: Arc::clone(&self.root),
        }
    }

    pub fn slot(&self) -> NativeToolExecutor {
        NativeToolExecutor::Terminal
    }

    pub fn descriptor(&self) -> ToolDescriptor {
        builtin_descriptor("terminal")
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
        match parse_terminal_request(arguments) {
            Ok(request) => self.run_with_controls(request, cancellation, deadline),
            Err(failure) => failure.into_result(),
        }
    }

    pub fn run(&self, request: TerminalRequest) -> ToolResult {
        let deadline = request
            .deadline
            .unwrap_or_else(|| no_controls_deadline(&self.inner.config));
        self.run_with_controls(request, &CancellationToken::new(), deadline)
    }

    pub fn run_with_controls(
        &self,
        request: TerminalRequest,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> ToolResult {
        if cancellation.is_cancelled() {
            return ToolResult::failure("cancelled", "process was cancelled");
        }
        if Instant::now() >= deadline {
            return ToolResult::failure("deadline_elapsed", "process deadline elapsed");
        }
        let prepared = match self.prepare(request, cancellation.clone(), deadline) {
            Ok(prepared) => prepared,
            Err(failure) => return failure.into_result(),
        };
        if prepared.background {
            self.spawn_background(prepared)
        } else {
            self.run_foreground(prepared, cancellation.clone())
        }
    }

    fn prepare(
        &self,
        request: TerminalRequest,
        token: CancellationToken,
        deadline: Instant,
    ) -> Result<PreparedRequest, ToolFailure> {
        if request.argv.is_empty() {
            return Err(ToolFailure::new(
                "invalid_argv",
                "argv must be a non-empty string array",
            ));
        }
        let timeout = resolve_timeout(&self.inner.config, request.timeout_ms)?;
        let stream_limit = resolve_stream_limit(&self.inner.config, request.max_output_bytes)?;
        if let Some(stdin) = request.stdin.as_ref()
            && stdin.len() > self.inner.config.max_stdin_bytes
        {
            return Err(ToolFailure::new(
                "invalid_stdin",
                "stdin exceeds the configured bound",
            ));
        }
        let directory = self
            .root
            .open_directory(request.cwd.as_deref().unwrap_or(""))
            .map_err(|_| invalid_cwd())?;
        if Instant::now() >= deadline {
            return Err(ToolFailure::new(
                "deadline_elapsed",
                "process deadline elapsed",
            ));
        }
        let mut core = BoundedProcessRequest::new(request.argv)
            .with_confined_cwd(directory)
            .with_env_map(request.env)
            .with_timeout(timeout)
            .with_output_limits(stream_limit, stream_limit, stream_limit)
            .with_cancellation_token(token)
            .with_deadline(deadline);
        if let Some(stdin) = request.stdin {
            core = core.with_stdin(stdin);
        }
        Ok(PreparedRequest {
            core,
            background: request.background,
        })
    }

    fn run_foreground(
        &self,
        mut prepared: PreparedRequest,
        token: CancellationToken,
    ) -> ToolResult {
        let (token, _guard) =
            match ProcessTable::register_foreground(&self.inner.table, &self.inner.owner, token) {
                Ok(registered) => registered,
                Err(failure) => return failure.into_result(),
            };
        prepared.core = prepared.core.with_cancellation_token(token);
        match exec_bounded(prepared.core) {
            Ok(output) => self.foreground_result(output, true, None),
            Err(BoundedExecError::TimedOut(output)) => self.foreground_result(
                output,
                false,
                Some(("deadline_elapsed", "process deadline elapsed".to_string())),
            ),
            Err(BoundedExecError::Cancelled(output)) => self.foreground_result(
                output,
                false,
                Some(("cancelled", "process was cancelled".to_string())),
            ),
            Err(BoundedExecError::Spawn(error) | BoundedExecError::Failed(error)) => {
                let (code, message) = process_error_code(&error);
                ToolResult::failure(code, message)
            }
        }
    }

    fn spawn_background(&self, prepared: PreparedRequest) -> ToolResult {
        let process = match BoundedProcess::spawn(prepared.core) {
            Ok(process) => process,
            Err(error) => {
                let (code, message) = process_error_code(&error);
                return ToolResult::failure(code, message);
            }
        };
        match self.inner.table.insert(self.inner.owner.clone(), process) {
            Ok(process_id) => ToolResult::success(
                String::new(),
                json!({
                    "background": true,
                    "process_id": process_id,
                    "status": "running",
                }),
            ),
            Err(failure) => failure.into_result(),
        }
    }

    fn foreground_result(
        &self,
        output: BoundedExecOutput,
        ok: bool,
        error: Option<(&str, String)>,
    ) -> ToolResult {
        let stdout = LogSnapshot {
            bytes: output.stdout,
            offset: output.stdout_offset,
            next_offset: output.stdout_next_offset,
            truncated: output.stdout_truncated,
            gap: output.stdout_gap,
            eof: true,
        };
        let stderr = LogSnapshot {
            bytes: output.stderr,
            offset: output.stderr_offset,
            next_offset: output.stderr_next_offset,
            truncated: output.stderr_truncated,
            gap: output.stderr_gap,
            eof: true,
        };
        let mut data = snapshot_data(&stdout, &stderr);
        insert_exit_status(&mut data, output.status);
        data.insert("background".into(), json!(false));
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
            &self.inner.config,
            &self.inner.owner,
            self.inner.artifact_sink.as_deref(),
            &stdout.bytes,
            &stderr.bytes,
        );
        result
    }
}

struct PreparedRequest {
    core: BoundedProcessRequest,
    background: bool,
}

fn parse_terminal_request(arguments: &Value) -> Result<TerminalRequest, ToolFailure> {
    let Some(items) = arguments.get("argv").and_then(Value::as_array) else {
        return Err(ToolFailure::new(
            "invalid_argv",
            "argv must be a non-empty string array",
        ));
    };
    let mut argv = Vec::with_capacity(items.len());
    for item in items {
        let Some(text) = item.as_str() else {
            return Err(ToolFailure::new(
                "invalid_argv",
                "argv must be a non-empty string array",
            ));
        };
        argv.push(text.to_string());
    }
    if argv.is_empty() {
        return Err(ToolFailure::new(
            "invalid_argv",
            "argv must be a non-empty string array",
        ));
    }
    let stdin = match arguments.get("stdin") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.as_bytes().to_vec()),
        Some(_) => {
            return Err(ToolFailure::new("invalid_stdin", "stdin must be a string"));
        }
    };
    Ok(TerminalRequest {
        argv,
        cwd: arguments
            .get("cwd")
            .and_then(Value::as_str)
            .map(str::to_string),
        env: BTreeMap::new(),
        stdin,
        timeout_ms: optional_positive_u64(arguments, "timeout_ms", "invalid_timeout")?,
        max_output_bytes: optional_positive_u64(
            arguments,
            "max_output_bytes",
            "invalid_output_limit",
        )?,
        background: arguments
            .get("background")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        ..TerminalRequest::default()
    })
}

fn resolve_timeout(
    config: &ProcessToolConfig,
    timeout_ms: Option<u64>,
) -> Result<Duration, ToolFailure> {
    let timeout = match timeout_ms {
        Some(0) => {
            return Err(ToolFailure::new(
                "invalid_timeout",
                "timeout_ms must be positive",
            ));
        }
        Some(ms) => Duration::from_millis(ms),
        None => config.default_timeout,
    };
    if timeout.is_zero() || timeout > config.max_timeout {
        return Err(ToolFailure::new(
            "invalid_timeout",
            "timeout exceeds the configured bound",
        ));
    }
    Ok(timeout)
}

fn resolve_stream_limit(
    config: &ProcessToolConfig,
    max_output_bytes: Option<u64>,
) -> Result<usize, ToolFailure> {
    match max_output_bytes {
        None => Ok(config.max_stream_bytes),
        Some(0) => Err(ToolFailure::new(
            "invalid_output_limit",
            "max_output_bytes must be positive",
        )),
        Some(value) => {
            let value = usize::try_from(value).unwrap_or(usize::MAX);
            if value > config.max_stream_bytes {
                Err(ToolFailure::new(
                    "invalid_output_limit",
                    "max_output_bytes exceeds the configured bound",
                ))
            } else {
                Ok(value)
            }
        }
    }
}

fn invalid_cwd() -> ToolFailure {
    ToolFailure::new("invalid_cwd", "cwd is outside the workspace")
}

fn insert_exit_status(data: &mut Map<String, Value>, status: ProcessStatus) {
    match status {
        ProcessStatus::Exited { code } => {
            data.insert("status".into(), json!("exited"));
            if let Some(code) = code {
                data.insert("exit_code".into(), json!(code));
            }
        }
        ProcessStatus::Signaled { signal } => {
            data.insert("status".into(), json!("signaled"));
            data.insert("signal".into(), json!(signal));
        }
        ProcessStatus::Unknown => {
            data.insert("status".into(), json!("unknown"));
        }
    }
}
