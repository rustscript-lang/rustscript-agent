//! Validated serial dispatch for native coding/process tools.
//!
//! Lookup and JSON Schema validation happen against the admitted registry
//! snapshot before any executor effect. Tool lifecycle events are committed
//! durably in order, and a failed append before `tool.started` prevents the
//! effect. A failed `tool.output` append after the effect stops publication
//! and returns `event_persist_failed` without retrying. Durable payloads keep
//! only bounded metadata; model-facing `ToolResult` stays complete but
//! bounded. One dispatcher serializes every native slot; panics at the
//! injectable executor boundary become typed failures. Terminal and process
//! calls receive a linked per-call token because core process `Drop` cancels
//! the token it holds; a bounded RAII watcher relays run/stop cancellation
//! onto that child and joins before returning. File calls use the run token
//! directly. Dropping the child never cancels the parent.

use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rustscript_vm::CancellationToken;
use serde_json::{Value, json};

use super::files::FileTools;
use super::process::ProcessExecutor;
use super::registry::{MAX_TOOL_NAME_BYTES, ToolRegistrySnapshot};
use super::terminal::TerminalExecutor;
use super::types::NativeToolExecutor;
use super::{
    ToolOwner, ToolResult, enforce_serialized_tool_result_cap, serialized_tool_result_len,
};
use crate::domain::ToolCall;

const MAX_EVENT_ID_BYTES: usize = 128;

/// Run-scoped output and call ceilings applied by the dispatcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchLimits {
    pub max_tool_calls: u64,
    pub max_tool_output_bytes: usize,
    pub max_event_bytes: usize,
}

/// Failure from the durable event committer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventCommitError {
    Terminal,
    PersistFailed(String),
}

/// Durable-first event sink used by dispatch. Implementations must not publish
/// after the run has committed a terminal state.
pub trait DurableEventCommitter: Send + Sync {
    fn is_terminal(&self) -> bool;
    fn stop_requested(&self) -> bool {
        false
    }
    fn commit(&self, event_type: &str, data: Value) -> Result<(), EventCommitError>;
}

/// Injectable native executor boundary. Production code uses
/// [`NativeExecutionDeps`]; tests inject counting/panic/blocking fakes.
pub trait ToolExecutorBoundary: Send + Sync {
    fn execute(
        &self,
        executor: &NativeToolExecutor,
        arguments: &Value,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> ToolResult;
}

/// Concrete native file/terminal/process dependencies sharing one owner,
/// workspace, cancellation/deadline pair, and artifact sink.
#[derive(Clone)]
pub struct NativeExecutionDeps {
    pub files: FileTools,
    pub terminal: TerminalExecutor,
    pub process: ProcessExecutor,
}

impl ToolExecutorBoundary for NativeExecutionDeps {
    fn execute(
        &self,
        executor: &NativeToolExecutor,
        arguments: &Value,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> ToolResult {
        match executor {
            NativeToolExecutor::ReadFile
            | NativeToolExecutor::SearchFiles
            | NativeToolExecutor::WriteFile
            | NativeToolExecutor::Patch => {
                self.files
                    .execute_with_controls(executor, arguments, cancellation, deadline)
            }
            NativeToolExecutor::Terminal => {
                self.terminal
                    .execute_with_controls(arguments, cancellation, deadline)
            }
            NativeToolExecutor::Process => {
                self.process
                    .execute_with_controls(arguments, cancellation, deadline)
            }
            NativeToolExecutor::Placeholder(name) => {
                ToolResult::failure("unknown_tool", format!("unknown tool: {name}"))
            }
        }
    }
}

/// Poll interval for the parent→child cancellation relay. The watcher is
/// joined on drop, so this also bounds how long Drop waits without unpark.
const LINKED_CANCEL_POLL: Duration = Duration::from_millis(5);

/// Isolated child token plus a bounded watcher that copies parent/stop
/// cancellation onto the child. Core `BoundedProcess` Drop cancels whatever
/// token it holds; this child exists so that drop cannot cancel the run.
struct LinkedCancellation {
    child: CancellationToken,
    stop: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
}

impl LinkedCancellation {
    fn watch(
        parent: &CancellationToken,
        events: &Arc<dyn DurableEventCommitter>,
        fail_spawn: bool,
    ) -> Result<Self, ()> {
        let child = CancellationToken::new();
        if parent.is_cancelled() || events.stop_requested() {
            child.cancel();
            return Ok(Self {
                child,
                stop: Arc::new(AtomicBool::new(true)),
                watcher: None,
            });
        }
        if fail_spawn {
            child.cancel();
            return Err(());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let parent = parent.clone();
        let child_watch = child.clone();
        let events = Arc::clone(events);
        let stop_watch = Arc::clone(&stop);
        match thread::Builder::new()
            .name("tool-cancel-link".to_string())
            .spawn(move || {
                while !stop_watch.load(Ordering::Acquire) {
                    if parent.is_cancelled() || events.stop_requested() {
                        child_watch.cancel();
                        return;
                    }
                    thread::park_timeout(LINKED_CANCEL_POLL);
                }
            }) {
            Ok(handle) => Ok(Self {
                child,
                stop,
                watcher: Some(handle),
            }),
            Err(_) => {
                child.cancel();
                Err(())
            }
        }
    }

    fn token(&self) -> &CancellationToken {
        &self.child
    }
}

impl Drop for LinkedCancellation {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.watcher.take() {
            handle.thread().unpark();
            let _ = handle.join();
        }
    }
}

fn isolates_process_token(executor: &NativeToolExecutor) -> bool {
    matches!(
        executor,
        NativeToolExecutor::Terminal | NativeToolExecutor::Process
    )
}

struct DispatchInner {
    owner: ToolOwner,
    workspace: PathBuf,
    cancellation: CancellationToken,
    deadline: Instant,
    registry: ToolRegistrySnapshot,
    registry_identity: String,
    toolset_hash: String,
    limits: DispatchLimits,
    events: Arc<dyn DurableEventCommitter>,
    executor: Arc<dyn ToolExecutorBoundary>,
    call_count: AtomicU64,
    serial: Mutex<()>,
    fail_linked_spawn: AtomicBool,
}

/// Serial dispatcher bound to one admitted run snapshot.
#[derive(Clone)]
pub struct DispatchContext {
    inner: Arc<DispatchInner>,
}

impl DispatchContext {
    /// Builds a dispatcher from an admitted snapshot and concrete dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner: ToolOwner,
        workspace: PathBuf,
        cancellation: CancellationToken,
        deadline: Instant,
        registry: ToolRegistrySnapshot,
        registry_identity: String,
        toolset_hash: String,
        limits: DispatchLimits,
        events: Arc<dyn DurableEventCommitter>,
        executor: Arc<dyn ToolExecutorBoundary>,
    ) -> Result<Self, String> {
        if registry_identity.is_empty() || toolset_hash.is_empty() {
            return Err("admitted registry identity must not be empty".to_string());
        }
        if limits.max_tool_calls == 0
            || limits.max_tool_output_bytes == 0
            || limits.max_event_bytes == 0
        {
            return Err("dispatch limits must be positive".to_string());
        }
        let _ = &owner;
        Ok(Self {
            inner: Arc::new(DispatchInner {
                owner,
                workspace,
                cancellation,
                deadline,
                registry,
                registry_identity,
                toolset_hash,
                limits,
                events,
                executor,
                call_count: AtomicU64::new(0),
                serial: Mutex::new(()),
                fail_linked_spawn: AtomicBool::new(false),
            }),
        })
    }

    /// Test failpoint: the next linked watcher spawn fails closed.
    pub fn inject_linked_spawn_failure(&self) {
        self.inner.fail_linked_spawn.store(true, Ordering::SeqCst);
    }

    /// Run-scoped cancellation token retained by this dispatcher.
    pub fn cancellation(&self) -> &CancellationToken {
        &self.inner.cancellation
    }

    /// Owner bound to this dispatcher.
    pub fn owner(&self) -> &ToolOwner {
        &self.inner.owner
    }

    /// Canonical workspace retained at construction.
    pub fn workspace(&self) -> &std::path::Path {
        &self.inner.workspace
    }

    /// Executes `calls` in the given order. Effects never overlap.
    pub fn dispatch(&self, calls: &[ToolCall]) -> Vec<ToolResult> {
        let _guard = self.inner.serial.lock();
        calls
            .iter()
            .map(|call| self.dispatch_one_locked(call))
            .collect()
    }

    /// Executes one tool call. Concurrent callers are serialized.
    pub fn dispatch_one(&self, call: &ToolCall) -> ToolResult {
        let _guard = self.inner.serial.lock();
        self.dispatch_one_locked(call)
    }

    fn dispatch_one_locked(&self, call: &ToolCall) -> ToolResult {
        if let Some(result) = self.gate_before_publication() {
            return result;
        }
        let used = self.inner.call_count.fetch_add(1, Ordering::SeqCst);
        if used >= self.inner.limits.max_tool_calls {
            let ordinal = used + 1;
            let result = ToolResult::failure("max_tool_calls", "max_tool_calls exceeded");
            if let Some(entry) = self.inner.registry.entry(&call.name) {
                self.publish_validation_failure(
                    call,
                    ordinal,
                    entry.executor().tool_name(),
                    Some(entry.descriptor().risk_class.as_str()),
                    &result,
                );
            } else {
                self.publish_validation_failure(call, ordinal, "unknown", None, &result);
            }
            return result;
        }
        let ordinal = used + 1;

        let Some(entry) = self.inner.registry.entry(&call.name) else {
            let result = unknown_tool_result(&call.name);
            self.publish_validation_failure(call, ordinal, "unknown", None, &result);
            return result;
        };
        let executor_name = entry.executor().tool_name();
        let risk = entry.descriptor().risk_class.as_str();
        if let Err(reason) = self
            .inner
            .registry
            .validate_arguments(&call.name, &call.arguments)
        {
            let result = ToolResult::failure("invalid_arguments", reason);
            self.publish_validation_failure(call, ordinal, executor_name, Some(risk), &result);
            return result;
        }

        if let Err(error) = self.commit(
            "tool.requested",
            self.lifecycle_payload(call, ordinal, executor_name, Some(risk), "requested", None),
        ) {
            return pre_effect_commit_failure(error);
        }
        if let Some(result) = self.gate_before_effect() {
            if !self.inner.events.is_terminal() {
                let _ = self.commit(
                    "tool.failed",
                    self.lifecycle_payload(
                        call,
                        ordinal,
                        executor_name,
                        Some(risk),
                        "failed",
                        Some(&result),
                    ),
                );
            }
            return result;
        }
        if let Err(error) = self.commit(
            "tool.started",
            self.lifecycle_payload(call, ordinal, executor_name, Some(risk), "started", None),
        ) {
            return pre_effect_commit_failure(error);
        }

        let executed = panic::catch_unwind(AssertUnwindSafe(|| {
            self.execute_native(entry.executor(), &call.arguments)
        }));
        let mut result = match executed {
            Ok(result) => result,
            Err(_) => ToolResult::failure("executor_panic", "native executor panicked"),
        };
        enforce_serialized_tool_result_cap(&mut result, self.inner.limits.max_tool_output_bytes);

        if self.inner.events.is_terminal() {
            return result;
        }
        match self.commit(
            "tool.output",
            self.lifecycle_payload(
                call,
                ordinal,
                executor_name,
                Some(risk),
                "output",
                Some(&result),
            ),
        ) {
            Ok(()) => {}
            Err(EventCommitError::Terminal) => return result,
            Err(EventCommitError::PersistFailed(_)) => return persist_failed_result(),
        }
        if self.inner.events.is_terminal() {
            return result;
        }
        let (event_type, status) = if result.ok {
            ("tool.completed", "completed")
        } else {
            ("tool.failed", "failed")
        };
        match self.commit(
            event_type,
            self.lifecycle_payload(
                call,
                ordinal,
                executor_name,
                Some(risk),
                status,
                Some(&result),
            ),
        ) {
            Ok(()) => result,
            Err(EventCommitError::Terminal) => result,
            Err(EventCommitError::PersistFailed(_)) => persist_failed_result(),
        }
    }

    fn execute_native(&self, executor: &NativeToolExecutor, arguments: &Value) -> ToolResult {
        if isolates_process_token(executor) {
            let fail_spawn = self.inner.fail_linked_spawn.swap(false, Ordering::SeqCst);
            let linked = match LinkedCancellation::watch(
                &self.inner.cancellation,
                &self.inner.events,
                fail_spawn,
            ) {
                Ok(linked) => linked,
                Err(()) => return cancellation_unavailable_result(),
            };
            self.inner
                .executor
                .execute(executor, arguments, linked.token(), self.inner.deadline)
        } else {
            self.inner.executor.execute(
                executor,
                arguments,
                &self.inner.cancellation,
                self.inner.deadline,
            )
        }
    }

    fn gate_before_publication(&self) -> Option<ToolResult> {
        self.control_failure()
    }

    fn gate_before_effect(&self) -> Option<ToolResult> {
        self.control_failure()
    }

    fn control_failure(&self) -> Option<ToolResult> {
        if self.inner.events.is_terminal() {
            return Some(ToolResult::failure(
                "cancelled",
                "run already committed a terminal state",
            ));
        }
        if self.inner.events.stop_requested() || self.inner.cancellation.is_cancelled() {
            return Some(ToolResult::failure(
                "cancelled",
                "tool execution was cancelled",
            ));
        }
        if Instant::now() >= self.inner.deadline {
            self.inner.cancellation.cancel();
            return Some(ToolResult::failure(
                "deadline_elapsed",
                "tool deadline elapsed",
            ));
        }
        if self.inner.registry.identity() != self.inner.registry_identity
            || self.inner.registry.identity() != self.inner.toolset_hash
        {
            return Some(ToolResult::failure(
                "registry_mismatch",
                "admitted registry identity does not match the frozen snapshot",
            ));
        }
        None
    }

    fn publish_validation_failure(
        &self,
        call: &ToolCall,
        ordinal: u64,
        executor: &str,
        risk: Option<&str>,
        result: &ToolResult,
    ) {
        if self.inner.events.is_terminal() {
            return;
        }
        if self
            .commit(
                "tool.requested",
                self.lifecycle_payload(call, ordinal, executor, risk, "requested", None),
            )
            .is_err()
        {
            return;
        }
        if self.inner.events.is_terminal() {
            return;
        }
        let _ = self.commit(
            "tool.failed",
            self.lifecycle_payload(call, ordinal, executor, risk, "failed", Some(result)),
        );
    }

    fn lifecycle_payload(
        &self,
        call: &ToolCall,
        ordinal: u64,
        executor: &str,
        risk: Option<&str>,
        status: &str,
        result: Option<&ToolResult>,
    ) -> Value {
        lifecycle_data(
            call,
            ordinal,
            executor,
            risk,
            status,
            result,
            self.inner.limits.max_event_bytes,
        )
    }

    fn commit(&self, event_type: &str, data: Value) -> Result<(), EventCommitError> {
        if self.inner.events.is_terminal() {
            return Err(EventCommitError::Terminal);
        }
        self.inner.events.commit(event_type, data)
    }
}

fn unknown_tool_result(name: &str) -> ToolResult {
    let bounded = truncate_utf8(name, MAX_TOOL_NAME_BYTES);
    ToolResult::failure("unknown_tool", format!("unknown tool: {bounded}"))
}

fn persist_failed_result() -> ToolResult {
    ToolResult::failure("event_persist_failed", "durable event commit failed")
}

fn cancellation_unavailable_result() -> ToolResult {
    ToolResult::failure(
        "cancellation_unavailable",
        "linked cancellation watcher is unavailable",
    )
}

fn pre_effect_commit_failure(error: EventCommitError) -> ToolResult {
    match error {
        EventCommitError::PersistFailed(_) => persist_failed_result(),
        EventCommitError::Terminal => {
            ToolResult::failure("cancelled", "run already committed a terminal state")
        }
    }
}

fn lifecycle_data(
    call: &ToolCall,
    ordinal: u64,
    executor: &str,
    risk: Option<&str>,
    status: &str,
    result: Option<&ToolResult>,
    cap: usize,
) -> Value {
    let name = truncate_utf8(&call.name, MAX_TOOL_NAME_BYTES);
    let id = truncate_utf8(&call.id, MAX_EVENT_ID_BYTES);
    let executor = truncate_utf8(executor, MAX_TOOL_NAME_BYTES);
    let mut data = json!({
        "tool_call_id": id.clone(),
        "tool_call": { "id": id, "name": name.clone() },
        "name": name,
        "ordinal": ordinal,
        "executor": executor,
        "status": status,
        "argument_bytes": encoded_len(&call.arguments),
    });
    if let Some(risk) = risk {
        data["risk"] = json!(truncate_utf8(risk, MAX_TOOL_NAME_BYTES));
    }
    if let Some(result) = result {
        data["ok"] = json!(result.ok);
        data["truncated"] = json!(result.truncated);
        data["result_bytes"] = json!(serialized_tool_result_len(result));
        if let Some(error) = &result.error {
            data["error_code"] = json!(truncate_utf8(&error.code, MAX_TOOL_NAME_BYTES));
        }
        if !result.artifacts.is_empty() {
            let artifacts: Vec<String> = result
                .artifacts
                .iter()
                .map(|artifact| truncate_utf8(artifact, MAX_EVENT_ID_BYTES))
                .collect();
            data["artifacts"] = json!(artifacts);
        }
    }
    bound_event(data, cap)
}

fn bound_event(data: Value, cap: usize) -> Value {
    if encoded_len(&data) <= cap {
        return data;
    }
    let stub = json!({
        "tool_call_id": data.get("tool_call_id").cloned().unwrap_or(json!("")),
        "status": data.get("status").cloned().unwrap_or(json!("truncated")),
        "truncated": true,
    });
    if encoded_len(&stub) <= cap {
        return stub;
    }
    json!({"truncated": true})
}

fn encoded_len(value: &Value) -> usize {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

fn truncate_utf8(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}
