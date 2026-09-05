//! Bounded, low-overhead metrics registry with Prometheus text rendering.
//!
//! Every label comes from a finite enum: admission rejection reasons, run
//! terminal statuses, typed storage commands, and terminal retry outcomes.
//! No run/session/token/model original value is ever a label, and the label
//! space cannot grow with workload. Counters and gauges are atomics
//! (relaxed ordering); the run-duration histogram uses fixed buckets so
//! memory is constant. The scrape path only reads atomics — it never takes
//! the store lock.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Finite admission rejection reasons, mirroring the `AdmitError` variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum AdmitRejectReason {
    RunLimitReached = 0,
    IdempotencyConflict = 1,
    ParentNotFound = 2,
    SessionNotFound = 3,
    Persistence = 4,
    Invalid = 5,
    /// Admission rejected because the gateway is halting (SIGINT path):
    /// no new work can start after shutdown begins.
    Halting = 6,
}

impl AdmitRejectReason {
    pub const ALL: [Self; 7] = [
        Self::RunLimitReached,
        Self::IdempotencyConflict,
        Self::ParentNotFound,
        Self::SessionNotFound,
        Self::Persistence,
        Self::Invalid,
        Self::Halting,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::RunLimitReached => "run_limit_reached",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::ParentNotFound => "parent_not_found",
            Self::SessionNotFound => "session_not_found",
            Self::Persistence => "persistence",
            Self::Invalid => "invalid",
            Self::Halting => "halting",
        }
    }
}

/// Finite run terminal statuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum TerminalStatus {
    Completed = 0,
    Cancelled = 1,
    Failed = 2,
}

impl TerminalStatus {
    pub const ALL: [Self; 3] = [Self::Completed, Self::Cancelled, Self::Failed];

    pub fn label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}

/// The closed set of typed storage commands; any other command collapses to
/// `Unknown` so the label space stays bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum StorageOp {
    AdmissionCreate = 0,
    SessionCreate = 1,
    SessionTouch = 2,
    SessionDelete = 3,
    MessageAppend = 4,
    EventAppend = 5,
    RunTerminal = 6,
    RunTransition = 7,
    RunGet = 8,
    EventReplay = 9,
    JobCreate = 10,
    JobUpdate = 11,
    JobDelete = 12,
    ApprovalRequest = 13,
    ApprovalGet = 14,
    ApprovalResolve = 15,
    ApprovalExpire = 16,
    CompactionStart = 17,
    CompactionGet = 18,
    CompactionLatest = 19,
    CompactionCommit = 20,
    CompactionFail = 21,
    Migrate = 22,
    RecoveryRecoverActive = 23,
    LoadAll = 24,
    SessionGet = 25,
    DeliveryGet = 26,
    DeliveryAdvance = 27,
    DeliverySet = 28,
    Unknown = 29,
}

impl StorageOp {
    pub const ALL: [Self; 30] = [
        Self::AdmissionCreate,
        Self::SessionCreate,
        Self::SessionTouch,
        Self::SessionDelete,
        Self::MessageAppend,
        Self::EventAppend,
        Self::RunTerminal,
        Self::RunTransition,
        Self::RunGet,
        Self::EventReplay,
        Self::JobCreate,
        Self::JobUpdate,
        Self::JobDelete,
        Self::ApprovalRequest,
        Self::ApprovalGet,
        Self::ApprovalResolve,
        Self::ApprovalExpire,
        Self::CompactionStart,
        Self::CompactionGet,
        Self::CompactionLatest,
        Self::CompactionCommit,
        Self::CompactionFail,
        Self::Migrate,
        Self::RecoveryRecoverActive,
        Self::LoadAll,
        Self::SessionGet,
        Self::DeliveryGet,
        Self::DeliveryAdvance,
        Self::DeliverySet,
        Self::Unknown,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::AdmissionCreate => "admission.create",
            Self::SessionCreate => "session.create",
            Self::SessionTouch => "session.touch",
            Self::SessionDelete => "session.delete",
            Self::MessageAppend => "message.append",
            Self::EventAppend => "event.append",
            Self::RunTerminal => "run.terminal",
            Self::RunTransition => "run.transition",
            Self::RunGet => "run.get",
            Self::EventReplay => "event.replay",
            Self::JobCreate => "job.create",
            Self::JobUpdate => "job.update",
            Self::JobDelete => "job.delete",
            Self::ApprovalRequest => "approval.request",
            Self::ApprovalGet => "approval.get",
            Self::ApprovalResolve => "approval.resolve",
            Self::ApprovalExpire => "approval.expire",
            Self::CompactionStart => "compaction.start",
            Self::CompactionGet => "compaction.get",
            Self::CompactionLatest => "compaction.latest",
            Self::CompactionCommit => "compaction.commit",
            Self::CompactionFail => "compaction.fail",
            Self::Migrate => "migrate",
            Self::RecoveryRecoverActive => "recovery.recover_active",
            Self::LoadAll => "load.all",
            Self::SessionGet => "session.get",
            Self::DeliveryGet => "delivery.get",
            Self::DeliveryAdvance => "delivery.advance",
            Self::DeliverySet => "delivery.set",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_command(op: &str) -> Self {
        match op {
            "admission.create" => Self::AdmissionCreate,
            "session.create" => Self::SessionCreate,
            "session.touch" => Self::SessionTouch,
            "session.delete" => Self::SessionDelete,
            "message.append" => Self::MessageAppend,
            "event.append" | "step.commit" => Self::EventAppend,
            "run.terminal" => Self::RunTerminal,
            "run.transition" => Self::RunTransition,
            "run.get" => Self::RunGet,
            "event.replay" => Self::EventReplay,
            "job.create" => Self::JobCreate,
            "job.update" => Self::JobUpdate,
            "job.delete" => Self::JobDelete,
            "approval.request" => Self::ApprovalRequest,
            "approval.get" => Self::ApprovalGet,
            "approval.resolve" => Self::ApprovalResolve,
            "approval.expire" => Self::ApprovalExpire,
            "compaction.start" => Self::CompactionStart,
            "compaction.get" => Self::CompactionGet,
            "compaction.latest" => Self::CompactionLatest,
            "compaction.commit" => Self::CompactionCommit,
            "compaction.fail" => Self::CompactionFail,
            "migrate" => Self::Migrate,
            "recovery.recover_active" | "recovery.reconcile_effects" => Self::RecoveryRecoverActive,
            "load.all" => Self::LoadAll,
            "session.get" => Self::SessionGet,
            "delivery.get" => Self::DeliveryGet,
            "delivery.advance" => Self::DeliveryAdvance,
            "delivery.set" => Self::DeliverySet,
            _ => Self::Unknown,
        }
    }
}

/// Finite terminal retry outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum TerminalRetryOutcome {
    Committed = 0,
    Conflict = 1,
    Expired = 2,
    RetryFailed = 3,
    Gone = 4,
}

impl TerminalRetryOutcome {
    pub const ALL: [Self; 5] = [
        Self::Committed,
        Self::Conflict,
        Self::Expired,
        Self::RetryFailed,
        Self::Gone,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Conflict => "conflict",
            Self::Expired => "expired",
            Self::RetryFailed => "retry_failed",
            Self::Gone => "gone",
        }
    }
}

/// Fixed run-duration histogram bounds (seconds); the final `+Inf` bucket is
/// implicit. The registry's memory is constant regardless of workload.
pub const RUN_DURATION_BUCKETS_SECONDS: [f64; 10] =
    [0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0, 900.0];

/// Number of histogram buckets including the `+Inf` overflow bucket.
pub const RUN_DURATION_BUCKET_COUNT: usize = RUN_DURATION_BUCKETS_SECONDS.len() + 1;

const ADMIT_REJECT_REASON_COUNT: usize = AdmitRejectReason::ALL.len();
const TERMINAL_STATUS_COUNT: usize = TerminalStatus::ALL.len();
const STORAGE_OP_COUNT: usize = StorageOp::ALL.len();
const TERMINAL_RETRY_OUTCOME_COUNT: usize = TerminalRetryOutcome::ALL.len();

/// One point-in-time read of every registry value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub admissions_accepted: u64,
    pub admissions_rejected: [u64; ADMIT_REJECT_REASON_COUNT],
    pub active_runs: i64,
    pub runs_terminal_pending: i64,
    pub runs_terminal: [u64; TERMINAL_STATUS_COUNT],
    pub events_emitted: u64,
    pub events_dropped: u64,
    pub events_lagged: u64,
    pub storage_ops_ok: [u64; STORAGE_OP_COUNT],
    pub storage_ops_error: [u64; STORAGE_OP_COUNT],
    pub terminal_retries: [u64; TERMINAL_RETRY_OUTCOME_COUNT],
    pub terminal_persist_backoffs: u64,
    pub sse_subscribers: i64,
    pub model_calls: u64,
    pub tool_calls: u64,
    pub tool_failures: u64,
    pub turns: u64,
    pub truncations: u64,
    pub run_duration: RunDurationSnapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunDurationSnapshot {
    /// Cumulative bucket counts; the last entry is the `+Inf` bucket.
    pub buckets: [u64; RUN_DURATION_BUCKET_COUNT],
    pub sum_micros: u64,
    pub count: u64,
}

impl MetricsSnapshot {
    pub fn admissions_rejected_by(&self, reason: AdmitRejectReason) -> u64 {
        self.admissions_rejected[reason as usize]
    }

    pub fn runs_terminal_by(&self, status: TerminalStatus) -> u64 {
        self.runs_terminal[status as usize]
    }

    pub fn storage_op_successes(&self, op: StorageOp) -> u64 {
        self.storage_ops_ok[op as usize]
    }

    pub fn storage_op_failures(&self, op: StorageOp) -> u64 {
        self.storage_ops_error[op as usize]
    }

    pub fn terminal_retries_by(&self, outcome: TerminalRetryOutcome) -> u64 {
        self.terminal_retries[outcome as usize]
    }
}

/// The bounded metrics registry. All operations are relaxed atomics; the
/// scrape path (`snapshot`/`render_prometheus`) never takes a lock.
#[derive(Default)]
pub struct Metrics {
    admissions_accepted: AtomicU64,
    admissions_rejected: [AtomicU64; ADMIT_REJECT_REASON_COUNT],
    active_runs: AtomicI64,
    runs_terminal_pending: AtomicI64,
    runs_terminal: [AtomicU64; TERMINAL_STATUS_COUNT],
    events_emitted: AtomicU64,
    events_dropped: AtomicU64,
    events_lagged: AtomicU64,
    storage_ops_ok: [AtomicU64; STORAGE_OP_COUNT],
    storage_ops_error: [AtomicU64; STORAGE_OP_COUNT],
    terminal_retries: [AtomicU64; TERMINAL_RETRY_OUTCOME_COUNT],
    terminal_persist_backoffs: AtomicU64,
    sse_subscribers: AtomicI64,
    model_calls: AtomicU64,
    tool_calls: AtomicU64,
    tool_failures: AtomicU64,
    turns: AtomicU64,
    truncations: AtomicU64,
    run_duration: RunDurationHistogram,
}

struct RunDurationHistogram {
    buckets: [AtomicU64; RUN_DURATION_BUCKET_COUNT],
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Default for RunDurationHistogram {
    fn default() -> Self {
        Self {
            buckets: Default::default(),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl Metrics {
    pub fn admission_accepted(&self) {
        self.admissions_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn admission_rejected(&self, reason: AdmitRejectReason) {
        self.admissions_rejected[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub fn active_runs_inc(&self) {
        self.active_runs.fetch_add(1, Ordering::Relaxed);
    }

    pub fn active_runs_dec(&self) {
        self.active_runs.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn runs_terminal_pending_inc(&self) {
        self.runs_terminal_pending.fetch_add(1, Ordering::Relaxed);
    }

    pub fn runs_terminal_pending_dec(&self) {
        self.runs_terminal_pending.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn runs_terminal(&self, status: TerminalStatus) {
        self.runs_terminal[status as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub fn events_emitted(&self) {
        self.events_emitted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn events_dropped(&self) {
        self.events_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn events_lagged(&self, dropped: u64) {
        self.events_lagged.fetch_add(dropped, Ordering::Relaxed);
    }

    pub fn storage_op(&self, op: StorageOp, ok: bool) {
        let target = if ok {
            &self.storage_ops_ok[op as usize]
        } else {
            &self.storage_ops_error[op as usize]
        };
        target.fetch_add(1, Ordering::Relaxed);
    }

    pub fn terminal_retry(&self, outcome: TerminalRetryOutcome) {
        self.terminal_retries[outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub fn terminal_persist_backoff(&self) {
        self.terminal_persist_backoffs
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn sse_subscriber_inc(&self) {
        self.sse_subscribers.fetch_add(1, Ordering::Relaxed);
    }

    pub fn sse_subscriber_dec(&self) {
        self.sse_subscribers.fetch_sub(1, Ordering::Relaxed);
    }

    /// Records one coding-agent model call. Saturates at `u64::MAX`.
    #[inline]
    pub fn record_model_call(&self) {
        self.record_model_calls(1);
    }

    /// Records `count` coding-agent model calls. Saturates at `u64::MAX`.
    #[inline]
    pub fn record_model_calls(&self, count: u64) {
        saturating_add_counter(&self.model_calls, count);
    }

    /// Records one coding-agent tool call. Saturates at `u64::MAX`.
    #[inline]
    pub fn record_tool_call(&self) {
        self.record_tool_calls(1);
    }

    /// Records `count` coding-agent tool calls. Saturates at `u64::MAX`.
    #[inline]
    pub fn record_tool_calls(&self, count: u64) {
        saturating_add_counter(&self.tool_calls, count);
    }

    /// Records one coding-agent tool failure. Saturates at `u64::MAX`.
    #[inline]
    pub fn record_tool_failure(&self) {
        self.record_tool_failures(1);
    }

    /// Records `count` coding-agent tool failures. Saturates at `u64::MAX`.
    #[inline]
    pub fn record_tool_failures(&self, count: u64) {
        saturating_add_counter(&self.tool_failures, count);
    }

    /// Records one coding-agent turn. Saturates at `u64::MAX`.
    #[inline]
    pub fn record_turn(&self) {
        self.record_turns(1);
    }

    /// Records `count` coding-agent turns. Saturates at `u64::MAX`.
    #[inline]
    pub fn record_turns(&self, count: u64) {
        saturating_add_counter(&self.turns, count);
    }

    /// Records one coding-agent truncation. Saturates at `u64::MAX`.
    #[inline]
    pub fn record_truncation(&self) {
        self.record_truncations(1);
    }

    /// Records `count` coding-agent truncations. Saturates at `u64::MAX`.
    #[inline]
    pub fn record_truncations(&self, count: u64) {
        saturating_add_counter(&self.truncations, count);
    }

    /// Accounts one actual `AgentProviderHost::call` attempt.
    ///
    /// Callers pass only deltas/booleans: never raw args, paths, prompts,
    /// outputs, provider errors, or identifiers. `successful_turn` is true
    /// only for a successfully normalized `ok: true` envelope. `truncated`
    /// is true only when that envelope carries a typed `response.truncated`
    /// flag.
    #[inline]
    pub fn account_model_attempt(&self, successful_turn: bool, truncated: bool) {
        self.record_model_call();
        if successful_turn {
            self.record_turn();
        }
        if truncated {
            self.record_truncation();
        }
    }

    /// Accounts one freshly executed or failed tool dispatch.
    ///
    /// Replay of an already durable `ToolResult` must not call this.
    /// `failed` maps to canonical `ToolResult.ok == false`. `truncated`
    /// maps to the typed `ToolResult.truncated` flag.
    #[inline]
    pub fn account_tool_attempt(&self, failed: bool, truncated: bool) {
        self.record_tool_call();
        if failed {
            self.record_tool_failure();
        }
        if truncated {
            self.record_truncation();
        }
    }

    /// Records one run duration (seconds) into the fixed histogram buckets.
    pub fn record_run_duration(&self, seconds: f64) {
        let bucket = RUN_DURATION_BUCKETS_SECONDS
            .iter()
            .position(|bound| seconds <= *bound)
            .unwrap_or(RUN_DURATION_BUCKET_COUNT - 1);
        self.run_duration.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.run_duration
            .sum_micros
            .fetch_add((seconds * 1_000_000.0) as u64, Ordering::Relaxed);
        self.run_duration.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns a `SubscriberGuard` that has already incremented the live SSE
    /// subscriber gauge and decrements it when dropped (stream end or client
    /// disconnect), so the gauge cannot drift.
    pub fn subscriber_guard(self: &Arc<Self>) -> SubscriberGuard {
        self.sse_subscriber_inc();
        SubscriberGuard {
            metrics: Arc::clone(self),
        }
    }

    /// Point-in-time read of every value; used by `/health/detailed` and the
    /// Prometheus renderer so both share one snapshot (one source of truth).
    pub fn snapshot(&self) -> MetricsSnapshot {
        let load = |values: &[AtomicU64; STORAGE_OP_COUNT]| {
            let mut out = [0_u64; STORAGE_OP_COUNT];
            for (index, value) in values.iter().enumerate() {
                out[index] = value.load(Ordering::Relaxed);
            }
            out
        };
        MetricsSnapshot {
            admissions_accepted: self.admissions_accepted.load(Ordering::Relaxed),
            admissions_rejected: load_array(&self.admissions_rejected),
            active_runs: self.active_runs.load(Ordering::Relaxed),
            runs_terminal_pending: self.runs_terminal_pending.load(Ordering::Relaxed),
            runs_terminal: load_array(&self.runs_terminal),
            events_emitted: self.events_emitted.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            events_lagged: self.events_lagged.load(Ordering::Relaxed),
            storage_ops_ok: load(&self.storage_ops_ok),
            storage_ops_error: load(&self.storage_ops_error),
            terminal_retries: load_array(&self.terminal_retries),
            terminal_persist_backoffs: self.terminal_persist_backoffs.load(Ordering::Relaxed),
            sse_subscribers: self.sse_subscribers.load(Ordering::Relaxed),
            model_calls: self.model_calls.load(Ordering::Relaxed),
            tool_calls: self.tool_calls.load(Ordering::Relaxed),
            tool_failures: self.tool_failures.load(Ordering::Relaxed),
            turns: self.turns.load(Ordering::Relaxed),
            truncations: self.truncations.load(Ordering::Relaxed),
            run_duration: RunDurationSnapshot {
                buckets: load_array(&self.run_duration.buckets),
                sum_micros: self.run_duration.sum_micros.load(Ordering::Relaxed),
                count: self.run_duration.count.load(Ordering::Relaxed),
            },
        }
    }

    /// Renders the Prometheus text exposition format (version 0.0.4). The
    /// output is deterministic: samples are sorted by name then labels.
    pub fn render_prometheus(&self) -> String {
        let snapshot = self.snapshot();
        let mut samples: Vec<(String, String, String)> = Vec::new();

        counter(
            &mut samples,
            "agent_admissions_total",
            &[("outcome", "accepted")],
            snapshot.admissions_accepted,
        );
        for reason in AdmitRejectReason::ALL {
            counter(
                &mut samples,
                "agent_admissions_total",
                &[("outcome", "rejected"), ("reason", reason.label())],
                snapshot.admissions_rejected_by(reason),
            );
        }
        gauge(&mut samples, "agent_active_runs", &[], snapshot.active_runs);
        gauge(
            &mut samples,
            "agent_runs_terminal_pending",
            &[],
            snapshot.runs_terminal_pending,
        );
        for status in TerminalStatus::ALL {
            counter(
                &mut samples,
                "agent_runs_terminal_total",
                &[("status", status.label())],
                snapshot.runs_terminal_by(status),
            );
        }
        counter(
            &mut samples,
            "agent_events_emitted_total",
            &[],
            snapshot.events_emitted,
        );
        counter(
            &mut samples,
            "agent_events_dropped_total",
            &[],
            snapshot.events_dropped,
        );
        counter(
            &mut samples,
            "agent_events_lagged_total",
            &[],
            snapshot.events_lagged,
        );
        for op in StorageOp::ALL {
            counter(
                &mut samples,
                "agent_storage_ops_total",
                &[("op", op.label()), ("outcome", "ok")],
                snapshot.storage_op_successes(op),
            );
            counter(
                &mut samples,
                "agent_storage_ops_total",
                &[("op", op.label()), ("outcome", "error")],
                snapshot.storage_op_failures(op),
            );
        }
        for outcome in TerminalRetryOutcome::ALL {
            counter(
                &mut samples,
                "agent_terminal_retries_total",
                &[("outcome", outcome.label())],
                snapshot.terminal_retries_by(outcome),
            );
        }
        counter(
            &mut samples,
            "agent_terminal_persist_backoffs_total",
            &[],
            snapshot.terminal_persist_backoffs,
        );
        gauge(
            &mut samples,
            "agent_sse_subscribers",
            &[],
            snapshot.sse_subscribers,
        );
        counter(
            &mut samples,
            "agent_model_calls_total",
            &[],
            snapshot.model_calls,
        );
        counter(
            &mut samples,
            "agent_tool_calls_total",
            &[],
            snapshot.tool_calls,
        );
        counter(
            &mut samples,
            "agent_tool_failures_total",
            &[],
            snapshot.tool_failures,
        );
        counter(&mut samples, "agent_turns_total", &[], snapshot.turns);
        counter(
            &mut samples,
            "agent_truncations_total",
            &[],
            snapshot.truncations,
        );

        // Histogram: cumulative buckets, then sum and count.
        let mut cumulative = 0_u64;
        for (index, bound) in RUN_DURATION_BUCKETS_SECONDS.iter().enumerate() {
            cumulative += snapshot.run_duration.buckets[index];
            counter(
                &mut samples,
                "agent_run_duration_seconds_bucket",
                &[("le", &bound.to_string())],
                cumulative,
            );
        }
        cumulative += snapshot.run_duration.buckets[RUN_DURATION_BUCKET_COUNT - 1];
        counter(
            &mut samples,
            "agent_run_duration_seconds_bucket",
            &[("le", "+Inf")],
            cumulative,
        );
        let sum_seconds = snapshot.run_duration.sum_micros as f64 / 1_000_000.0;
        counter(
            &mut samples,
            "agent_run_duration_seconds_sum",
            &[],
            format!("{sum_seconds}"),
        );
        counter(
            &mut samples,
            "agent_run_duration_seconds_count",
            &[],
            snapshot.run_duration.count,
        );

        samples.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));

        let mut out = String::new();
        for (name, help, kind) in METRIC_DEFS {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push(' ');
            out.push_str(help);
            out.push('\n');
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push(' ');
            out.push_str(kind);
            out.push('\n');
        }
        for (name, labels, value) in samples {
            out.push_str(&name);
            if !labels.is_empty() {
                out.push('{');
                out.push_str(&labels);
                out.push('}');
            }
            out.push(' ');
            out.push_str(&value);
            out.push('\n');
        }
        out
    }
}

/// Decrements the SSE subscriber gauge exactly once when the subscriber's
/// stream is dropped — on a terminal, on a lagged error, or on a client
/// disconnect — so the gauge never drifts.
pub struct SubscriberGuard {
    metrics: Arc<Metrics>,
}

impl SubscriberGuard {
    /// Records events the subscriber skipped because it fell behind the
    /// bounded broadcast buffer.
    pub fn record_lag(&self, dropped: u64) {
        self.metrics.events_lagged(dropped);
    }
}

impl Drop for SubscriberGuard {
    fn drop(&mut self) {
        self.metrics.sse_subscriber_dec();
    }
}

fn load_array<const N: usize>(values: &[AtomicU64; N]) -> [u64; N] {
    let mut out = [0_u64; N];
    for (index, value) in values.iter().enumerate() {
        out[index] = value.load(Ordering::Relaxed);
    }
    out
}

/// Adds `delta` to `target`, saturating at `u64::MAX` instead of wrapping.
/// A CAS/update loop keeps concurrent increments lossless until saturation.
fn saturating_add_counter(target: &AtomicU64, delta: u64) {
    if delta == 0 {
        return;
    }
    let mut current = target.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(delta);
        if next == current {
            return;
        }
        match target.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn counter(
    samples: &mut Vec<(String, String, String)>,
    name: &str,
    labels: &[(&str, &str)],
    value: impl std::fmt::Display,
) {
    let rendered = labels
        .iter()
        .map(|(key, value)| format!("{key}=\"{value}\""))
        .collect::<Vec<_>>()
        .join(",");
    samples.push((name.to_string(), rendered, value.to_string()));
}

fn gauge(
    samples: &mut Vec<(String, String, String)>,
    name: &str,
    labels: &[(&str, &str)],
    value: impl std::fmt::Display,
) {
    counter(samples, name, labels, value);
}

/// Metric definitions in fixed order: (name, help, type).
const METRIC_DEFS: &[(&str, &str, &str)] = &[
    (
        "agent_admissions_total",
        "Run admissions by outcome; rejected carries a finite reason label.",
        "counter",
    ),
    (
        "agent_active_runs",
        "Admitted runs that have not yet committed a terminal state.",
        "gauge",
    ),
    (
        "agent_runs_terminal_pending",
        "Runs awaiting the bounded durable terminal retry.",
        "gauge",
    ),
    (
        "agent_runs_terminal_total",
        "Runs committed to a terminal state by status.",
        "counter",
    ),
    (
        "agent_events_emitted_total",
        "Script events durably delivered to live subscribers.",
        "counter",
    ),
    (
        "agent_events_dropped_total",
        "Script events dropped (schema violations or persist failures).",
        "counter",
    ),
    (
        "agent_events_lagged_total",
        "SSE events skipped by lagging subscribers.",
        "counter",
    ),
    (
        "agent_storage_ops_total",
        "Typed storage commands by operation and outcome.",
        "counter",
    ),
    (
        "agent_terminal_retries_total",
        "Bounded terminal retry loop outcomes.",
        "counter",
    ),
    (
        "agent_terminal_persist_backoffs_total",
        "Worker terminal-persist backoff retries.",
        "counter",
    ),
    ("agent_sse_subscribers", "Live SSE subscribers.", "gauge"),
    (
        "agent_model_calls_total",
        "Coding agent model calls.",
        "counter",
    ),
    (
        "agent_tool_calls_total",
        "Coding agent tool calls.",
        "counter",
    ),
    (
        "agent_tool_failures_total",
        "Coding agent tool call failures.",
        "counter",
    ),
    ("agent_turns_total", "Coding agent turns.", "counter"),
    (
        "agent_truncations_total",
        "Coding agent truncations.",
        "counter",
    ),
    (
        "agent_run_duration_seconds",
        "Run duration from admission to terminal, fixed buckets.",
        "histogram",
    ),
];
