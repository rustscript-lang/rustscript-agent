//! Native Subagent/parallel supervision engine (embedding layer).
//!
//! RSS policy modules (`rss/agent/parallel.rss`, `rss/agent/subagents.rss`)
//! are pure *decision* policies: they own the WHAT (windows, ordered result
//! slots, race/fail-fast supervision rules, depth/fanout budgets, child and
//! parent identity). They never execute anything and never emit an event as
//! if a child already ran. The native layer in this module owns the HOW: it
//! consumes the plan inputs and drives N child runs concurrently with
//! bounded concurrency, ordered results, race/fail-fast supervision,
//! parent-cancellation propagation, and per-slot isolation.
//!
//! The engine is deliberately generic over a [`ChildExecutor`] so the same
//! concurrency logic is testable with in-memory fakes and bindable to real
//! infrastructure (AgentService capacity semaphore, `AdmitRunRequest`
//! carrying `parent_run_id`, the tokio worker, `RunCancellation`, and the
//! `run.link_child` storage command). A real executor owns the
//! admission/link round-trip, so no fabricated `subagent.started` /
//! `run.link_child` ever originates from the decision layer: those lifecycle
//! artifacts are produced only when the executor has really admitted and
//! linked a child.
//!
//! The engine's job is lifecycle + concurrency only. It never chooses
//! windows, never imposes depth/fanout budgets, and never fabricates a
//! success: anything it cannot run it reports as a typed [`ChildOutcome`]
//! (Cancelled/Failed), never as a borrowed success.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::FutureExt;
use futures_util::stream::{FuturesUnordered, StreamExt};
use serde_json::Value as JsonValue;

/// Payload handed to the executor for one child slot.
#[derive(Debug, Clone)]
pub struct ChildSpec {
    /// Ordered result-slot index (submission order, 0-based).
    pub slot: usize,
    /// The child run id when the plan pre-assigns one; empty means the
    /// executor assigns it (for example the admission round-trip).
    pub child_run_id: String,
    /// Opaque child input carried verbatim to the executor.
    pub input: JsonValue,
}

/// Outcome of one supervised child slot, in submission order.
#[derive(Debug, Clone, PartialEq)]
pub enum ChildOutcome {
    /// The child run reached a settled success.
    Completed(JsonValue),
    /// The child run ended as a typed cancellation (requested by the parent,
    /// a race loser, or a fail-fast sibling).
    Cancelled(String),
    /// The child run failed with a typed error message.
    Failed(String),
}

impl ChildOutcome {
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

/// The supervision strategy carried by the RSS plan's `cancel_rule`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisionMode {
    All,
    Race,
    FailFast,
}

impl SupervisionMode {
    /// Accepts both the plan's short mode names (`"race"` / `"fail_fast"`)
    /// and the long-form `cancel_rule` descriptors the policy emits
    /// (`"cancel_losers_on_first_success"` / `"cancel_siblings_on_first_failure"`).
    pub fn from_plan(value: Option<&str>) -> Self {
        match value {
            Some("race") | Some("cancel_losers_on_first_success") => Self::Race,
            Some("fail_fast") | Some("cancel_siblings_on_first_failure") => Self::FailFast,
            _ => Self::All,
        }
    }
}

/// Shared cancel flag. Once set, no further child is started and every
/// in-flight child is given the chance to abort its executor before
/// producing its terminal outcome.
#[derive(Clone, Default)]
pub struct SupervisorCancel {
    flag: Arc<AtomicBool>,
    reason: Arc<Mutex<Option<String>>>,
}

impl SupervisorCancel {
    pub fn request(&self) {
        self.request_with_reason("parent_cancelled");
    }

    pub fn request_with_reason(&self, reason: &str) {
        let mut current = self.reason.lock().expect("supervisor cancel reason lock");
        if current.is_none() {
            *current = Some(reason.to_string());
        }
        drop(current);
        self.flag.store(true, Ordering::Release);
    }

    pub fn reason(&self) -> String {
        self.reason
            .lock()
            .expect("supervisor cancel reason lock")
            .clone()
            .unwrap_or_else(|| "parent_cancelled".to_string())
    }

    pub fn is_requested(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
}

/// Runs one child run: real admission, the actual work, and the real
/// terminal. `cancel` is the shared supervision flag: the executor may use
/// it to abort a race loser / fail-fast sibling. `&self` must be
/// `Send + Sync` so many slots can share it.
pub trait ChildExecutor: Send + Sync {
    fn execute_child(
        &self,
        child: &ChildSpec,
        cancel: &SupervisorCancel,
    ) -> Pin<Box<dyn Future<Output = ChildOutcome> + Send + '_>>;

    /// Best-effort durable terminal for a slot that the batch was DROPPED on
    /// (the grace-drop window). Returns the real typed outcome when the slot's
    /// child already reached a DURABLE terminal (for example `subagent.completed`
    /// was already appended but the outcome had not yet been folded into the
    /// shared buffer), so the grace fallback folds the REAL outcome instead of
    /// reporting a spurious cancellation. `None` means the slot is not (yet)
    /// durably terminal — the caller falls back to the typed cancel reason.
    fn observed_terminal_outcome(&self, _slot: usize) -> Option<ChildOutcome> {
        None
    }
}

/// Boxed per-slot futures in a shared unordered stream; the engine's
/// bounded-concurrency workhorse.
type SlotCalls<'a> = futures_util::stream::FuturesUnordered<
    Pin<Box<dyn Future<Output = (usize, ChildOutcome)> + Send + 'a>>,
>;

/// Drives a batch of child slots under the given supervision policy, with
/// bounded in-flight concurrency and ordered result slots.
///
/// The loop owns concurrency: exactly `max_concurrency` slots are in flight
/// at once, and a queued slot is started ONLY after the previous outcome's
/// supervision gate has been processed — so the moment the race/fail-fast
/// gate fires, no further slot ever starts (the remaining queued slots
/// report typed `parent_cancelled` outcomes without executing). This makes
/// "the first success cancels losers" / "the first failure cancels
/// siblings" exact, never one slot past the gate.
///
/// - Bounded concurrency: the number of concurrent `execute_child` calls is
///   ≤ `max_concurrency`.
/// - Ordered results: the returned vector has exactly `specs.len()` entries,
///   aligned one-per-submission-slot regardless of real completion order.
/// - Race / fail-fast: the first success (race) or the first failure
///   (fail-fast) sets the shared cancel flag, which cancels in-flight
///   losers / siblings (through their executor) and stops the remaining
///   slots from starting.
/// - Parent cancellation: a requested [`SupervisorCancel`] propagates the
///   same way; children never start (or continue) after the parent cancels.
pub async fn supervise_batch(
    executor: &dyn ChildExecutor,
    specs: &[ChildSpec],
    mode: SupervisionMode,
    max_concurrency: usize,
    cancel: &SupervisorCancel,
) -> Vec<ChildOutcome> {
    supervise_batch_shared(
        executor,
        specs,
        mode,
        max_concurrency,
        cancel,
        &Arc::new(Mutex::new(vec![None; specs.len()])),
    )
    .await
}

/// The shared-outcomes engine behind [`supervise_batch`]. Every collected
/// slot outcome is ALSO written into the caller-owned shared buffer, so a
/// grace-drop that destroys the batch future can never lose a completed
/// outcome (the bounded wrapper's fallback reads the buffer).
async fn supervise_batch_shared(
    executor: &dyn ChildExecutor,
    specs: &[ChildSpec],
    mode: SupervisionMode,
    max_concurrency: usize,
    cancel: &SupervisorCancel,
    shared: &Arc<Mutex<Vec<Option<ChildOutcome>>>>,
) -> Vec<ChildOutcome> {
    let total = specs.len();
    if total == 0 {
        return Vec::new();
    }
    let bound = max_concurrency.max(1);

    // One future per started slot; a slot only starts when the loop hands
    // it out, so the gate check below always runs BEFORE the next slot.
    let mut calls: SlotCalls<'_> = FuturesUnordered::new();
    let mut outcomes: Vec<Option<ChildOutcome>> = vec![None; total];
    let mut next_slot = 0usize;
    let mut in_flight = 0usize;
    while next_slot < total && in_flight < bound {
        push_slot(&mut calls, executor, specs, next_slot, cancel);
        next_slot += 1;
        in_flight += 1;
    }
    while in_flight > 0 {
        let (slot, outcome) = calls.next().await.expect("in-flight slot");
        outcomes[slot] = Some(outcome.clone());
        // The completed outcome is preserved in the shared buffer BEFORE
        // the gate is processed: a grace-drop of this future (the bounded
        // wrapper's drain timeout) can never lose it.
        shared.lock().expect("shared outcomes lock")[slot] = Some(outcome.clone());
        in_flight -= 1;
        // The supervision gate is processed BEFORE the next slot starts, so
        // a gate that fires here prevents every remaining slot from
        // starting (never one slot past the gate).
        if !cancel.is_requested() {
            let gate = match mode {
                SupervisionMode::All => false,
                SupervisionMode::Race => matches!(outcome, ChildOutcome::Completed(_)),
                SupervisionMode::FailFast => outcome.is_failure(),
            };
            if gate {
                cancel.request();
            }
        }
        if next_slot < total {
            if cancel.is_requested() {
                // No further slot ever starts after the gate: every remaining
                // queued slot is a typed cancellation, never a fabricated
                // success and never an execution.
                while next_slot < total {
                    outcomes[next_slot] = Some(ChildOutcome::Cancelled(cancel.reason()));
                    next_slot += 1;
                }
            } else {
                push_slot(&mut calls, executor, specs, next_slot, cancel);
                next_slot += 1;
                in_flight += 1;
            }
        }
    }

    outcomes.into_iter().map(|value| value.unwrap()).collect()
}

/// Pushes one slot future into the shared unordered stream.
fn push_slot<'a>(
    calls: &mut SlotCalls<'a>,
    executor: &'a dyn ChildExecutor,
    specs: &'a [ChildSpec],
    slot: usize,
    cancel: &'a SupervisorCancel,
) {
    let child_cancel = cancel.clone();
    let child = specs[slot].clone();
    calls.push(Box::pin(async move {
        if child_cancel.is_requested() {
            return (slot, ChildOutcome::Cancelled(cancel.reason()));
        }
        let outcome = executor.execute_child(&child, &child_cancel).await;
        (slot, outcome)
    }));
}

/// Drives [`supervise_batch`] bounded by a wall-clock deadline.
///
/// When the deadline fires, the shared cancel is requested (every in-flight
/// child's executor observes it and aborts) and the batch is drained within
/// `grace` so the in-flight children really reach typed outcomes. A drain
/// that cannot finish within the grace reports typed cancellations for the
/// unfinished slots (their cancellations were genuinely requested) — never
/// a fabricated success. Returns `(outcomes, timed_out)`.
pub async fn supervise_batch_bounded(
    executor: &dyn ChildExecutor,
    specs: &[ChildSpec],
    mode: SupervisionMode,
    max_concurrency: usize,
    cancel: &SupervisorCancel,
    deadline: std::time::Instant,
    grace: std::time::Duration,
) -> (Vec<ChildOutcome>, bool) {
    // The shared outcome buffer survives the batch future: a grace-drop can
    // never lose a completed slot outcome (the fallback reads it first).
    let shared = Arc::new(Mutex::new(vec![None; specs.len()]));
    let mut batch = Box::pin(supervise_batch_shared(
        executor,
        specs,
        mode,
        max_concurrency,
        cancel,
        &shared,
    ));
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    match tokio::time::timeout(remaining, &mut batch).await {
        Ok(outcomes) => (outcomes, false),
        Err(_) => {
            cancel.request_with_reason("deadline");
            match tokio::time::timeout(grace, &mut batch).await {
                Ok(outcomes) => (outcomes, true),
                Err(_) => {
                    // Give a child that became ready with the grace timer one
                    // final poll before the batch is dropped. This drains
                    // ready futures without extending the configured grace.
                    tokio::task::yield_now().await;
                    if let Some(outcomes) = batch.as_mut().now_or_never() {
                        return (outcomes, true);
                    }
                    // Grace fallback: FIRST collect the completed-but-
                    // undrained outcomes from the shared buffer — a slot
                    // whose outcome was already produced is reported exactly
                    // as it was, never misreported as a cancellation. A slot
                    // that was still in flight when the batch was dropped but
                    // whose child had ALREADY reached a REAL durable terminal
                    // (e.g. `subagent.completed` appended but the outcome not
                    // yet folded into the shared buffer) is folded to its
                    // REAL observed outcome via the executor — never rewritten
                    // as a spurious `Cancelled`. Only the slots that are not
                    // (yet) durably terminal report the typed deadline
                    // cancellation (their executors observed the shared
                    // cancel and their RAII guards compensate durably).
                    let collected = shared.lock().expect("shared outcomes lock").clone();
                    let outcomes = specs
                        .iter()
                        .enumerate()
                        .map(|(slot, _)| {
                            collected
                                .get(slot)
                                .cloned()
                                .flatten()
                                .or_else(|| executor.observed_terminal_outcome(slot))
                                .unwrap_or_else(|| ChildOutcome::Cancelled(cancel.reason()))
                        })
                        .collect();
                    (outcomes, true)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct ImmediateExecutor;

    impl ChildExecutor for ImmediateExecutor {
        fn execute_child(
            &self,
            _child: &ChildSpec,
            _cancel: &SupervisorCancel,
        ) -> Pin<Box<dyn Future<Output = ChildOutcome> + Send + '_>> {
            Box::pin(async move { ChildOutcome::Completed(JsonValue::Null) })
        }
    }

    #[tokio::test]
    async fn ordered_slots_preserve_submission_order() {
        let specs: Vec<ChildSpec> = (0..3)
            .map(|slot| ChildSpec {
                slot,
                child_run_id: format!("c{slot}"),
                input: JsonValue::from(slot),
            })
            .collect();
        let outcomes = supervise_batch(
            &ImmediateExecutor,
            &specs,
            SupervisionMode::All,
            8,
            &SupervisorCancel::default(),
        )
        .await;
        assert_eq!(outcomes.len(), 3);
        assert!(
            outcomes
                .iter()
                .all(|o| matches!(o, ChildOutcome::Completed(_)))
        );
    }

    /// An executor whose `execute_child` future NEVER resolves but whose child has
    /// ALREADY durably reached its real terminal (`completed`) — used to prove
    /// the grace-drop fallback consults `observed_terminal_outcome` and folds
    /// the child's REAL terminal instead of a spurious cancellation.
    struct CompletedTerminalExecutor;

    impl ChildExecutor for CompletedTerminalExecutor {
        fn execute_child(
            &self,
            _child: &ChildSpec,
            _cancel: &SupervisorCancel,
        ) -> Pin<Box<dyn Future<Output = ChildOutcome> + Send + '_>> {
            // The in-flight slot future never resolves within grace: the bounded
            // batch grace-drops it.
            Box::pin(std::future::pending())
        }

        fn observed_terminal_outcome(&self, _slot: usize) -> Option<ChildOutcome> {
            Some(ChildOutcome::Completed(JsonValue::String(
                "child real durable terminal".to_string(),
            )))
        }
    }

    #[tokio::test]
    async fn bounded_grace_drop_folds_slots_with_observed_real_terminal() {
        let specs: Vec<ChildSpec> = vec![ChildSpec {
            slot: 0,
            child_run_id: "dropped-child-run".to_string(),
            input: JsonValue::from("block-forever"),
        }];
        // Deadline already elapsed + a SHORT grace: the slot future is REALLY
        // dropped. Its child is in-flight AND already durably terminal, so the
        // fallback must fold the REAL typed terminal, never a cancellation.
        let (outcomes, _timed_out) = supervise_batch_bounded(
            &CompletedTerminalExecutor,
            &specs,
            SupervisionMode::All,
            1,
            &SupervisorCancel::default(),
            std::time::Instant::now() - std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(20),
        )
        .await;
        assert_eq!(outcomes.len(), 1);
        assert!(
            matches!(
                &outcomes[0],
                ChildOutcome::Completed(JsonValue::String(text))
                    if text == "child real durable terminal"
            ),
            "the grace drop must fold the slot child's REAL terminal, got {:?}",
            outcomes[0]
        );
    }

    /// Fakes one child outcome per slot from a scripted plan.
    struct ScriptedExecutor {
        script: Vec<ChildOutcome>,
        call_index: Arc<AtomicUsize>,
    }

    impl ChildExecutor for ScriptedExecutor {
        fn execute_child(
            &self,
            _child: &ChildSpec,
            _cancel: &SupervisorCancel,
        ) -> Pin<Box<dyn Future<Output = ChildOutcome> + Send + '_>> {
            let outcome = self.script[self.call_index.fetch_add(1, Ordering::SeqCst)].clone();
            Box::pin(async move {
                // A short wait lets the supervisor observe cancellation between
                // slots and cancel the remaining siblings / losers.
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                outcome
            })
        }
    }

    #[tokio::test]
    async fn race_cancels_losers_on_first_success() {
        // slot 0 succeeds (race gate), slots 1-3 are losers the supervisor
        // must cancel.
        let executor = ScriptedExecutor {
            script: vec![
                ChildOutcome::Completed(JsonValue::from("win")),
                ChildOutcome::Completed(JsonValue::from("lose-1")),
                ChildOutcome::Completed(JsonValue::from("lose-2")),
                ChildOutcome::Completed(JsonValue::from("lose-3")),
            ],
            call_index: Arc::new(AtomicUsize::new(0)),
        };
        let cancel = SupervisorCancel::default();
        let _ = &cancel;
        let specs: Vec<ChildSpec> = (0..4)
            .map(|slot| ChildSpec {
                slot,
                child_run_id: format!("c{slot}"),
                input: JsonValue::from(slot),
            })
            .collect();
        let outcomes = supervise_batch(
            &executor,
            &specs,
            SupervisionMode::Race,
            1,
            &SupervisorCancel::default(),
        )
        .await;
        // first success collected; at least one loser cancelled.
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, ChildOutcome::Completed(_))),
            "the successful racer must be reported"
        );
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, ChildOutcome::Cancelled(_))),
            "early enough losers must be cancelled by the first success"
        );
    }

    #[tokio::test]
    async fn fail_fast_cancels_siblings_on_first_failure() {
        let executor = ScriptedExecutor {
            script: vec![
                ChildOutcome::Completed(JsonValue::from("ok")),
                ChildOutcome::Failed("boom".to_string()),
                ChildOutcome::Completed(JsonValue::from("sibling")),
            ],
            call_index: Arc::new(AtomicUsize::new(0)),
        };
        let specs: Vec<ChildSpec> = (0..3)
            .map(|slot| ChildSpec {
                slot,
                child_run_id: format!("c{slot}"),
                input: JsonValue::from(slot),
            })
            .collect();
        let outcomes = supervise_batch(
            &executor,
            &specs,
            SupervisionMode::FailFast,
            1,
            &SupervisorCancel::default(),
        )
        .await;
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, ChildOutcome::Failed(_))),
            "the first failure must be reported in its slot"
        );
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, ChildOutcome::Cancelled(_))),
            "later siblings must be cancelled (fail-fast)"
        );
    }

    #[tokio::test]
    async fn parent_cancellation_stops_new_children() {
        let cancel = SupervisorCancel::default();
        cancel.request();
        let specs: Vec<ChildSpec> = (0..3)
            .map(|slot| ChildSpec {
                slot,
                child_run_id: format!("c{slot}"),
                input: JsonValue::from(slot),
            })
            .collect();
        let outcomes =
            supervise_batch(&ImmediateExecutor, &specs, SupervisionMode::All, 1, &cancel).await;
        assert!(outcomes.iter().all(|o| matches!(
            o,
            ChildOutcome::Cancelled(reason) if reason == "parent_cancelled"
        )));
    }

    /// A slow executor: each slot takes `hold_ms` to produce its scripted
    /// outcome, so a deadline can land mid-batch.
    struct SlowExecutor {
        hold_ms: u64,
    }

    impl ChildExecutor for SlowExecutor {
        fn execute_child(
            &self,
            _child: &ChildSpec,
            cancel: &SupervisorCancel,
        ) -> Pin<Box<dyn Future<Output = ChildOutcome> + Send + '_>> {
            let hold_ms = self.hold_ms;
            let cancel = cancel.clone();
            Box::pin(async move {
                tokio::time::sleep(std::time::Duration::from_millis(hold_ms)).await;
                if cancel.is_requested() {
                    ChildOutcome::Cancelled(cancel.reason())
                } else {
                    ChildOutcome::Completed(JsonValue::Null)
                }
            })
        }
    }

    /// An executor whose slot 0 completes quickly while slot 1 stalls far
    /// past the grace: the grace-drop fallback must preserve slot 0's
    /// collected Completed outcome (never misreport a completed child as a
    /// cancellation) and report the still-in-flight slot 1 as the typed
    /// deadline cancellation.
    struct MixedExecutor;

    impl ChildExecutor for MixedExecutor {
        fn execute_child(
            &self,
            child: &ChildSpec,
            _cancel: &SupervisorCancel,
        ) -> Pin<Box<dyn Future<Output = ChildOutcome> + Send + '_>> {
            let slot = child.slot;
            Box::pin(async move {
                if slot == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    ChildOutcome::Completed(JsonValue::String("done-0".to_string()))
                } else {
                    // Stalls far past the batch deadline and the grace.
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    ChildOutcome::Completed(JsonValue::Null)
                }
            })
        }
    }

    #[tokio::test]
    async fn grace_timeout_preserves_collected_completed_outcomes() {
        let specs: Vec<ChildSpec> = (0..2)
            .map(|slot| ChildSpec {
                slot,
                child_run_id: format!("c{slot}"),
                input: JsonValue::from(slot),
            })
            .collect();
        let cancel = SupervisorCancel::default();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(40);
        let (outcomes, timed_out) = supervise_batch_bounded(
            &MixedExecutor,
            &specs,
            SupervisionMode::All,
            2,
            &cancel,
            deadline,
            std::time::Duration::from_millis(20),
        )
        .await;
        assert!(timed_out, "the batch must observe its deadline");
        assert_eq!(outcomes.len(), 2, "every slot stays ordered and typed");
        assert_eq!(
            outcomes[0],
            ChildOutcome::Completed(JsonValue::String("done-0".to_string())),
            "the completed-but-undrained slot keeps its real outcome — never a fabricated cancellation"
        );
        assert!(
            matches!(&outcomes[1], ChildOutcome::Cancelled(reason) if reason == "deadline"),
            "the still-in-flight slot reports the typed deadline cancellation"
        );
    }

    #[tokio::test]
    async fn bounded_batch_preserves_parent_stop_reason_after_grace() {
        let specs: Vec<ChildSpec> = (0..2)
            .map(|slot| ChildSpec {
                slot,
                child_run_id: format!("c{slot}"),
                input: JsonValue::from(slot),
            })
            .collect();
        let cancel = SupervisorCancel::default();
        let stop = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            stop.request();
        });
        let (outcomes, timed_out) = supervise_batch_bounded(
            &SlowExecutor { hold_ms: 100 },
            &specs,
            SupervisionMode::All,
            2,
            &cancel,
            std::time::Instant::now() + std::time::Duration::from_millis(35),
            std::time::Duration::from_millis(5),
        )
        .await;
        assert!(timed_out);
        assert!(
            outcomes
                .iter()
                .all(|outcome| matches!(outcome, ChildOutcome::Cancelled(reason) if reason == "parent_cancelled")),
            "a parent stop that precedes the deadline must not be relabeled as deadline: {outcomes:?}"
        );
    }
}
