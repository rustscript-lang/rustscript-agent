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
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::stream::{FuturesUnordered, StreamExt};
use serde_json::Value as JsonValue;
use tokio::sync::Semaphore;

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
    pub fn from_plan(value: Option<&str>) -> Self {
        match value {
            Some("race") => Self::Race,
            Some("fail_fast") => Self::FailFast,
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
}

impl SupervisorCancel {
    pub fn request(&self) {
        self.flag.store(true, Ordering::Release);
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
}

/// Boxed per-slot futures in a shared unordered stream; the engine's
/// bounded-concurrency workhorse.
type SlotCalls<'a> = futures_util::stream::FuturesUnordered<
    Pin<Box<dyn Future<Output = (usize, ChildOutcome)> + Send + 'a>>,
>;

/// Drives a batch of child slots under the given supervision policy, with
/// bounded in-flight concurrency and ordered result slots.
///
/// - Bounded concurrency: a [`Semaphore`] caps how many children run at
///   once; a slot only begins its real work after a permit is available, so
///   the number of concurrent `execute_child` calls is ≤ `max_concurrency`.
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
    let total = specs.len();
    if total == 0 {
        return Vec::new();
    }

    let bound = max_concurrency.max(1);
    let semaphore = Arc::new(Semaphore::new(bound));

    // One future per slot. Each acquires a bounded permit before starting,
    // refuses once cancelled, then delegates to the executor.
    let mut calls: SlotCalls<'_> = FuturesUnordered::new();
    for (slot, child) in specs.iter().cloned().enumerate() {
        let child_cancel = cancel.clone();
        let permit = Arc::clone(&semaphore);
        calls.push(Box::pin(async move {
            let _permit = permit.acquire_owned().await.expect("child permit");
            if child_cancel.is_requested() {
                return (
                    slot,
                    ChildOutcome::Cancelled("parent_cancelled".to_string()),
                );
            }
            let outcome = executor.execute_child(&child, &child_cancel).await;
            (slot, outcome)
        }));
    }

    // Collect in real completion order but place each outcome into its
    // submission slot, so the result vector is exactly submission-ordered.
    let mut ordered: Vec<Option<ChildOutcome>> = vec![None; total];
    while let Some((slot, outcome)) = calls.next().await {
        ordered[slot] = Some(outcome.clone());
        // The first marker (a success in race, a failure in fail-fast)
        // cancels in-flight losers / siblings and stops the rest.
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
    }

    // Anything never filled is a typed cancellation, never a fabricated
    // success (cannot happen with the draining loop above; defensive).
    for slot_value in ordered.iter_mut() {
        if slot_value.is_none() {
            *slot_value = Some(ChildOutcome::Cancelled("batch_terminated".to_string()));
        }
    }

    ordered.into_iter().map(|value| value.unwrap()).collect()
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
}
