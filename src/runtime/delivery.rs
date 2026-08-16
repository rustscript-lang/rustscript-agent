//! Bounded live event delivery for one run.
//!
//! The worker sends script events through one bounded mpsc channel; the
//! delivery task validates each `Event(Value)` against the canonical agent
//! event schema, assigns the monotonic per-run sequence, appends it durably
//! (typed `event.append` while the store write lock is held on a blocking
//! thread), and only then publishes it to live subscribers. `blocking_send`
//! pauses the worker (and therefore invocation polling) while the delivery
//! task is busy, so core execution cannot outrun delivery. Nothing is
//! published after the run commits a terminal state, and a failed append is
//! rolled back so no unpersisted event is ever visible.

use std::sync::Arc;

use parking_lot::RwLock;
use rustscript_vm::Value as VmValue;
use serde_json::{Value, json};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::config::AgentGatewayConfig;
use crate::domain::{timestamp, truncate_for_log};
use crate::events;
use crate::gateway::store::{GatewayEvent, GatewayPersistence, GatewayStore, RunRecord};
use crate::metrics::Metrics;
use crate::{RunDeliveryError, RunEventSink};

/// The store/persistence/config slice the delivery task needs; built by
/// AgentService so delivery stays independent of service internals.
pub(crate) struct DeliveryContext {
    pub(crate) store: Arc<RwLock<GatewayStore>>,
    pub(crate) persistence: Option<Arc<GatewayPersistence>>,
    pub(crate) config: Arc<AgentGatewayConfig>,
    pub(crate) metrics: Arc<Metrics>,
}

/// Bounded channel delivery sink: `blocking_send` pauses the worker (and
/// therefore invocation polling) while the delivery task is busy, and fails
/// once the receiver is gone.
pub(crate) struct ChannelEventSink(pub(crate) tokio::sync::mpsc::Sender<VmValue>);

impl RunEventSink for ChannelEventSink {
    fn deliver(&mut self, value: VmValue) -> Result<(), RunDeliveryError> {
        self.0
            .blocking_send(value)
            .map_err(|_| RunDeliveryError::Closed)
    }
}

/// Discards script events (used by the legacy chat completion path, which has
/// no run record for live delivery).
pub(crate) struct DiscardingSink;

impl RunEventSink for DiscardingSink {
    fn deliver(&mut self, _value: VmValue) -> Result<(), RunDeliveryError> {
        Ok(())
    }
}

/// Outcome of one run's delivery task.
#[derive(Default)]
pub struct DeliveryOutcome {
    /// First schema-violation message, if any event failed validation.
    pub schema_violation: Option<String>,
    /// At least one event could not be appended durably before publish.
    pub persist_failed: bool,
    /// Total events durably delivered.
    pub delivered: usize,
}

/// Outcome of one delivery critical section: the event was durably appended
/// and may be published, the run ended (stop the stream), or the durable
/// append failed (roll back in memory, report persist failure).
enum DeliverOutcome {
    Published(GatewayEvent, broadcast::Sender<GatewayEvent>),
    RunEnded,
    PersistFailed(String),
}

/// Durable live delivery for one run.
///
/// For every script event: validate against the agent event schema, assign
/// the monotonic per-run sequence, append durably (persist) and only then
/// publish to live subscribers. Nothing is published after the run commits a
/// terminal state, and a failed append is rolled back so no unpersisted event
/// is ever visible.
pub(crate) async fn run_delivery_task(
    context: DeliveryContext,
    run_id: String,
    mut receiver: tokio::sync::mpsc::Receiver<VmValue>,
) -> DeliveryOutcome {
    let mut outcome = DeliveryOutcome::default();
    while let Some(value) = receiver.recv().await {
        let event_type = match events::validate_script_event(&value) {
            Ok(event_type) => event_type.to_string(),
            Err(reason) => {
                if outcome.schema_violation.is_none() {
                    outcome.schema_violation = Some(reason.to_string());
                }
                context.metrics.events_dropped();
                continue;
            }
        };
        let data = events::script_event_data(&value);
        // The critical section (store write lock plus the blocking storage
        // worker round-trip) runs on a blocking thread so the request
        // runtime is never occupied by a storage stall.
        let context_for_block = DeliveryContext {
            store: Arc::clone(&context.store),
            persistence: context.persistence.clone(),
            config: Arc::clone(&context.config),
            metrics: Arc::clone(&context.metrics),
        };
        let run_id_for_block = run_id.clone();
        let event_type_for_block = event_type.clone();
        let data_for_block = data.clone();
        let delivered = tokio::task::spawn_blocking(move || {
            let mut store = context_for_block.store.write();
            let Some(run) = store.runs.get_mut(&run_id_for_block) else {
                return DeliverOutcome::RunEnded;
            };
            if matches!(
                run.status.as_str(),
                "completed" | "failed" | "cancelled" | "terminal_pending"
            ) {
                return DeliverOutcome::RunEnded;
            }
            let previous_events = run.events.clone();
            let event = append_event_locked(
                run,
                &event_type_for_block,
                data_for_block,
                context_for_block.config.max_event_bytes,
                context_for_block.config.max_events_per_run,
            );
            // Durable before visible: the event row is committed through the
            // typed `event.append` transaction while the write lock is held;
            // on failure the in-memory append is rolled back so no
            // unpersisted event is ever visible.
            let durable = match context_for_block.persistence.as_ref() {
                Some(persistence) => {
                    let payload = json!({
                        "run_id": run_id_for_block,
                        "event_id": event.event_id,
                        "event_type": event.event,
                        "payload_json": serde_json::to_string(&event.data)
                            .unwrap_or_else(|_| "{}".to_string()),
                        "now_ms": timestamp(),
                        "max_events": context_for_block.config.max_events_per_run,
                    });
                    persistence.event_append(&payload).map(|_| ())
                }
                None => Ok(()),
            };
            match durable {
                Ok(()) => DeliverOutcome::Published(
                    event,
                    run.sender
                        .as_ref()
                        .cloned()
                        .expect("the delivery channel exists while the run is active"),
                ),
                Err(error) => {
                    restore_events_after_failed_append(&mut run.events, previous_events);
                    DeliverOutcome::PersistFailed(error.to_string())
                }
            }
        })
        .await
        .expect("delivery task must complete");
        match delivered {
            DeliverOutcome::Published(event, sender) => {
                outcome.delivered += 1;
                context.metrics.events_emitted();
                let _ = sender.send(event);
            }
            DeliverOutcome::RunEnded => break,
            DeliverOutcome::PersistFailed(error) => {
                tracing::error!(
                    run_id,
                    op = "event.append",
                    error = %truncate_for_log(&error, 256),
                    "failed to append run event durably"
                );
                outcome.persist_failed = true;
                context.metrics.events_dropped();
            }
        }
    }
    outcome
}

fn compact_provider_error(error: Option<&Value>) -> Value {
    let Some(error) = error.and_then(Value::as_object) else {
        return Value::Null;
    };
    let mut compact = serde_json::Map::new();
    for key in ["type", "code", "message", "param", "request_id"] {
        if let Some(value) = error.get(key) {
            compact.insert(key.to_string(), value.clone());
        }
    }
    Value::Object(compact)
}

/// Restores the complete retained event snapshot after a failed durable
/// append. Retention may have removed older rows, so a length-based truncate
/// cannot restore the pre-append history.
pub(crate) fn restore_events_after_failed_append(
    events: &mut Vec<GatewayEvent>,
    previous_events: Vec<GatewayEvent>,
) {
    *events = previous_events;
}

/// Appends one event to the run's retained history and returns it with the
/// live delivery sender. Sequence and timestamps are AgentService-owned;
/// retention and byte bounds come from the validated configuration.
pub(crate) fn append_event_locked(
    run: &mut RunRecord,
    event_type: &str,
    mut data: Value,
    max_event_bytes: usize,
    max_events_per_run: usize,
) -> GatewayEvent {
    if serde_json::to_vec(&data)
        .map(|payload| payload.len() > max_event_bytes)
        .unwrap_or(true)
    {
        data = match event_type {
            "run.completed" => json!({
                "status": "completed",
                "message_id": data.get("message_id").cloned().unwrap_or(Value::Null),
                "usage": data.get("usage").cloned().unwrap_or(Value::Null),
            }),
            "run.failed" => json!({
                "status": "failed",
                "error_code": data.get("error_code").cloned().unwrap_or(Value::Null),
                "error_message": data.get("error_message").cloned().unwrap_or(Value::Null),
                "provider_error": compact_provider_error(data.get("provider_error")),
            }),
            "run.cancelled" => json!({
                "status": "cancelled",
                "reason": data.get("reason").cloned().unwrap_or(Value::Null),
            }),
            _ => json!({"truncated":true,"original_bytes":"over_limit"}),
        };
    }
    let seq = run.events.last().map(|event| event.seq + 1).unwrap_or(1);
    let event = GatewayEvent {
        event_id: Uuid::new_v4().to_string(),
        seq,
        event: event_type.to_string(),
        run_id: run.run_id.clone(),
        timestamp: timestamp(),
        data,
    };
    run.events.push(event.clone());
    if run.events.len() > max_events_per_run {
        let excess = run.events.len() - max_events_per_run;
        run.events.drain(0..excess);
    }
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_append_restores_the_full_retained_snapshot() {
        let old = vec![
            GatewayEvent {
                event_id: "old-1".to_string(),
                seq: 1,
                event: "model.delta".to_string(),
                run_id: "run-1".to_string(),
                timestamp: 1,
                data: json!({"delta": "first"}),
            },
            GatewayEvent {
                event_id: "old-2".to_string(),
                seq: 2,
                event: "model.delta".to_string(),
                run_id: "run-1".to_string(),
                timestamp: 2,
                data: json!({"delta": "second"}),
            },
        ];
        let mut retained = old.clone();
        retained.remove(0);
        retained.push(GatewayEvent {
            event_id: "new-3".to_string(),
            seq: 3,
            event: "run.completed".to_string(),
            run_id: "run-1".to_string(),
            timestamp: 3,
            data: json!({"status": "completed"}),
        });

        restore_events_after_failed_append(&mut retained, old.clone());
        assert_eq!(
            retained, old,
            "retention must not destroy the rollback snapshot"
        );
    }

    #[tokio::test]
    async fn full_bounded_channel_blocks_delivery_until_capacity_returns() {
        // The service-level delivery sink must pause the worker when the
        // bounded delivery path is full (backpressure): a delivery attempt
        // stays blocked until the receiver drains capacity. The sink uses
        // blocking_send, so the deliveries run on a plain thread (the sink
        // is only ever used from blocking worker threads).
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let mut sink = ChannelEventSink(sender);
        let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            sink.deliver(VmValue::Int(1)).expect("the first event fits");
            let _ = blocked_tx.send(());
            sink.deliver(VmValue::Int(2))
                .expect("delivery must resume after capacity returns");
        });
        blocked_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("the worker must fill the bounded channel");
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            !worker.is_finished(),
            "a full bounded delivery path must block the worker (backpressure)"
        );
        assert_eq!(
            receiver.recv().await.expect("receiver must drain"),
            VmValue::Int(1)
        );
        worker.join().expect("blocked delivery worker");
        assert_eq!(
            receiver.recv().await.expect("second event must arrive"),
            VmValue::Int(2)
        );
    }

    #[test]
    fn failed_terminal_append_after_retention_drain_restores_old_events_and_drops_new_unpersisted()
    {
        // Finding A: after retention has drained older events, a failed
        // durable terminal append must restore the pre-append retained
        // snapshot. A length-based `truncate(previous_len)` regression would
        // keep the unpersisted terminal (because retention keeps the length
        // constant) and drop the drained old event.
        fn run(max_events_per_run: usize) -> Vec<String> {
            let mut run = RunRecord {
                run_id: "run-1".to_string(),
                session_id: "session-1".to_string(),
                parent_run_id: None,
                request_overrides: Value::Null,
                platform: "api_server".to_string(),
                status: "running".to_string(),
                events: Vec::new(),
                sender: None,
                cancel_requested: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };
            append_event_locked(
                &mut run,
                "run.started",
                json!({"status":"running"}),
                1024,
                max_events_per_run,
            );
            append_event_locked(
                &mut run,
                "model.delta",
                json!({"delta":"hello"}),
                1024,
                max_events_per_run,
            );
            // The caller snapshots the retained history before the terminal
            // append, exactly as the terminal paths do.
            let previous_events = run.events.clone();
            let terminal = append_event_locked(
                &mut run,
                "run.completed",
                json!({"status":"completed"}),
                1024,
                max_events_per_run,
            );
            // Retention drained run.started on the third append; the new
            // terminal row is not yet durable.
            assert_eq!(terminal.event, "run.completed");
            assert_eq!(
                run.events
                    .iter()
                    .map(|e| e.event.as_str())
                    .collect::<Vec<_>>(),
                vec!["model.delta", "run.completed"]
            );
            restore_events_after_failed_append(&mut run.events, previous_events);
            run.events.iter().map(|e| e.event.clone()).collect()
        }
        // With retention 3 the pre-append snapshot is the same; but with
        // retention 2 the old run.started event was drained and must be
        // restored, while the unpersisted terminal must be removed.
        let restored_low = run(2);
        assert_eq!(
            restored_low,
            vec!["run.started", "model.delta"],
            "rollback must restore the drained old event and drop the unpersisted terminal"
        );
        assert!(
            !restored_low.contains(&"run.completed".to_string()),
            "the failure rollback must never keep the un-persisted terminal event"
        );
    }
}
