//! Gateway durable state: a dedicated storage worker thread executes every
//! RSS storage command off the Tokio request threads against the normalized
//! typed schema (`rss/storage/main.rss`), never the legacy blob adapter
//! (`rss/storage/gateway.rss`, retained only as an explicit migration
//! fixture).
//!
//! The worker owns the compiled `main.rss` program and serializes all
//! SQLite access through one connection per command. Callers submit a
//! request and block on the bounded response; the worker performs the RSS
//! invocation. `load()` migrates, runs transactional restart recovery in
//! bounded batches, then reconstructs the in-memory store from a
//! cursor-paginated dump — a load larger than any single page or byte limit
//! is drained completely, never silently truncated.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, RecvTimeoutError, Sender},
};
use std::time::{Duration, Instant};

use rustscript_vm::Value as VmValue;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::config::AgentGatewayConfig;
use crate::domain::{timestamp, vm_value_to_json};
use crate::{AgentConfig, AgentRunner};

/// Response timeout for one storage command; the worker is dedicated and
/// every RSS op is bounded, so this only guards against a wedged worker.
const STORAGE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// One absolute bound captured when a fixture pause or rendezvous is armed.
/// Entered and release waits consume the remainder; a phase does not start
/// another 5s, and unarmed production calls do not consult this bound.
const PLUGIN_CONTROL_FIXTURE_BOUND: Duration = Duration::from_secs(5);

pub(crate) const PLUGIN_CONTROL_FIXTURE_ABORTED: &str = "plugin_control_fixture_aborted";
pub(crate) const PLUGIN_CONTROL_FIXTURE_TIMEOUT: &str = "plugin_control_fixture_timeout";
pub(crate) const PLUGIN_CONTROL_FIXTURE_CLOSED: &str = "plugin_control_fixture_closed";

/// One recovery batch processes at most this many interrupted runs; the
/// gateway loops until a batch reports zero recovered.
const RECOVERY_BATCH: i64 = 512;

/// Page size used by the cursor-paginated `load.all` dump.
const LOAD_PAGE_ROWS: i64 = 512;

/// Per-page byte budget of the cursor-paginated `load.all` dump.
const LOAD_PAGE_BYTES: i64 = 2 * 1024 * 1024;

/// Hard total-row cap of the `load.all` dump: a state larger than this is
/// a typed `load_too_large` error, never a silent truncation.
const LOAD_CAP_ROWS: i64 = 1_000_000;

/// Column orders of the `load.all` rows (part of the command contract; see
/// `rss/storage/load.rss`).
/// sessions:   id, profile, platform, account_id, chat_id, thread_id,
///             user_id, generation, status, system_prompt, model, provider,
///             toolset_hash, metadata_json, last_message_seq, created_at_ms,
///             updated_at_ms, title, end_reason
/// messages:   ordinal, id, session_id, role, content_json, name,
///             tool_call_id, parent_message_id, token_estimate, compacted,
///             metadata_json, run_id, finish_reason, created_at_ms
/// runs:       id, session_id, parent_run_id, status, input_json, provider,
///             model, script_hash, idempotency_scope, idempotency_key,
///             turn_count, input_tokens, output_tokens, error_code,
///             error_message, recovery_reason, created_at_ms, started_at_ms,
///             finished_at_ms, updated_at_ms
/// events:     seq, run_id, event_id, event_type, payload_json, created_at_ms
/// jobs:       id, name, schedule_json, prompt, deliver_json, skills_json,
///             repeat_count, enabled, output_json, created_at_ms,
///             updated_at_ms, last_run_at_ms
/// idempotency: scope, key, request_hash, resource_type, resource_id, state,
///              response_json, created_at_ms, expires_at_ms, completed_at_ms
///
/// A typed storage command failure carrying the RSS error code.
#[derive(Debug, Clone)]
pub struct StorageError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for StorageError {}

type AdmissionPrecommitHook = Box<dyn FnOnce(&Value) + Send>;

#[cfg(test)]
type AdmissionPayloadTransform = Box<dyn FnOnce(&mut Value) + Send>;
#[cfg(test)]
type AdmissionResultObserver = Box<dyn FnOnce(AdmissionCommandCode) + Send>;

/// Code of one original admission command. The observer never receives the
/// payload, message, or headers.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdmissionCommandCode {
    pub ok: bool,
    pub code: String,
}

/// Applies a one-shot fixture closure to a shadow, then rejects every delta
/// except the existing failpoint field set to `after_commit_before_publish`.
#[cfg(test)]
fn admission_failpoint_shadow(payload: &Value, transform: AdmissionPayloadTransform) -> Value {
    let mut shadow = payload.clone();
    transform(&mut shadow);
    let mut expected = payload.clone();
    expected["failpoint"] = json!("after_commit_before_publish");
    if shadow.get("failpoint") != Some(&json!("after_commit_before_publish")) || shadow != expected
    {
        panic!("admission payload transform may only set failpoint=after_commit_before_publish");
    }
    shadow
}

#[cfg(feature = "config-fixture")]
struct ApprovalExpireHook {
    before: Box<dyn FnOnce() + Send>,
    completed: Box<dyn FnOnce(bool) + Send>,
}

fn managed_metadata_context() -> crate::RunCancellation {
    crate::RunCancellation::with_timeout(Duration::from_secs(5))
}

#[cfg(test)]
type ManagedRequestHook = Arc<dyn Fn(&str, &crate::RunCancellation, bool) + Send + Sync>;

pub struct GatewayPersistence {
    #[cfg(test)]
    pub(crate) managed_request_hook: Mutex<Option<ManagedRequestHook>>,
    #[cfg(feature = "workspace-io-fault")]
    drop_next_managed_commit_ack: Arc<AtomicBool>,
    /// Fixture-only: drop the next `effect.delegate_intent` request before the
    /// SDK executes it, so the caller observes ambiguity with nothing written.
    #[cfg(feature = "workspace-io-fault")]
    drop_next_managed_intent_without_apply: Arc<AtomicBool>,
    #[cfg(all(test, feature = "workspace-io-fault"))]
    maintenance_fault_statement: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    maintenance_reply_block: Mutex<Option<Arc<PersistBlockState>>>,
    /// Fixture-only one-shot park at the post-ack settlement phase of one
    /// `plugin.state_object_put`. The request's reply has already been
    /// published, so the observation never holds a sidecar open and forces no
    /// health, sweep, or retry. Production builds never have this slot.
    #[cfg(all(test, feature = "workspace-io-fault"))]
    state_owner_settle_gate: Arc<Mutex<Option<Arc<PersistBlockState>>>>,
    managed_pending: Arc<std::sync::atomic::AtomicUsize>,
    /// Per-root state writer leases shared by every store opened on this
    /// persistence. Checkpoint freezes exact roots here, not on the branch gate.
    pub(crate) plugin_state_writers: Arc<crate::plugins::PluginStateWriters>,
    /// Same-store Native revocation listeners shared by every store object
    /// opened on this persistence, so a second `PluginControlStore` cannot
    /// bypass same-process owner notification.
    pub(crate) managed_revoke_listeners: Arc<crate::effects::ManagedRevokeListeners>,
    /// In-flight migration candidate ids protected from the bounded orphan
    /// collector until their admission settles.
    pub(crate) plugin_state_candidates: Arc<crate::plugins::PluginStateCandidates>,
    worker: StorageWorker,
    max_events: i64,
    broadcast_capacity: usize,
    metrics: Arc<crate::metrics::Metrics>,
    fail_next: std::sync::atomic::AtomicBool,
    fail_after_partial_write: std::sync::atomic::AtomicBool,
    fail_after_commit_before_publish: std::sync::atomic::AtomicBool,
    fail_model_requested_append: std::sync::atomic::AtomicBool,
    fail_plugin_control_partial: std::sync::atomic::AtomicBool,
    persist_block: Mutex<Option<Arc<PersistBlockState>>>,
    /// Fixture-local one-shot rendezvous. Armed tests wait here after a stale
    /// pre-check and before the guarded command. Unarmed production calls do
    /// not wait. Dropping the controller aborts cloned waiters; clearing this
    /// slot alone does not.
    plugin_control_precommit_gate: Mutex<Option<Arc<PluginControlGate>>>,
    plugin_retain_precommit_pause: Mutex<Option<Arc<PluginRetainPause>>>,
    plugin_activate_receipt_hook: Mutex<Option<PluginActivateReceiptHook>>,
    admission_precommit_hook: Mutex<Option<AdmissionPrecommitHook>>,
    #[cfg(test)]
    admission_postcommit_hook: Mutex<Option<AdmissionPrecommitHook>>,
    /// One-shot shadow transform for the same `admission.create` command.
    /// Production builds do not have this slot.
    #[cfg(test)]
    admission_payload_transform: Mutex<Option<AdmissionPayloadTransform>>,
    /// One-shot read-only observer of the original command code.
    #[cfg(test)]
    admission_result_observer: Mutex<Option<AdmissionResultObserver>>,
    /// One-shot drop of a successful admission command ack. The transaction is
    /// not submitted again.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    admission_ack_loss: std::sync::atomic::AtomicBool,
    /// One-shot post-commit secondary-decode loss. Same seam as ack loss, with
    /// the existing `storage_error` code. Not a second RSS failpoint.
    #[cfg(test)]
    admission_secondary_decode_loss: std::sync::atomic::AtomicBool,
    /// One-shot precommit failure. Returns before the transaction, so no row
    /// is committed.
    #[cfg(test)]
    admission_precommit_fail: std::sync::atomic::AtomicBool,
    /// One-shot durable admission failpoint after the plugin state root CAS
    /// and binding statements. Arming it proves the transaction rolls the
    /// prepared migration back instead of publishing a root before admission.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    admission_state_fail: std::sync::atomic::AtomicBool,
    /// Test-only observer immediately before the caller issues the typed
    /// plugin state collection command. No behavior change.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    plugin_state_collect_observer: Mutex<Option<StorageUnitHook>>,
    /// One-shot real SQL failpoint for the typed plugin state collector. The
    /// same RSS transaction aborts; the collector surfaces the error.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    plugin_state_collect_failpoint: std::sync::atomic::AtomicBool,
    /// One-shot loss of a successful `plugin.state_object_put` reply after the
    /// durable object transaction. The transaction is not repeated.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    plugin_state_put_ack_loss: std::sync::atomic::AtomicBool,
    /// Fixture-only blocking observer after a real `plugin.state_object_put`
    /// is durable and before the producer returns. It observes the existing
    /// Native producer seam; it changes no put, reservation, or SQL state.
    #[cfg(feature = "workspace-io-fault")]
    plugin_state_object_put_observer: Mutex<Option<StorageStringHook>>,
    /// Fixture-only blocking observer after the typed collector command
    /// returns its real result and before the caller records collection
    /// health. No command, SQL, or debt state is changed by the observer.
    #[cfg(feature = "workspace-io-fault")]
    plugin_state_collect_result_observer: Mutex<Option<StorageBoolHook>>,
    /// Fixture-only observer at the caller's collector enqueue seam: after the
    /// execution epoch is snapshotted and before the typed request is issued.
    /// It reports the explicit/quiet health flag and changes no command,
    /// epoch, health, or SQL state.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    plugin_state_collect_enqueue_observer: Mutex<Option<StorageBoolHook>>,
    /// Fixture-only blocking hook at the exact storage-worker execution
    /// boundary, after a queued request is dequeued and before the protected
    /// set is read or any RSS/SQL command runs. It observes queue order only.
    #[cfg(feature = "workspace-io-fault")]
    worker_execute_gate: StorageExecuteGate,
    /// Fixture-only blocking observer right after the worker takes one
    /// `plugin.state_collect` snapshot (protected set + dirty generation)
    /// and before its RSS/SQL runs. Stored as the worker-thread slot below;
    /// a test parks the worker here to land a last-owner release mid-sweep
    /// and prove the later success clears just the covered generation.
    #[cfg(feature = "workspace-io-fault")]
    worker_collect_snapshot_gate: StorageSnapshotGate,
    /// Fixture-only shorter reply window for a controlled real RPC timeout.
    /// It never changes a command, deadline, cancellation, or protection rule.
    #[cfg(feature = "workspace-io-fault")]
    control_reply_timeout_override: Mutex<Option<Duration>>,
    /// Bounded `admission_replay` failures. Armed only after the original
    /// postcommit hook so precommit reads cannot consume them.
    #[cfg(test)]
    admission_replay_fail_remaining: Mutex<u32>,
    #[cfg(feature = "config-fixture")]
    approval_expire_hook: Mutex<Option<ApprovalExpireHook>>,
    #[cfg(test)]
    context_snapshot_read_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

/// Blocks the next storage command until [`PersistBlockGuard::release`].
pub struct PersistBlockGuard {
    inner: Arc<PersistBlockState>,
}

struct PersistBlockState {
    mutex: Mutex<()>,
    entered: AtomicBool,
    released: AtomicBool,
    entered_cvar: Condvar,
    released_cvar: Condvar,
    #[cfg(test)]
    entered_schedule: PersistBlockSchedule,
    #[cfg(test)]
    released_schedule: PersistBlockSchedule,
}

#[cfg(test)]
#[derive(Default)]
struct PersistBlockSchedule {
    before_wait: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    signal_started: Mutex<Option<mpsc::Sender<()>>>,
    signalled: Mutex<Option<mpsc::Sender<()>>>,
}

#[cfg(test)]
impl PersistBlockSchedule {
    fn before_wait(&self) {
        if let Some((arrived, resume)) = self.before_wait.lock().unwrap().take() {
            let _ = arrived.send(());
            let _ = resume.recv();
        }
    }

    fn signal_started(&self) {
        if let Some(started) = self.signal_started.lock().unwrap().take() {
            let _ = started.send(());
        }
    }

    fn signalled(&self) {
        if let Some(signalled) = self.signalled.lock().unwrap().take() {
            let _ = signalled.send(());
        }
    }
}

impl PersistBlockState {
    fn enter_and_wait(&self) {
        #[cfg(test)]
        self.entered_schedule.signal_started();
        // The predicate check and its transition share this instance mutex;
        // notification cannot slip between a false check and parking.
        let mut guard = self.mutex.lock().expect("persist block lock");
        self.entered.store(true, Ordering::SeqCst);
        self.entered_cvar.notify_all();
        #[cfg(test)]
        self.entered_schedule.signalled();
        while !self.released.load(Ordering::SeqCst) {
            #[cfg(test)]
            self.released_schedule.before_wait();
            guard = self
                .released_cvar
                .wait(guard)
                .expect("persist block release wait");
        }
    }
}

impl PersistBlockGuard {
    /// Waits until the next storage command has entered the persist path.
    pub fn wait_entered(&self) {
        let mut guard = self.inner.mutex.lock().expect("persist block lock");
        while !self.inner.entered.load(Ordering::SeqCst) {
            #[cfg(test)]
            self.inner.entered_schedule.before_wait();
            guard = self
                .inner
                .entered_cvar
                .wait(guard)
                .expect("persist block entered wait");
        }
    }

    /// Unblocks the waiting storage command.
    pub fn release(&self) {
        #[cfg(test)]
        self.inner.released_schedule.signal_started();
        // Release is also used during unwind. Recover this fixture's predicate
        // mutex so a poisoned lock cannot add a second cleanup panic.
        let _guard = self
            .inner
            .mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.inner.released.store(true, Ordering::SeqCst);
        self.inner.released_cvar.notify_all();
        #[cfg(test)]
        self.inner.released_schedule.signalled();
    }
}

type PluginActivateReceiptHook = Arc<dyn Fn() + Send + Sync>;

struct PluginRetainPauseState {
    entered: bool,
    released: bool,
    aborted: bool,
}

struct PluginRetainPause {
    mutex: Mutex<PluginRetainPauseState>,
    cvar: Condvar,
    deadline: Instant,
}

/// Pauses `plugin.retain` after the graph pre-read and before the retain command.
pub struct PluginRetainPauseGuard {
    inner: Arc<PluginRetainPause>,
}

fn lock_retain(pause: &PluginRetainPause) -> std::sync::MutexGuard<'_, PluginRetainPauseState> {
    pause
        .mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl PluginRetainPauseGuard {
    /// Fails if retain does not reach the precommit pause within the deadline
    /// captured when the pause was armed. This is a missed-seam detector, not
    /// a retry used to manufacture a race.
    pub fn wait_entered(&self) {
        let mut state = lock_retain(&self.inner);
        while !state.entered {
            let now = Instant::now();
            if state.aborted || now >= self.inner.deadline {
                panic!("plugin retain precommit pause was not entered");
            }
            let (next, timeout) = self
                .inner
                .cvar
                .wait_timeout(state, self.inner.deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if timeout.timed_out() && !state.entered {
                panic!("plugin retain precommit pause was not entered");
            }
        }
    }

    /// Lets the paused retain continue into its command.
    ///
    /// The released predicate and the notify happen under the same mutex the
    /// waiter uses, so a release that lands before `wait` is not lost.
    pub fn release(&self) {
        let mut state = lock_retain(&self.inner);
        if state.aborted {
            return;
        }
        state.released = true;
        self.inner.cvar.notify_all();
    }
}

impl Drop for PluginRetainPauseGuard {
    fn drop(&mut self) {
        let mut state = lock_retain(&self.inner);
        if state.released || state.aborted {
            return;
        }
        state.aborted = true;
        self.inner.cvar.notify_all();
    }
}

fn plugin_control_fixture_error(code: &'static str) -> StorageError {
    let message = match code {
        PLUGIN_CONTROL_FIXTURE_ABORTED => "plugin control fixture aborted",
        PLUGIN_CONTROL_FIXTURE_TIMEOUT => "plugin control fixture timed out",
        PLUGIN_CONTROL_FIXTURE_CLOSED => "plugin control fixture rendezvous is closed",
        _ => "plugin control fixture fault",
    };
    StorageError {
        code: code.to_string(),
        message: message.to_string(),
    }
}

struct PluginControlGateState {
    arrived: usize,
    completed: bool,
    aborted: bool,
}

struct PluginControlGate {
    mutex: Mutex<PluginControlGateState>,
    cvar: Condvar,
    parties: usize,
    deadline: Instant,
}

/// Aborts every cloned waiter of one armed rendezvous. Drop does not join
/// threads and does not call fixture callbacks.
#[must_use = "dropping the gate controller aborts waiters"]
pub struct PluginControlGateGuard {
    inner: Arc<PluginControlGate>,
}

impl PluginControlGate {
    fn lock(&self) -> std::sync::MutexGuard<'_, PluginControlGateState> {
        self.mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn abort(&self) {
        let mut state = self.lock();
        if state.completed || state.aborted {
            return;
        }
        state.aborted = true;
        self.cvar.notify_all();
    }
}

impl Drop for PluginControlGateGuard {
    fn drop(&mut self) {
        self.inner.abort();
    }
}

/// Owns the receipt hook claimed for one activation attempt. Drop discards an
/// unconsumed hook without running it and without holding the slot mutex.
pub(crate) struct PluginActivateReceiptAttempt {
    hook: Option<PluginActivateReceiptHook>,
}

impl PluginActivateReceiptAttempt {
    pub(crate) fn run(mut self) {
        if let Some(hook) = self.hook.take() {
            hook();
        }
    }
}

impl Drop for PluginActivateReceiptAttempt {
    fn drop(&mut self) {
        self.hook.take();
    }
}

pub(crate) struct ManagedMaintenanceClaim {
    permit: Arc<ManagedStoragePermit>,
    pub(crate) identity: crate::effects::ManagedWorkspaceIdentity,
    pub(crate) proof: String,
    pub(crate) request_id: String,
    pub(crate) action: &'static str,
    submitted: AtomicBool,
    settled: AtomicBool,
    failed: AtomicBool,
    busy: AtomicBool,
    read_busy: AtomicBool,
}
struct ManagedMaintenanceReadPermit(Arc<ManagedMaintenanceClaim>);
impl Drop for ManagedMaintenanceReadPermit {
    fn drop(&mut self) {
        self.0.read_busy.store(false, Ordering::Release);
    }
}

fn maintenance_data(result: Value) -> Result<Value, StorageError> {
    if result.get("ok") != Some(&Value::Bool(true)) {
        match result.get("code").and_then(Value::as_str) {
            Some("plugin_graph_revoked") => {
                return Err(StorageError {
                    code: "plugin_graph_revoked".into(),
                    message: "plugin graph is revoked".into(),
                });
            }
            Some("plugin_graph_pin_required") => {
                return Err(StorageError {
                    code: "plugin_graph_pin_required".into(),
                    message: "tool graph pin is required".into(),
                });
            }
            _ => {}
        }
        return Err(StorageError {
            code: "managed_transaction_rolled_back".into(),
            message: "managed transaction rejected".into(),
        });
    }
    decode_command_data(result.get("data").cloned().unwrap_or(Value::Null))
}
impl ManagedMaintenanceClaim {
    pub(crate) fn submitted(&self) -> bool {
        self.submitted.load(Ordering::Acquire)
    }
    pub(crate) fn worker_failed(&self) -> bool {
        self.settled.load(Ordering::Acquire) && self.failed.load(Ordering::Acquire)
    }
}
impl GatewayPersistence {
    #[cfg(test)]
    pub(crate) fn record_synthetic_usage_for_test(
        &self,
        run_id: &str,
    ) -> Result<Value, StorageError> {
        self.command_data("run.usage", &json!({"id":"frozen-usage-fact","run_id":run_id,"provider":"synthetic","model":"synthetic","request_count":1,"input_tokens":17,"output_tokens":9,"reasoning_tokens":3,"cached_tokens":2,"now_ms":10}))
    }
    #[cfg(test)]
    pub(crate) fn block_maintenance_reply_for_test(&self) -> PersistBlockGuard {
        let guard = self.inject_block_persist();
        *self.maintenance_reply_block.lock().unwrap() = self.persist_block.lock().unwrap().take();
        guard
    }
    /// Fixture-only one-shot park on the next `plugin.state_object_put`
    /// post-ack settlement phase: after its reply is published. It never
    /// changes the reply, a reservation, or any collector health.
    #[cfg(all(test, feature = "workspace-io-fault"))]
    pub(crate) fn block_state_owner_settle_for_test(&self) -> PersistBlockGuard {
        let inner = Arc::new(PersistBlockState {
            mutex: Mutex::new(()),
            entered: AtomicBool::new(false),
            released: AtomicBool::new(false),
            entered_cvar: Condvar::new(),
            released_cvar: Condvar::new(),
            entered_schedule: PersistBlockSchedule::default(),
            released_schedule: PersistBlockSchedule::default(),
        });
        *self
            .state_owner_settle_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::clone(&inner));
        PersistBlockGuard { inner }
    }
    #[cfg(test)]
    pub(crate) fn fill_pending_for_test(&self) -> impl Sized {
        (self.managed_pending.load(Ordering::Acquire)..32)
            .map(|_| ManagedStoragePermit::acquire(&self.managed_pending).unwrap())
            .collect::<Vec<_>>()
    }
    #[cfg(test)]
    pub(crate) fn pending_count_for_test(&self) -> usize {
        self.managed_pending.load(Ordering::Acquire)
    }
    pub(crate) fn plugin_state_writers(&self) -> &crate::plugins::PluginStateWriters {
        &self.plugin_state_writers
    }
    pub(crate) fn managed_revoke_listeners(&self) -> &crate::effects::ManagedRevokeListeners {
        &self.managed_revoke_listeners
    }
    pub(crate) fn maintenance_claim(
        &self,
        identity: crate::effects::ManagedWorkspaceIdentity,
        proof: String,
        request_id: String,
        action: &'static str,
    ) -> Result<Arc<ManagedMaintenanceClaim>, String> {
        Ok(Arc::new(ManagedMaintenanceClaim {
            permit: Arc::new(ManagedStoragePermit::acquire(&self.managed_pending)?),
            identity,
            proof,
            request_id,
            action,
            submitted: AtomicBool::new(false),
            settled: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            read_busy: AtomicBool::new(false),
        }))
    }
    pub(crate) fn maintenance_submit(
        &self,
        claim: &Arc<ManagedMaintenanceClaim>,
        payload: &Value,
        cancellation: &crate::RunCancellation,
    ) -> Result<Value, StorageError> {
        let (proof, request_id, workspace_id, branch_id, store_id) = if claim.action == "checkpoint"
        {
            let value = crate::plugins::strict_managed_yaml_to_json(
                payload["maintenance_json"].as_str().unwrap_or_default(),
            )
            .map_err(|_| crate::effects::journal::storage_error("managed metadata invalid"))?;
            crate::effects::journal::validate_maintenance_value::<
                crate::effects::journal::ManagedCheckpointCommitInput,
            >(&value)
            .map_err(crate::effects::journal::storage_error)?;
            let input: crate::effects::journal::ManagedCheckpointCommitInput =
                serde_json::from_str(payload["maintenance_json"].as_str().unwrap_or_default())
                    .map_err(|_| {
                        crate::effects::journal::storage_error(
                            "managed maintenance identity mismatch",
                        )
                    })?;
            (
                input.original_request_proof,
                input.request.request_id,
                input.captured_source.workspace_id,
                input.captured_source.branch_id,
                input.captured_source.store_id,
            )
        } else {
            let value = crate::plugins::strict_managed_yaml_to_json(
                payload["restore_json"].as_str().unwrap_or_default(),
            )
            .map_err(|_| crate::effects::journal::storage_error("managed metadata invalid"))?;
            crate::effects::journal::validate_maintenance_value::<
                crate::effects::journal::ManagedRestoreExecutionEnvelope,
            >(&value)
            .map_err(crate::effects::journal::storage_error)?;
            let input: crate::effects::journal::ManagedRestoreExecutionEnvelope =
                serde_json::from_str(payload["restore_json"].as_str().unwrap_or_default())
                    .map_err(|_| {
                        crate::effects::journal::storage_error(
                            "managed maintenance identity mismatch",
                        )
                    })?;
            (
                input.original_request_proof,
                input.request.request_id,
                input.request.expected_source.workspace_id,
                input.request.expected_source.branch_id,
                input.request.expected_source.store_id,
            )
        };
        if proof != claim.proof
            || request_id != claim.request_id
            || workspace_id != claim.identity.workspace_id
            || branch_id != claim.identity.branch_id
            || store_id != claim.identity.store_id
            || !Arc::ptr_eq(&claim.permit.0, &self.managed_pending)
        {
            return Err(crate::effects::journal::storage_error(
                "managed maintenance identity mismatch",
            ));
        }
        if claim.action == "restore" {
            #[cfg(test)]
            if let Some(hook) = self
                .admission_precommit_hook
                .lock()
                .expect("admission hook")
                .take()
            {
                hook(payload);
            }
            validate_composed_restore_budget(payload).map_err(|_| StorageError {
                code: "managed_metadata_budget_exceeded".into(),
                message: "managed_metadata_budget_exceeded".into(),
            })?;
        }
        if claim.busy.swap(true, Ordering::AcqRel) || claim.settled.load(Ordering::Acquire) {
            return Err(crate::effects::journal::storage_error(
                "managed maintenance claim already submitted",
            ));
        }
        #[cfg(all(test, feature = "workspace-io-fault"))]
        let payload = {
            let mut payload = payload.clone();
            let statement = self.maintenance_fault_statement.swap(0, Ordering::AcqRel);
            if statement != 0 {
                if claim.action == "checkpoint" {
                    payload["cut"] = json!("managed_rollback");
                } else {
                    payload["failpoint"] = json!(format!("managed_statement_{statement}"));
                }
            }
            payload
        };
        #[cfg(all(test, feature = "workspace-io-fault"))]
        let payload = &payload;
        let outcome = if claim.action == "checkpoint" {
            self.managed_effect_command_claim(
                "effect.checkpoint_create",
                payload,
                Some(cancellation),
                Some(claim),
                None,
            )
        } else {
            self.command_with_claim(
                "admission.create",
                payload,
                Some(cancellation),
                Some(claim),
                StorageRequestOptions {
                    report_health: true,
                    ..StorageRequestOptions::default()
                },
            )
            .map_err(|message| StorageError {
                code: "storage_unavailable".into(),
                message,
            })
            .and_then(maintenance_data)
        };
        outcome.map_err(|error| {
            // These closed RSS classifications follow a transaction whose
            // every admission write was disabled by the same pin predicate.
            if matches!(
                error.code.as_str(),
                "plugin_graph_revoked" | "plugin_graph_pin_required"
            ) {
                return error;
            }
            StorageError {
                code: if claim.submitted() {
                    "managed_submitted_unknown"
                } else {
                    "managed_not_submitted"
                }
                .into(),
                message: error.message,
            }
        })
    }
    pub(crate) fn maintenance_read(
        &self,
        claim: &Arc<ManagedMaintenanceClaim>,
        identity: &crate::effects::ManagedWorkspaceIdentity,
        proof: &str,
        op: &str,
        payload: &Value,
        cancellation: &crate::RunCancellation,
    ) -> Result<Value, String> {
        if !claim.settled.load(Ordering::Acquire) {
            return Err("managed_submitted_unknown".into());
        }
        if !Arc::ptr_eq(&claim.permit.0, &self.managed_pending)
            || &claim.identity != identity
            || claim.proof != proof
            || !matches!(
                op,
                "effect.maintenance_receipt" | "effect.branch_publication_history"
            )
            || payload["workspace_id"].as_str() != Some(identity.workspace_id.as_str())
        {
            return Err("managed_restore_reconciliation_required".into());
        }
        if payload["receipt_id"] != claim.request_id
            || (op == "effect.maintenance_receipt" && payload["cut"] != claim.action)
        {
            return Err("managed_restore_reconciliation_required".into());
        }
        if op == "effect.branch_publication_history" && payload["cut"] == "checkpoint_rollback" {
            let input: crate::effects::journal::ManagedCheckpointCommitInput =
                serde_json::from_str(payload["record_json"].as_str().unwrap_or_default())
                    .map_err(|_| "managed_restore_reconciliation_required")?;
            if claim.action != "checkpoint"
                || input.original_request_proof != claim.proof
                || input.request.request_id != claim.request_id
            {
                return Err("managed_restore_reconciliation_required".into());
            }
        }
        if op == "effect.branch_publication_history" && payload["cut"] == "rollback" {
            let envelope: crate::effects::journal::ManagedRestoreExecutionEnvelope =
                serde_json::from_str(payload["record_json"].as_str().unwrap_or_default())
                    .map_err(|_| "managed_restore_reconciliation_required")?;
            if envelope.original_request_proof != claim.proof
                || envelope.request.request_id != claim.request_id
            {
                return Err("managed_restore_reconciliation_required".into());
            }
        }
        self.managed_effect_command_claim(op, payload, Some(cancellation), Some(claim), None)
            .map_err(|_| "managed_submitted_unknown".into())
    }
}

struct ManagedStoragePermit(Arc<std::sync::atomic::AtomicUsize>);
impl ManagedStoragePermit {
    fn acquire(pending: &Arc<std::sync::atomic::AtomicUsize>) -> Result<Self, String> {
        pending
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 32).then_some(count + 1)
            })
            .map_err(|_| "managed storage pending-operation bound exceeded".to_string())?;
        Ok(Self(Arc::clone(pending)))
    }
}
impl Drop for ManagedStoragePermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One serialized storage request for the dedicated worker thread.
struct StorageRequest {
    op: String,
    payload: Value,
    respond: Sender<Result<Value, String>>,
    cancellation: Option<crate::RunCancellation>,
    _managed_permit: Option<Arc<ManagedStoragePermit>>,
    maintenance: Option<Arc<ManagedMaintenanceClaim>>,
    _maintenance_read: Option<ManagedMaintenanceReadPermit>,
    /// Strong Native reservation sidecar: keeps every unsettled object this
    /// request references protected until the worker settles it. The caller
    /// releases only its own reference; ownership is never handed off with a
    /// flag and never rebuilt from JSON or guest ids. Pure identity, held
    /// beside the VM/guest/grant state but never serialized into it.
    state_owner: Option<crate::plugins::PluginStateCandidateLease>,
    /// Whether this collect updates worker-ordered GC health. Explicit
    /// collector invocations report; backpressure-path reclamation sweeps do
    /// not clear debt on their own.
    report_health: bool,
    #[cfg(test)]
    reply_block: Option<Arc<PersistBlockState>>,
}

/// Named aliases for the fixture observers/gates. Keeps the optional worker
/// and observer declarations readable without a broad `type_complexity` allow.
#[cfg(any(test, feature = "workspace-io-fault"))]
type StorageUnitHook = Arc<dyn Fn() + Send + Sync>;

#[cfg(any(test, feature = "workspace-io-fault"))]
type StorageStringHook = Arc<dyn Fn(&str) + Send + Sync>;

#[cfg(any(test, feature = "workspace-io-fault"))]
type StorageBoolHook = Arc<dyn Fn(bool) + Send + Sync>;

/// Fixture-only observer of one worker `plugin.state_collect` snapshot: the
/// dirty generation the sweep covers. It reports the already-taken snapshot
/// value and can never change the snapshot, the payload, or any health state.
#[cfg(feature = "workspace-io-fault")]
type StorageGenerationHook = Arc<dyn Fn(u64) + Send + Sync>;

/// Named alias for the optional fixture-only worker execution gate slot.
#[cfg(feature = "workspace-io-fault")]
type StorageExecuteGate = Arc<Mutex<Option<StorageStringHook>>>;

/// Named alias for the optional fixture-only worker collect-snapshot slot.
#[cfg(feature = "workspace-io-fault")]
type StorageSnapshotGate = Arc<Mutex<Option<StorageGenerationHook>>>;

/// Optional per-request storage-command settings. Bundling these keeps the
/// internal claim/owner/report switches out of the positional signature.
#[derive(Default)]
struct StorageRequestOptions {
    read_timeout: Option<Duration>,
    state_owner: Option<crate::plugins::PluginStateCandidateLease>,
    report_health: bool,
}

/// The dedicated storage worker: owns the compiled RSS program and executes
/// every command on its own thread.
struct StorageWorker {
    sender: Sender<StorageRequest>,
    shutdown: Sender<()>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    closed: std::sync::atomic::AtomicBool,
    #[cfg(any(test, feature = "workspace-io-fault"))]
    executed_commands: Arc<std::sync::atomic::AtomicUsize>,
}

struct StorageRunner {
    runner: AgentRunner,
    db_path: String,
    max_events: i64,
    #[cfg(any(test, feature = "workspace-io-fault"))]
    executed_commands: Arc<std::sync::atomic::AtomicUsize>,
}

impl StorageRunner {
    fn open(config: &AgentGatewayConfig, path: &Path) -> Result<Self, String> {
        let root = path.parent().unwrap_or_else(|| Path::new("."));
        let agent_config = AgentConfig {
            http: config.http.clone(),
            sqlite: config.sqlite.clone(),
            fuel: config.fuel,
        }
        .with_sqlite_root(root);
        let runner = AgentRunner::from_bundled("rss/storage/main.rss", agent_config)
            .map_err(|error| format!("compile RSS storage program: {error}"))?;
        let db_path = path
            .file_name()
            .ok_or_else(|| "gateway SQLite state path must name a file".to_string())?
            .to_string_lossy()
            .into_owned();
        Ok(Self {
            runner,
            db_path,
            max_events: config.max_events_per_run as i64,
            #[cfg(any(test, feature = "workspace-io-fault"))]
            executed_commands: Arc::default(),
        })
    }

    fn command(
        &self,
        op: &str,
        payload: &Value,
        cancellation: Option<&crate::RunCancellation>,
    ) -> Result<Value, String> {
        if cancellation
            .is_some_and(|cancel| cancel.requested().is_some() || cancel.deadline_passed())
        {
            return Err("managed storage original deadline/cancellation".into());
        }
        #[cfg(any(test, feature = "workspace-io-fault"))]
        self.executed_commands.fetch_add(1, Ordering::Relaxed);
        let input = VmValue::map(vec![
            (VmValue::string("op"), VmValue::string(op)),
            (
                VmValue::string("request_id"),
                VmValue::string(Uuid::new_v4().to_string()),
            ),
            (
                VmValue::string("db_path"),
                VmValue::string(self.db_path.clone()),
            ),
            (
                VmValue::string("db_mode"),
                VmValue::string("read_write_create"),
            ),
            (VmValue::string("busy_timeout_ms"), VmValue::Int(5_000)),
            (VmValue::string("max_rows"), VmValue::Int(LOAD_PAGE_ROWS)),
            (VmValue::string("max_bytes"), VmValue::Int(LOAD_PAGE_BYTES)),
            (VmValue::string("max_events"), VmValue::Int(self.max_events)),
            (VmValue::string("max_messages"), VmValue::Int(128)),
            (VmValue::string("now_ms"), VmValue::Int(timestamp() as i64)),
            (
                VmValue::string("payload_json"),
                VmValue::string(payload.to_string()),
            ),
        ]);
        let execution = if let Some(cancellation) = cancellation {
            self.runner
                .run_with_context_and_events(input, &mut StorageNoEvents, cancellation)
        } else {
            self.runner.run_with_context(input)
        };
        let result =
            execution.map_err(|error| format!("run RSS storage operation {op}: {error}"))?;
        let VmValue::Map(result) = result else {
            return Err(format!(
                "RSS storage operation {op} returned a non-map result"
            ));
        };
        Ok(vm_value_to_json(&VmValue::Map(result)))
    }
}

struct StorageNoEvents;
impl crate::RunEventSink for StorageNoEvents {
    fn deliver(&mut self, _value: VmValue) -> Result<(), crate::RunDeliveryError> {
        Err(crate::RunDeliveryError::Rejected {
            code: "managed_storage_event_denied",
            message: "storage command cannot emit live events".into(),
        })
    }
}

/// Runs the worker loop: execute one request at a time on this dedicated
/// thread, then answer. A dropped sender (or shutdown signal) ends the loop.
fn storage_worker_loop(
    runner: StorageRunner,
    requests: Receiver<StorageRequest>,
    shutdown: Receiver<()>,
    _managed_ack_faults: (Arc<AtomicBool>, Arc<AtomicBool>),
    state_candidates: Arc<crate::plugins::PluginStateCandidates>,
    #[cfg(feature = "workspace-io-fault")] worker_gates: (StorageExecuteGate, StorageSnapshotGate),
    #[cfg(all(test, feature = "workspace-io-fault"))] settle_gate: Arc<
        Mutex<Option<Arc<PersistBlockState>>>,
    >,
) {
    #[cfg(feature = "workspace-io-fault")]
    let (execute_gate, collect_snapshot_gate) = worker_gates;
    loop {
        match requests.recv_timeout(Duration::from_millis(200)) {
            Ok(mut request) => {
                // Fixture-only observation of the exact worker execution
                // boundary. Production builds never block here.
                #[cfg(feature = "workspace-io-fault")]
                if let Some(gate) = execute_gate
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
                {
                    gate(&request.op);
                }
                // The caller health check is only early refusal, never an
                // execution permit: every `plugin.state_object_put` re-applies
                // the current worker-ordered health/dirty decision at this
                // exact execution boundary, before any durable write. A caller
                // that passed an older Healthy check cannot cross a newer
                // Debt or a pending dirty generation. Refusal carries the
                // exact typed code and never becomes durable.
                if request.op == "plugin.state_object_put" {
                    let (health_state, pending) = state_candidates.admission_snapshot();
                    if health_state != crate::plugins::CollectorHealthState::Healthy || pending {
                        // No SDK runs and nothing is written: release this
                        // request's own reservation sidecar before publishing
                        // the original typed refusal, so a caller that acts on
                        // the refusal never observes this request's release
                        // afterwards. The conservative dirty mark is unchanged.
                        drop(request.state_owner.take());
                        let _ = request.respond.send(Ok(serde_json::json!({
                            "ok": false,
                            "code": "plugin_state_unavailable",
                            "message": "state collection is not proven or has pending dirty objects; new objects are refused",
                        })));
                        continue;
                    }
                }
                // The protected candidate set and the dirty generation are
                // read together at this exact execution boundary under one
                // registry lock. A caller-supplied snapshot can be stale; the
                // worker order (register-before-put, FIFO) makes this pair
                // authoritative. A later success only clears the generation
                // observed here.
                let mut collect_generation: Option<u64> = None;
                if request.op == "plugin.state_collect" {
                    let (protected, dirty_generation) = state_candidates.snapshot_for_collect();
                    collect_generation = Some(dirty_generation);
                    // Fixture-only observation of the covered generation. The
                    // snapshot is already taken; the observer only reads it.
                    #[cfg(feature = "workspace-io-fault")]
                    if let Some(observer) = collect_snapshot_gate
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone()
                    {
                        observer(dirty_generation);
                    }
                    match serde_json::to_string(&protected) {
                        Ok(protected_json) => {
                            request.payload["protected_ids_json"] =
                                Value::String(protected_json.clone());
                            // Native budget on the injected payload, before any
                            // RSS/SQL runs: count, full wire bytes, and
                            // aggregate parameter-repeat weight. The RSS 1 MiB
                            // SQL parameter limit is not a substitute for this
                            // Native injection accounting. Overbudget is a typed
                            // fail-closed rejection: no SQL executes, the
                            // protected set stays readable, and GC health keeps
                            // debt until an explicit sweep recovers.
                            let wire_len = serde_json::to_vec(&request.payload)
                                .map(|wire| wire.len())
                                .unwrap_or(usize::MAX);
                            let aggregate = protected_json
                                .len()
                                .saturating_mul(2)
                                .saturating_add(protected.len().saturating_mul(64))
                                .saturating_add(wire_len);
                            #[cfg(any(test, feature = "workspace-io-fault"))]
                            state_candidates.report_collect_budget_inputs(
                                protected.len(),
                                wire_len,
                                aggregate,
                            );
                            if protected.len() > crate::plugins::PLUGIN_STATE_MAX_RESERVATIONS
                                || wire_len > crate::effects::journal::METADATA_BYTES
                                || aggregate > crate::effects::journal::METADATA_BYTES
                            {
                                // Native overbudget is a real collector
                                // failure: keep worker-ordered Debt. No SQL
                                // executes and the protected set stays
                                // readable until an explicit sweep recovers.
                                state_candidates.record_collect_failure();
                                let _ = request.respond.send(Ok(serde_json::json!({
                                    "ok": false,
                                    "code": "plugin_state_budget_exceeded",
                                    "message": "injected collector payload exceeds the Native budget",
                                })));
                                continue;
                            }
                        }
                        Err(_) => {
                            // Fail closed: never fall back to an empty
                            // protection set. No SQL executes, and the
                            // unevaluated sweep is recorded as a real
                            // worker-ordered failure, never as success.
                            state_candidates.record_collect_failure();
                            let _ = request.respond.send(Ok(serde_json::json!({
                                "ok": false,
                                "code": "plugin_state_unavailable",
                                "message": "collector protection set is not encodable",
                            })));
                            continue;
                        }
                    }
                }
                #[cfg(feature = "workspace-io-fault")]
                if request.op == "effect.delegate_intent"
                    && _managed_ack_faults.1.swap(false, Ordering::AcqRel)
                {
                    // Fixture-only: drop the request before the SDK executes it.
                    // Nothing is written and the caller observes transport
                    // ambiguity (an unequal read-back), never a refusal.
                    continue;
                }
                let result =
                    runner.command(&request.op, &request.payload, request.cancellation.as_ref());
                // Every collect outcome is recorded by this same worker in
                // execution order. A typed `ok: false` envelope is a real
                // failure even when the transport succeeded; `result.is_ok`
                // alone must never mark it success. Quiet sweeps report
                // failures too (a newer explicit success cannot be shadowed
                // by an older quiet result because the worker order is total),
                // while a quiet success never clears existing Debt: only an
                // explicit successful sweep proves recovery.
                if request.op == "plugin.state_collect" {
                    let succeeded = result
                        .as_ref()
                        .is_ok_and(|value| value.get("ok") == Some(&Value::Bool(true)));
                    if succeeded {
                        state_candidates.record_collect_success(
                            collect_generation.unwrap_or(0),
                            request.report_health,
                        );
                    } else {
                        state_candidates.record_collect_failure();
                    }
                }
                #[cfg(test)]
                if let Some(block) = request.reply_block.take() {
                    block.enter_and_wait();
                }
                // The SDK operation has settled; acknowledge only after its
                // Native admission charge is released, even if the receiver left.
                if let Some(claim) = &request.maintenance
                    && (request.op == "admission.create"
                        || request.op == "effect.checkpoint_create")
                {
                    claim.failed.store(
                        !result
                            .as_ref()
                            .is_ok_and(|value| value.get("ok") == Some(&Value::Bool(true))),
                        Ordering::Release,
                    );
                    claim.settled.store(true, Ordering::Release);
                }
                drop(request._maintenance_read.take());
                drop(request._managed_permit.take());
                // The SDK operation and all of its worker bookkeeping have
                // settled. Release the worker-owned clone of this request's
                // Native reservation sidecar now, before any reply (or an
                // intentionally closed ack channel) can be observed. The clone
                // is not assumed to be the last owner: if it is, a sequential
                // caller already observes the dirty generation and performs
                // its own bounded sweep before enqueueing; if the caller still
                // holds the last reference, its drop records the generation on
                // return, before its next put.
                #[cfg(all(test, feature = "workspace-io-fault"))]
                let had_state_owner = request.state_owner.is_some();
                drop(request.state_owner.take());
                #[cfg(feature = "workspace-io-fault")]
                if (request.op == "effect.commit"
                    || request.op == "effect.delegate_intent"
                    || request.op == "effect.checkpoint_create"
                    || (request.op == "admission.create"
                        && request
                            .payload
                            .get("restore_json")
                            .and_then(Value::as_str)
                            .is_some_and(|value| !value.is_empty())))
                    && result
                        .as_ref()
                        .is_ok_and(|value| value.get("ok") == Some(&Value::Bool(true)))
                    && _managed_ack_faults.0.swap(false, Ordering::AcqRel)
                {
                    // Discard the real successful SDK reply by closing its
                    // response sender. The durable transaction is not undone.
                    continue;
                }
                let _ = request.respond.send(result);
                // Fixture-only park at the same post-ack settlement phase as
                // the original order: the reply is already published, so this
                // observation never holds a sidecar open. It changes no
                // admission, health, or durable state and forces no sweep.
                #[cfg(all(test, feature = "workspace-io-fault"))]
                if had_state_owner
                    && let Some(block) = settle_gate
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .take()
                {
                    block.enter_and_wait();
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if shutdown.try_recv().is_ok() {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompactionContextQuery {
    columns: Vec<String>,
    rows: Vec<Value>,
    truncated: bool,
    next_cursor: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactionContextSnapshotWire {
    session: CompactionContextQuery,
    messages: CompactionContextQuery,
    summary_loaded: bool,
    latest: CompactionContextQuery,
}

pub(crate) struct CompactionContextSnapshot {
    pub(crate) session: Value,
    pub(crate) messages: Value,
    pub(crate) summary_loaded: bool,
    pub(crate) latest: Value,
}

impl CompactionContextSnapshot {
    fn decode(data: Value) -> Result<Self, StorageError> {
        let invalid = |message: String| StorageError {
            code: "snapshot_invalid".to_string(),
            message,
        };
        let wire: CompactionContextSnapshotWire = serde_json::from_value(data)
            .map_err(|error| invalid(format!("decode context snapshot: {error}")))?;
        let mut snapshot = Self {
            session: json!(wire.session),
            messages: json!(wire.messages),
            summary_loaded: wire.summary_loaded,
            latest: json!(wire.latest),
        };
        for query in [
            &mut snapshot.session,
            &mut snapshot.messages,
            &mut snapshot.latest,
        ] {
            if query.get("truncated").and_then(Value::as_bool) != Some(false) {
                return Err(invalid(
                    "context snapshot query is truncated or omitted its bound marker".into(),
                ));
            }
            *query = decode_command_data(std::mem::take(query))?;
            crate::sqlite_storage_rows::sqlite_storage_rows(query).map_err(invalid)?;
        }
        let session_rows =
            crate::sqlite_storage_rows::sqlite_storage_rows(&snapshot.session).map_err(invalid)?;
        if session_rows.len() != 1 || session_rows[0].get(7).and_then(Value::as_i64).is_none() {
            return Err(invalid(
                "context snapshot session or generation is missing or invalid".into(),
            ));
        }
        let messages =
            crate::sqlite_storage_rows::sqlite_storage_rows(&snapshot.messages).map_err(invalid)?;
        let latest =
            crate::sqlite_storage_rows::sqlite_storage_rows(&snapshot.latest).map_err(invalid)?;
        if messages.len() > 128
            || snapshot.summary_loaded != (messages.len() < 128)
            || (!snapshot.summary_loaded && !latest.is_empty())
        {
            return Err(invalid(
                "context snapshot summary marker disagrees with its page".into(),
            ));
        }
        Ok(snapshot)
    }
}

// Fixed RSS text-parameter occurrences. Count all mutually exclusive resend
// branches conservatively; do not depend on a storage prequery for admission.
// The paired source-catalog test requires an explicit update on RSS changes.
fn managed_parameter_bindings(op: &str) -> &'static [(&'static str, usize)] {
    match op {
        "effect.workspace_get" => &[
            ("store_id", 1),
            ("profile", 1),
            ("source_device", 1),
            ("source_inode", 1),
        ],
        "effect.workspace_register" => &[
            ("workspace_json", 12),
            ("store_id", 4),
            ("profile", 4),
            ("source_device", 4),
            ("source_inode", 4),
        ],
        "effect.run_binding" => &[("run_id", 1)],
        "effect.run_list" | "effect.run_list_has_more" | "effect.run_cursor" => &[
            ("run_id", 1),
            ("profile", 1),
            ("session_id", 1),
            ("workspace_id", 1),
            ("branch_id", 1),
            ("after_effect_id", 1),
        ],
        "effect.head" => &[("workspace_id", 1), ("branch_id", 1)],
        "effect.get" => &[("run_id", 1), ("call_id", 1), ("profile", 1)],
        "effect.begin" => &[
            ("effect_id", 6),
            ("run_id", 23),
            ("call_id", 2),
            ("record_json", 12),
            ("workspace_id", 2),
            ("branch_id", 2),
            ("commit_id", 3),
            ("projections_json", 10),
            ("cut", 1),
            ("sealed_class", 2),
        ],
        "effect.checkpoint_context" => &[
            ("run_id", 1),
            ("workspace_id", 1),
            ("branch_id", 1),
            ("profile", 1),
        ],
        "effect.maintenance_receipt" => &[("workspace_id", 2), ("receipt_id", 2)],
        "effect.branch_publication_history" => {
            &[("workspace_id", 3), ("receipt_id", 1), ("record_json", 20)]
        }
        "effect.checkpoint_get" => &[("workspace_id", 1), ("commit_id", 1)],
        "effect.checkpoint_create" => &[("maintenance_json", 38)],
        "effect.branch_create" => &[("maintenance_json", 62)],
        "effect.branch_receipt" => &[("workspace_id", 1), ("receipt_id", 1)],
        "effect.branch_origin" => &[("workspace_id", 2), ("branch_id", 3)],
        "effect.publish_eligibility" => &[("maintenance_json", 31)],
        "effect.publish_submit" => &[("maintenance_json", 86)],
        "effect.publish_receipt" => &[("maintenance_json", 2)],
        "effect.publication_get" => &[("maintenance_json", 2)],
        "effect.prepare" => &[
            ("effect_id", 5),
            ("receipt_id", 2),
            ("prepared_json", 5),
            ("record_json", 3),
            ("cut", 1),
        ],
        "effect.delegate_intent" => &[
            ("effect_id", 2),
            ("run_id", 1),
            ("call_id", 1),
            ("workspace_id", 1),
            ("branch_id", 1),
            ("record_json", 8),
        ],
        "effect.commit" => &[
            ("effect_id", 13),
            ("run_id", 7),
            ("workspace_id", 2),
            ("branch_id", 2),
            ("commit_id", 8),
            ("receipt_id", 1),
            ("prepared_json", 50),
            ("cut", 5),
            ("projections_json", 15),
        ],
        "effect.recover_one" => &[
            ("commit_id", 4),
            ("projections_json", 15),
            ("effect_id", 5),
            ("run_id", 5),
        ],
        "effect.recovery_context" => &[("call_id", 1), ("run_id", 1)],
        _ => &[],
    }
}

// Fixed fresh-session restore transaction text bindings. Numeric/null SDK
// parameters have zero byte weight; the source census checks these weights.
// Complete canonical admission.create literal query/statement text binds,
// conservatively including alternative branches; helper-expanded binds follow separately.
const ADMISSION_CREATE_BINDINGS: &[(&str, usize)] = &[
    ("account_id", 1),
    ("event_id", 1),
    ("idempotency_key", 3),
    ("idempotency_scope", 3),
    ("input_json", 7),
    ("message_id", 3),
    ("message_run_id", 1),
    ("model", 4),
    ("parent_run_id", 13),
    ("platform", 1),
    ("profile", 2),
    ("provider", 4),
    ("request_hash", 1),
    ("run_id", 30),
    ("script_hash", 1),
    ("session_id", 21),
    ("session_metadata_json", 11),
    ("system_prompt", 3),
    ("tool_graph_id", 34),
    ("tool_ref_id", 12),
    ("tool_registry_identity", 1),
    ("tool_workspace", 1),
    ("workspace_identity_json", 8),
];

const RESTORE_ENVELOPE_BINDINGS: usize = 48;
#[cfg(test)]
const RESTORE_ADMISSION_BINDINGS: &[(&str, usize)] = &[
    ("session_id", 14),
    ("profile", 2),
    ("platform", 1),
    ("account_id", 1),
    ("system_prompt", 1),
    ("model", 2),
    ("provider", 2),
    ("session_metadata_json", 5),
    ("parent_run_id", 7),
    ("run_id", 15),
    ("message_id", 2),
    ("message_run_id", 1),
    ("input_json", 7),
    ("script_hash", 1),
    ("idempotency_scope", 1),
    ("idempotency_key", 1),
    ("request_hash", 1),
    ("workspace_identity_json", 2),
    ("tool_graph_id", 4),
    ("tool_ref_id", 2),
    ("event_id", 1),
];

const ORDINARY_PIN_BINDINGS: &[(&str, usize)] = &[
    ("tool_graph_id", 22),
    ("run_id", 13),
    ("tool_ref_id", 11),
    ("session_id", 2),
];
const CHECKPOINT_PIN_BINDINGS: &[(&str, usize)] = &[
    ("tool_graph_id", 20),
    ("run_id", 12),
    ("tool_ref_id", 10),
    ("session_id", 2),
];
// All alternative admission writes and bounded rollback cuts are charged conservatively.
#[cfg(test)]
const ADMISSION_GRAPH_GUARD_BINDINGS: &[(&str, usize)] =
    &[("tool_graph_id", 30), ("run_id", 10), ("tool_ref_id", 10)];
const MANAGED_ADMISSION_GRAPH_GUARD_BINDINGS: &[(&str, usize)] =
    &[("tool_graph_id", 6), ("run_id", 2), ("tool_ref_id", 2)];
const RESTORE_GRAPH_GUARD_BINDINGS: &[(&str, usize)] =
    &[("tool_graph_id", 39), ("run_id", 13), ("tool_ref_id", 13)];
const EVENT_PAIR_BINDINGS: &[(&str, usize)] = &[
    ("run_id", 20),
    ("event_id_a", 2),
    ("event_type_a", 1),
    ("payload_json_a", 1),
    ("event_id_b", 2),
    ("event_type_b", 1),
    ("payload_json_b", 1),
    ("failpoint", 1),
];

fn fixed_parameter_bytes(payload: &Value, bindings: &[(&str, usize)]) -> Result<usize, String> {
    bindings.iter().try_fold(0usize, |sum, (name, count)| {
        payload[name]
            .as_str()
            .unwrap_or_default()
            .len()
            .checked_mul(*count)
            .and_then(|bytes| sum.checked_add(bytes))
            .ok_or_else(|| "managed_metadata_budget_exceeded".into())
    })
}

// These are SQLite's actual output names (qualified simple columns lose the
// table qualifier). Keep the positional nine-cell projections in parity tests.
const HARNESS_PIN_READ_COLUMNS: &[&str] = &[
    "COALESCE(json_extract(idem.response_json, '$.tool_graph_id'), '')",
    "COALESCE(json_extract(idem.response_json, '$.tool_ref_id'), '')",
    "COALESCE(CAST(json_extract(idem.response_json, '$.tool_generation') AS INTEGER), 0)",
    "resource_id",
    "COALESCE((SELECT session_id FROM runs WHERE id = idem.resource_id), '')",
    "COALESCE(json_extract(idem.response_json, '$.registry_identity'), '')",
    "COALESCE(json_extract(idem.response_json, '$.workspace'), '')",
    "COALESCE(json_extract(idem.response_json, '$.profile'), '')",
    "COALESCE(json_extract(idem.response_json, '$.harness_selection'), 'null')",
];
fn harness_receipt_read_bytes(payload: &Value, outer: &Value) -> Result<(usize, usize), String> {
    let rejected = || "managed_metadata_budget_exceeded".to_string();
    let mut receipt = json!({"run_id":payload["run_id"],"status":"running","tool_graph_id":payload["tool_graph_id"],"tool_ref_id":payload["tool_ref_id"],"tool_generation":payload["tool_graph_generation"],"registry_identity":payload["tool_registry_identity"].as_str().unwrap_or_default(),"workspace":payload["tool_workspace"].as_str().unwrap_or_default(),"profile":payload["profile"],"harness_selection":outer["run_graph_selection"]["harness_selection"]});
    if let Some(identity) = payload["workspace_identity_json"]
        .as_str()
        .filter(|s| !s.is_empty())
    {
        receipt["workspace_identity"] = serde_json::from_str(identity).map_err(|_| rejected())?;
    }
    let encoded = serde_json::to_vec(&receipt).map_err(|_| rejected())?;
    let keyed = !payload["idempotency_key"]
        .as_str()
        .unwrap_or_default()
        .is_empty();
    let scope = if keyed {
        payload["idempotency_scope"].as_str().unwrap_or_default()
    } else {
        "native.tool-pin"
    };
    let key = if keyed {
        &payload["idempotency_key"]
    } else {
        &payload["run_id"]
    };
    let mut receipt_bytes = crate::config::ADMISSION_IDEMPOTENCY_QUERY_COLUMNS
        .iter()
        .map(|c| c.name.len())
        .sum::<usize>();
    for n in [
        scope.len(),
        key.as_str().unwrap_or_default().len(),
        payload["request_hash"].as_str().unwrap_or_default().len(),
        3,
        payload["run_id"].as_str().unwrap_or_default().len(),
        9,
        encoded.len(),
        24,
    ] {
        receipt_bytes = receipt_bytes.checked_add(n).ok_or_else(rejected)?;
    }
    let mut pin_bytes = HARNESS_PIN_READ_COLUMNS
        .iter()
        .map(|s| s.len())
        .sum::<usize>();
    for n in [
        payload["tool_graph_id"].as_str().unwrap_or_default().len(),
        payload["tool_ref_id"].as_str().unwrap_or_default().len(),
        8,
        payload["run_id"].as_str().unwrap_or_default().len(),
        payload["session_id"].as_str().unwrap_or_default().len(),
        payload["tool_registry_identity"]
            .as_str()
            .unwrap_or_default()
            .len(),
        payload["tool_workspace"].as_str().unwrap_or_default().len(),
        payload["profile"].as_str().unwrap_or_default().len(),
        serde_json::to_vec(&outer["run_graph_selection"]["harness_selection"])
            .map_err(|_| rejected())?
            .len(),
    ] {
        pin_bytes = pin_bytes.checked_add(n).ok_or_else(rejected)?;
    }
    Ok((receipt_bytes, pin_bytes))
}
fn validate_harness_receipt_reads(payload: &Value) -> Result<(), String> {
    let outer: Value = serde_json::from_str(payload["input_json"].as_str().unwrap_or("{}"))
        .map_err(|_| "managed_metadata_budget_exceeded".to_string())?;
    if outer["run_graph_selection"]["harness_selection"]["mode"] != "context_prompt" {
        return Ok(());
    }
    let (receipt, pin) = harness_receipt_read_bytes(payload, &outer)?;
    if receipt > crate::config::ADMISSION_IDEMPOTENCY_QUERY_LIMIT_BYTES
        || pin > crate::config::ADMISSION_IDEMPOTENCY_QUERY_LIMIT_BYTES
    {
        return Err("managed_metadata_budget_exceeded".into());
    }
    Ok(())
}

fn harness_admission_parameter_bytes(payload: &Value, restore: bool) -> Result<usize, String> {
    let rejected = || "managed_metadata_budget_exceeded".to_string();
    let wire = serde_json::to_vec(payload).map_err(|_| rejected())?.len();
    let mut total = wire.checked_mul(5).ok_or_else(rejected)?;
    let mut add = |n: usize, w: usize| -> Result<(), String> {
        total = total
            .checked_add(n.checked_mul(w).ok_or_else(rejected)?)
            .ok_or_else(rejected)?;
        Ok(())
    };
    add(
        fixed_parameter_bytes(payload, ADMISSION_CREATE_BINDINGS)?,
        1,
    )?;
    add(
        fixed_parameter_bytes(
            payload,
            if restore {
                CHECKPOINT_PIN_BINDINGS
            } else {
                ORDINARY_PIN_BINDINGS
            },
        )?,
        1,
    )?;
    add(payload["input_json"].as_str().unwrap_or_default().len(), 4)?;
    let keyed = !payload["idempotency_key"]
        .as_str()
        .unwrap_or_default()
        .is_empty();
    let scope = if keyed {
        payload["idempotency_scope"].as_str().unwrap_or_default()
    } else {
        "native.tool-pin"
    };
    let key = if keyed {
        payload["idempotency_key"].as_str().unwrap_or_default()
    } else {
        payload["run_id"].as_str().unwrap_or_default()
    };
    add(scope.len(), 2)?;
    add(key.len(), 3)?;
    let outer: Value = serde_json::from_str(payload["input_json"].as_str().unwrap_or("{}"))
        .map_err(|_| rejected())?;
    let raw = serde_json::to_string(&outer["run_context"]["input"]).map_err(|_| rejected())?;
    add(raw.len(), 2)?;
    add(
        serde_json::to_vec(&json!([{"type":"text","text":raw}]))
            .map_err(|_| rejected())?
            .len(),
        1,
    )?;
    if let Some(binding) = payload["managed_binding_json"]
        .as_str()
        .filter(|s| !s.is_empty())
    {
        add(
            fixed_parameter_bytes(payload, MANAGED_ADMISSION_GRAPH_GUARD_BINDINGS)?,
            1,
        )?;
        let binding: Value = serde_json::from_str(binding).map_err(|_| rejected())?;
        for (field, n) in [
            ("workspace_id", 3),
            ("branch_id", 2),
            ("record_json", 5),
            ("run_id", 1),
            ("profile", 1),
        ] {
            add(binding[field].as_str().unwrap_or_default().len(), n)?;
        }
    }
    if restore {
        let envelope = payload["restore_json"].as_str().ok_or_else(rejected)?;
        add(envelope.len(), RESTORE_ENVELOPE_BINDINGS)?;
        add(
            fixed_parameter_bytes(payload, RESTORE_GRAPH_GUARD_BINDINGS)?,
            1,
        )?;
        let envelope: Value = serde_json::from_str(envelope).map_err(|_| rejected())?;
        add(
            serde_json::to_vec(&envelope["result"]["graph"]["harness_selection"])
                .map_err(|_| rejected())?
                .len(),
            1,
        )?;
        for v in [
            &envelope["request"]["checkpoint_id"],
            &envelope["result"]["graph"]["checkpoint_graph_ref_id"],
        ] {
            add(v.as_str().unwrap_or_default().len(), 1)?;
        }
    }
    Ok(total)
}
fn validate_harness_admission_budget(payload: &Value) -> Result<(), String> {
    validate_harness_receipt_reads(payload)?;
    if harness_admission_parameter_bytes(payload, false)? > crate::effects::journal::METADATA_BYTES
        || serde_json::to_vec(payload)
            .map_err(|_| "managed_metadata_budget_exceeded")?
            .len()
            > crate::effects::journal::METADATA_BYTES
    {
        return Err("managed_metadata_budget_exceeded".into());
    }
    Ok(())
}

fn validate_graph_parameter_budget(op: &str, payload: &Value) -> Result<(), String> {
    let mut total = 0usize;
    let mut add = |bindings| -> Result<(), String> {
        total = total
            .checked_add(fixed_parameter_bytes(payload, bindings)?)
            .ok_or("managed_metadata_budget_exceeded")?;
        Ok(())
    };
    if op == "event.append_pair" {
        add(EVENT_PAIR_BINDINGS)?;
        // The run-existence prequery is outside the fixed statement array.
        add(&[("run_id", 1)])?;
    } else if op == "admission.create"
        && !payload["tool_graph_id"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
        && payload["restore_json"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    {
        return validate_harness_admission_budget(payload);
    }
    if total > crate::effects::journal::METADATA_BYTES {
        return Err("managed_metadata_budget_exceeded".into());
    }
    Ok(())
}

pub(crate) fn validate_composed_restore_budget(payload: &Value) -> Result<(), String> {
    if payload["restore_json"]
        .as_str()
        .unwrap_or_default()
        .is_empty()
    {
        return Ok(());
    }
    validate_harness_receipt_reads(payload)?;
    if harness_admission_parameter_bytes(payload, true)? > crate::effects::journal::METADATA_BYTES
        || serde_json::to_vec(payload)
            .map_err(|_| "managed_metadata_budget_exceeded")?
            .len()
            > crate::effects::journal::METADATA_BYTES
    {
        return Err("managed_metadata_budget_exceeded".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "managed_storage_budget_tests.rs"]
mod managed_storage_budget_tests;

impl GatewayPersistence {
    pub(crate) fn compaction_context_snapshot(
        &self,
        session_id: &str,
    ) -> Result<CompactionContextSnapshot, StorageError> {
        let snapshot = CompactionContextSnapshot::decode(
            self.command_data("compaction.context", &json!({"session_id": session_id}))?,
        )?;
        #[cfg(test)]
        {
            let hook = self.context_snapshot_read_hook.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
        }
        Ok(snapshot)
    }

    #[cfg(test)]
    pub(crate) fn after_context_snapshot_read(&self, hook: impl FnOnce() + Send + 'static) {
        *self.context_snapshot_read_hook.lock().unwrap() = Some(Box::new(hook));
    }

    /// Opens the normalized typed storage repository: compiles `main.rss`
    /// and spawns the dedicated worker thread. Typed repository commands
    /// (admission, sessions, messages, runs, events, jobs, approvals,
    /// compactions) block on the worker's bounded response and are meant to
    /// be called from blocking threads (`spawn_blocking`), never directly
    /// from Tokio request threads.
    pub fn open(config: &crate::config::AgentGatewayConfig, path: &Path) -> Result<Self, String> {
        Self::open_with_metrics(config, path, Arc::new(crate::metrics::Metrics::default()))
    }

    /// Like [`Self::open`], but shares the caller's bounded metrics registry
    /// so every storage command is observable.
    pub fn open_with_metrics(
        config: &crate::config::AgentGatewayConfig,
        path: &Path,
        metrics: Arc<crate::metrics::Metrics>,
    ) -> Result<Self, String> {
        let runner = StorageRunner::open(config, path)?;
        #[cfg(any(test, feature = "workspace-io-fault"))]
        let executed_commands = Arc::clone(&runner.executed_commands);
        let (sender, requests) = mpsc::channel::<StorageRequest>();
        let (shutdown_sender, shutdown) = mpsc::channel::<()>();
        let drop_next_managed_commit_ack = Arc::new(AtomicBool::new(false));
        let worker_ack_fault = Arc::clone(&drop_next_managed_commit_ack);
        let drop_next_managed_intent_without_apply = Arc::new(AtomicBool::new(false));
        let worker_intent_apply_fault = Arc::clone(&drop_next_managed_intent_without_apply);
        let plugin_state_candidates = Arc::new(crate::plugins::PluginStateCandidates::default());
        let worker_state_candidates = Arc::clone(&plugin_state_candidates);
        #[cfg(feature = "workspace-io-fault")]
        let worker_execute_gate: StorageExecuteGate = Arc::new(Mutex::new(None));
        #[cfg(feature = "workspace-io-fault")]
        let worker_execute_gate_for_thread = Arc::clone(&worker_execute_gate);
        #[cfg(feature = "workspace-io-fault")]
        let worker_collect_snapshot_gate: StorageSnapshotGate = Arc::new(Mutex::new(None));
        #[cfg(feature = "workspace-io-fault")]
        let worker_collect_snapshot_gate_for_thread = Arc::clone(&worker_collect_snapshot_gate);
        #[cfg(all(test, feature = "workspace-io-fault"))]
        let worker_state_owner_settle_gate: Arc<Mutex<Option<Arc<PersistBlockState>>>> =
            Arc::new(Mutex::new(None));
        #[cfg(all(test, feature = "workspace-io-fault"))]
        let worker_state_owner_settle_gate_for_thread = Arc::clone(&worker_state_owner_settle_gate);
        let thread = std::thread::Builder::new()
            .name("gateway-storage-worker".to_string())
            .spawn(move || {
                storage_worker_loop(
                    runner,
                    requests,
                    shutdown,
                    (worker_ack_fault, worker_intent_apply_fault),
                    worker_state_candidates,
                    #[cfg(feature = "workspace-io-fault")]
                    (
                        worker_execute_gate_for_thread,
                        worker_collect_snapshot_gate_for_thread,
                    ),
                    #[cfg(all(test, feature = "workspace-io-fault"))]
                    worker_state_owner_settle_gate_for_thread,
                )
            })
            .map_err(|error| format!("spawn gateway storage worker: {error}"))?;
        Ok(Self {
            #[cfg(feature = "workspace-io-fault")]
            drop_next_managed_commit_ack,
            #[cfg(feature = "workspace-io-fault")]
            drop_next_managed_intent_without_apply,
            #[cfg(all(test, feature = "workspace-io-fault"))]
            maintenance_fault_statement: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            maintenance_reply_block: Mutex::new(None),
            #[cfg(all(test, feature = "workspace-io-fault"))]
            state_owner_settle_gate: worker_state_owner_settle_gate,
            managed_pending: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            plugin_state_writers: Arc::new(crate::plugins::PluginStateWriters::default()),
            managed_revoke_listeners: Arc::new(crate::effects::ManagedRevokeListeners::default()),
            plugin_state_candidates,
            #[cfg(test)]
            managed_request_hook: Mutex::new(None),
            worker: StorageWorker {
                sender,
                shutdown: shutdown_sender,
                thread: std::sync::Mutex::new(Some(thread)),
                closed: std::sync::atomic::AtomicBool::new(false),
                #[cfg(any(test, feature = "workspace-io-fault"))]
                executed_commands,
            },
            max_events: config.max_events_per_run as i64,
            broadcast_capacity: config.broadcast_capacity,
            metrics,
            fail_next: std::sync::atomic::AtomicBool::new(false),
            fail_after_partial_write: std::sync::atomic::AtomicBool::new(false),
            fail_after_commit_before_publish: std::sync::atomic::AtomicBool::new(false),
            fail_model_requested_append: std::sync::atomic::AtomicBool::new(false),
            fail_plugin_control_partial: std::sync::atomic::AtomicBool::new(false),
            persist_block: Mutex::new(None),
            plugin_control_precommit_gate: Mutex::new(None),
            plugin_retain_precommit_pause: Mutex::new(None),
            plugin_activate_receipt_hook: Mutex::new(None),
            admission_precommit_hook: Mutex::new(None),
            #[cfg(test)]
            admission_postcommit_hook: Mutex::new(None),
            #[cfg(test)]
            admission_payload_transform: Mutex::new(None),
            #[cfg(test)]
            admission_result_observer: Mutex::new(None),
            #[cfg(any(test, feature = "workspace-io-fault"))]
            admission_ack_loss: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            admission_secondary_decode_loss: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            admission_precommit_fail: std::sync::atomic::AtomicBool::new(false),
            #[cfg(any(test, feature = "workspace-io-fault"))]
            admission_state_fail: std::sync::atomic::AtomicBool::new(false),
            #[cfg(any(test, feature = "workspace-io-fault"))]
            plugin_state_collect_observer: Mutex::new(None),
            #[cfg(any(test, feature = "workspace-io-fault"))]
            plugin_state_collect_failpoint: std::sync::atomic::AtomicBool::new(false),
            #[cfg(any(test, feature = "workspace-io-fault"))]
            plugin_state_put_ack_loss: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "workspace-io-fault")]
            plugin_state_object_put_observer: Mutex::new(None),
            #[cfg(feature = "workspace-io-fault")]
            plugin_state_collect_result_observer: Mutex::new(None),
            #[cfg(any(test, feature = "workspace-io-fault"))]
            plugin_state_collect_enqueue_observer: Mutex::new(None),
            #[cfg(feature = "workspace-io-fault")]
            worker_execute_gate,
            #[cfg(feature = "workspace-io-fault")]
            worker_collect_snapshot_gate,
            #[cfg(feature = "workspace-io-fault")]
            control_reply_timeout_override: Mutex::new(None),
            #[cfg(test)]
            admission_replay_fail_remaining: Mutex::new(0),
            #[cfg(feature = "config-fixture")]
            approval_expire_hook: Mutex::new(None),
            #[cfg(test)]
            context_snapshot_read_hook: Mutex::new(None),
        })
    }

    /// Closes the storage worker deterministically: signals it to exit,
    /// joins the thread, and marks it closed so every later command fails
    /// fast with a typed error instead of hanging. Idempotent; concurrent
    /// calls and `Drop` are safe. Queued-but-unstarted requests observe a
    /// disconnected response channel (typed `storage_unavailable`).
    pub fn shutdown(&self) {
        self.worker.shutdown();
    }

    /// Whether the storage worker thread can still execute queued requests.
    /// A caller that timed out waiting for a collect reply must not mark
    /// collection debt while the worker is alive: its request may still be
    /// queued (parked or backlogged) and the worker records the real outcome
    /// itself in execution order. Only a gone worker — whose queued requests
    /// can never execute — lets a caller mark debt for an unknown outcome.
    pub(crate) fn is_storage_worker_running(&self) -> bool {
        if self
            .worker
            .closed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return false;
        }
        !self
            .worker
            .thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .is_some_and(|thread| thread.is_finished())
    }

    /// Number of real RSS storage commands executed by the dedicated worker.
    /// It increments before the RSS program runs; a command rejected by a
    /// caller-side budget never reaches this counter.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub fn executed_storage_commands(&self) -> usize {
        self.worker.executed_commands.load(Ordering::Relaxed)
    }

    #[cfg(all(test, feature = "workspace-io-fault"))]
    pub(crate) fn inject_maintenance_transaction_fault(&self, statement: usize) {
        self.maintenance_fault_statement
            .store(statement, Ordering::Release);
    }
    /// Fixture-only: drop the reply of the next successful managed
    /// commit/prepare/delegate-intent transaction while leaving the durable
    /// transaction intact. The caller observes transport ambiguity.
    #[cfg(feature = "workspace-io-fault")]
    pub fn inject_drop_managed_commit_ack(&self) {
        self.drop_next_managed_commit_ack
            .store(true, Ordering::Release);
    }
    #[cfg(feature = "workspace-io-fault")]
    pub fn managed_commit_ack_drop_armed(&self) -> bool {
        self.drop_next_managed_commit_ack.load(Ordering::Acquire)
    }
    /// Fixture-only: drop the next delegation-intent request before it is
    /// executed. Nothing is written and the caller observes transport
    /// ambiguity with an unequal read-back.
    #[cfg(feature = "workspace-io-fault")]
    pub fn inject_drop_managed_intent_without_apply(&self) {
        self.drop_next_managed_intent_without_apply
            .store(true, Ordering::Release);
    }

    /// Runs one command on the dedicated storage worker and blocks (bounded)
    /// for the response. The worker thread executes the RSS program; caller
    /// threads never run storage code themselves.
    fn command(&self, op: &str, payload: &Value) -> Result<Value, String> {
        // Independent trusted metadata/startup/maintenance operations own a
        // finite context. Live effect callers use the explicit parent path.
        let context = op.starts_with("effect.").then(managed_metadata_context);
        self.command_with_cancellation(op, payload, context.as_ref())
    }
    fn command_with_cancellation(
        &self,
        op: &str,
        payload: &Value,
        parent: Option<&crate::RunCancellation>,
    ) -> Result<Value, String> {
        self.command_with_claim(
            op,
            payload,
            parent,
            None,
            StorageRequestOptions {
                report_health: true,
                ..StorageRequestOptions::default()
            },
        )
    }
    fn command_with_cancellation_and_owner(
        &self,
        op: &str,
        payload: &Value,
        parent: Option<&crate::RunCancellation>,
        state_owner: Option<crate::plugins::PluginStateCandidateLease>,
    ) -> Result<Value, String> {
        self.command_with_claim(
            op,
            payload,
            parent,
            None,
            StorageRequestOptions {
                state_owner,
                report_health: true,
                ..StorageRequestOptions::default()
            },
        )
    }
    fn command_with_owner(
        &self,
        op: &str,
        payload: &Value,
        state_owner: Option<crate::plugins::PluginStateCandidateLease>,
    ) -> Result<Value, String> {
        // Same finite context as `command`: independent trusted
        // metadata/startup/maintenance operations own one; live effect callers
        // use the explicit parent path.
        let context = op.starts_with("effect.").then(managed_metadata_context);
        self.command_with_claim(
            op,
            payload,
            context.as_ref(),
            None,
            StorageRequestOptions {
                state_owner,
                report_health: true,
                ..StorageRequestOptions::default()
            },
        )
    }
    fn command_with_claim(
        &self,
        op: &str,
        payload: &Value,
        parent: Option<&crate::RunCancellation>,
        claim: Option<&Arc<ManagedMaintenanceClaim>>,
        options: StorageRequestOptions,
    ) -> Result<Value, String> {
        let StorageRequestOptions {
            read_timeout,
            state_owner,
            report_health,
        } = options;
        validate_graph_parameter_budget(op, payload)?;
        if op == "admission.create" {
            validate_composed_restore_budget(payload)?;
        }
        let cancellation = if op.starts_with("effect.")
            || claim.is_some()
            || (op == "plugin.graph_revocation_get" && parent.is_some())
        {
            // The exact execution-guard read carries the original run
            // cancellation: it honors the same finite-deadline requirement and
            // remaining-deadline/command-timeout bound as effect calls, without
            // minting a new run clock. Ordinary history reads pass no parent
            // and keep the previous parent-less path.
            let parent = parent.ok_or("managed storage context missing")?;
            if parent.deadline_instant().is_none() {
                return Err("managed storage finite original deadline required".into());
            }
            Some(parent.child())
        } else {
            None
        };
        #[cfg(test)]
        if let Some(cancel) = &cancellation {
            let hook = self
                .managed_request_hook
                .lock()
                .expect("managed request hook")
                .clone();
            if let Some(hook) = hook {
                hook(op, cancel, false);
            }
        }
        if cancellation
            .as_ref()
            .is_some_and(|cancel| cancel.requested().is_some() || cancel.deadline_passed())
        {
            return Err("managed storage original deadline/cancellation".into());
        }
        let maintenance_read = if let Some(claim) = claim.filter(|_| {
            matches!(
                op,
                "effect.maintenance_receipt" | "effect.branch_publication_history"
            )
        }) {
            if claim.read_busy.swap(true, Ordering::AcqRel) {
                return Err("managed_submitted_unknown".into());
            }
            Some(ManagedMaintenanceReadPermit(claim.clone()))
        } else {
            None
        };
        let managed_permit = if let Some(claim) = claim {
            if !Arc::ptr_eq(&claim.permit.0, &self.managed_pending) {
                return Err("managed maintenance persistence mismatch".into());
            }
            Some(claim.permit.clone())
        } else if cancellation.is_some() {
            Some(Arc::new(ManagedStoragePermit::acquire(
                &self.managed_pending,
            )?))
        } else {
            None
        };
        if let Some(block) = self
            .persist_block
            .lock()
            .expect("persist block lock")
            .take()
        {
            block.enter_and_wait();
        }
        if self
            .fail_next
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.metrics
                .storage_op(crate::metrics::StorageOp::from_command(op), false);
            return Err("injected persist failure".to_string());
        }
        if cancellation
            .as_ref()
            .is_some_and(|cancel| cancel.requested().is_some() || cancel.deadline_passed())
        {
            return Err("managed storage original deadline/cancellation".into());
        }
        let result = if self
            .worker
            .closed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            Err("gateway storage worker is not running".to_string())
        } else {
            let (respond, response) = mpsc::channel();
            let response_timeout = if let Some(timeout) = read_timeout {
                timeout.min(STORAGE_COMMAND_TIMEOUT)
            } else {
                cancellation
                    .as_ref()
                    .and_then(crate::RunCancellation::remaining_deadline)
                    .map_or(STORAGE_COMMAND_TIMEOUT, |remaining| {
                        remaining.min(STORAGE_COMMAND_TIMEOUT)
                    })
            };
            #[cfg(feature = "workspace-io-fault")]
            let response_timeout = self
                .control_reply_timeout_override
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .map_or(response_timeout, |timeout| response_timeout.min(timeout));
            #[cfg(test)]
            if let Some(cancel) = &cancellation {
                let hook = self
                    .managed_request_hook
                    .lock()
                    .expect("managed request hook")
                    .clone();
                if let Some(hook) = hook {
                    hook(op, cancel, true);
                }
            }
            let sent = self.worker.sender.send(StorageRequest {
                op: op.to_string(),
                payload: payload.clone(),
                respond,
                cancellation,
                _managed_permit: managed_permit,
                maintenance: claim.cloned(),
                _maintenance_read: maintenance_read,
                state_owner,
                report_health,
                #[cfg(test)]
                reply_block: if claim.is_some() {
                    self.maintenance_reply_block.lock().unwrap().take()
                } else {
                    None
                },
            });
            match sent {
                Ok(()) => {
                    if let Some(claim) = claim
                        && (op == "admission.create"
                            || op == "effect.checkpoint_create"
                            || op == "effect.publish_submit")
                    {
                        claim.submitted.store(true, Ordering::Release);
                    }
                    response
                        .recv_timeout(response_timeout)
                        .map_err(|error| match error {
                            RecvTimeoutError::Timeout => {
                                "gateway storage worker timed out".to_string()
                            }
                            RecvTimeoutError::Disconnected => {
                                "gateway storage worker exited unexpectedly".to_string()
                            }
                        })?
                }
                Err(_) => Err("gateway storage worker is not running".to_string()),
            }
        };
        self.metrics
            .storage_op(crate::metrics::StorageOp::from_command(op), result.is_ok());
        result
    }

    /// Runs one typed command and returns its `data` payload, or a typed
    /// [`StorageError`] carrying the RSS error code.
    fn command_data(&self, op: &str, payload: &Value) -> Result<Value, StorageError> {
        let result = self.command(op, payload).map_err(|message| StorageError {
            code: "storage_unavailable".to_string(),
            message,
        })?;
        if result.get("ok") != Some(&Value::Bool(true)) {
            return Err(StorageError {
                code: result
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("storage_error")
                    .to_string(),
                message: result
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("storage command failed")
                    .to_string(),
            });
        }
        decode_command_data(result.get("data").cloned().unwrap_or(Value::Null))
    }

    fn command_data_with_cancellation(
        &self,
        op: &str,
        payload: &Value,
        cancellation: &crate::RunCancellation,
    ) -> Result<Value, StorageError> {
        let result = self
            .command_with_cancellation(op, payload, Some(cancellation))
            .map_err(|message| StorageError {
                code: "storage_unavailable".into(),
                message,
            })?;
        if result.get("ok") != Some(&Value::Bool(true)) {
            return Err(StorageError {
                code: result
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("storage_error")
                    .into(),
                message: result
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("storage command failed")
                    .into(),
            });
        }
        decode_command_data(result.get("data").cloned().unwrap_or(Value::Null))
    }

    fn command_data_with_owner(
        &self,
        op: &str,
        payload: &Value,
        state_owner: Option<crate::plugins::PluginStateCandidateLease>,
    ) -> Result<Value, StorageError> {
        let result = self
            .command_with_owner(op, payload, state_owner)
            .map_err(|message| StorageError {
                code: "storage_unavailable".to_string(),
                message,
            })?;
        if result.get("ok") != Some(&Value::Bool(true)) {
            return Err(StorageError {
                code: result
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("storage_error")
                    .to_string(),
                message: result
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("storage command failed")
                    .to_string(),
            });
        }
        decode_command_data(result.get("data").cloned().unwrap_or(Value::Null))
    }

    fn command_data_with_cancellation_and_owner(
        &self,
        op: &str,
        payload: &Value,
        cancellation: &crate::RunCancellation,
        state_owner: Option<crate::plugins::PluginStateCandidateLease>,
    ) -> Result<Value, StorageError> {
        let result = self
            .command_with_cancellation_and_owner(op, payload, Some(cancellation), state_owner)
            .map_err(|message| StorageError {
                code: "storage_unavailable".into(),
                message,
            })?;
        if result.get("ok") != Some(&Value::Bool(true)) {
            return Err(StorageError {
                code: result
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("storage_error")
                    .into(),
                message: result
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("storage command failed")
                    .into(),
            });
        }
        decode_command_data(result.get("data").cloned().unwrap_or(Value::Null))
    }

    /// Private original-owner proof read. `Some(until)` shares one window of
    /// the original remaining deadline, capped by the existing command timeout.
    /// `None` is an already-expired confirmation: the existing command timeout
    /// still runs once and is not rejected for remaining=0. This is not a new
    /// execution clock and does not refresh the run deadline.
    pub(crate) fn command_data_for_original_proof(
        &self,
        op: &str,
        payload: &Value,
        budget_until: Option<Instant>,
    ) -> Result<Value, StorageError> {
        let read_timeout = if let Some(until) = budget_until {
            let now = Instant::now();
            if now >= until {
                return Err(StorageError {
                    code: "storage_unavailable".into(),
                    message: "original proof read budget exhausted".into(),
                });
            }
            Some(until.saturating_duration_since(now))
        } else {
            None
        };
        let result = self
            .command_with_claim(
                op,
                payload,
                None,
                None,
                StorageRequestOptions {
                    read_timeout,
                    report_health: true,
                    ..StorageRequestOptions::default()
                },
            )
            .map_err(|message| StorageError {
                code: "storage_unavailable".into(),
                message,
            })?;
        if result.get("ok") != Some(&Value::Bool(true)) {
            return Err(StorageError {
                code: result
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("storage_error")
                    .to_string(),
                message: result
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("storage command failed")
                    .to_string(),
            });
        }
        decode_command_data(result.get("data").cloned().unwrap_or(Value::Null))
    }

    /// Shared proof window from the original remaining deadline, capped by the
    /// existing command timeout. `None` means the original deadline is already
    /// gone: confirmation still uses the existing command timeout once and is
    /// not rejected. The execution deadline is not refreshed.
    pub(crate) fn original_proof_budget(original: &crate::RunCancellation) -> Option<Instant> {
        if original.requested().is_some()
            || original.deadline_passed()
            || original
                .remaining_deadline()
                .is_some_and(|remaining| remaining.is_zero())
        {
            return None;
        }
        let window = original
            .remaining_deadline()
            .unwrap_or(STORAGE_COMMAND_TIMEOUT)
            .min(STORAGE_COMMAND_TIMEOUT);
        Instant::now().checked_add(window)
    }

    pub(crate) fn managed_effect_command_with_cancellation(
        &self,
        op: &str,
        payload: &Value,
        cancellation: &crate::RunCancellation,
    ) -> Result<Value, StorageError> {
        self.managed_effect_command_inner(op, payload, Some(cancellation))
    }
    pub(crate) fn managed_effect_command_with_cancellation_and_owner(
        &self,
        op: &str,
        payload: &Value,
        cancellation: &crate::RunCancellation,
        state_owner: Option<crate::plugins::PluginStateCandidateLease>,
    ) -> Result<Value, StorageError> {
        self.managed_effect_command_inner_with_owner(op, payload, Some(cancellation), state_owner)
    }
    pub(crate) fn managed_effect_command(
        &self,
        op: &str,
        payload: &Value,
    ) -> Result<Value, StorageError> {
        self.managed_effect_command_inner(op, payload, None)
    }

    fn managed_effect_command_inner(
        &self,
        op: &str,
        payload: &Value,
        cancellation: Option<&crate::RunCancellation>,
    ) -> Result<Value, StorageError> {
        self.managed_effect_command_claim(op, payload, cancellation, None, None)
    }
    fn managed_effect_command_inner_with_owner(
        &self,
        op: &str,
        payload: &Value,
        cancellation: Option<&crate::RunCancellation>,
        state_owner: Option<crate::plugins::PluginStateCandidateLease>,
    ) -> Result<Value, StorageError> {
        self.managed_effect_command_claim(op, payload, cancellation, None, state_owner)
    }
    fn managed_effect_command_claim(
        &self,
        op: &str,
        payload: &Value,
        cancellation: Option<&crate::RunCancellation>,
        claim: Option<&Arc<ManagedMaintenanceClaim>>,
        state_owner: Option<crate::plugins::PluginStateCandidateLease>,
    ) -> Result<Value, StorageError> {
        use crate::effects::journal::{METADATA_BYTES, storage_error};
        const OPS: &[&str] = &[
            "effect.run_binding",
            "effect.run_list",
            "effect.run_list_has_more",
            "effect.run_cursor",
            "effect.workspace_get",
            "effect.workspace_register",
            "effect.head",
            "effect.get",
            "effect.begin",
            "effect.checkpoint_context",
            "effect.checkpoint_create",
            "effect.branch_create",
            "effect.branch_receipt",
            "effect.branch_origin",
            "effect.publish_eligibility",
            "effect.publish_submit",
            "effect.publish_receipt",
            "effect.publication_get",
            "effect.checkpoint_get",
            "effect.maintenance_receipt",
            "effect.branch_publication_history",
            "effect.prepare",
            "effect.delegate_intent",
            "effect.commit",
            "effect.pending",
            "effect.recover_one",
            "effect.recovery_context",
        ];
        if !OPS.contains(&op) {
            return Err(storage_error("unsupported managed operation"));
        }
        let mut wire = json!({"record_json":"", "prepared_json":"", "workspace_json":"", "projections_json":"",
            "effect_id":"", "receipt_id":"", "commit_id":"", "run_id":"", "call_id":"", "store_id":"",
            "profile":"", "source_device":"", "source_inode":"", "workspace_id":"", "branch_id":"",
            "now_ms":timestamp(), "max_events":self.max_events, "cut":"", "sealed_class":"", "maintenance_json":"", "session_id":"", "after_effect_id":"", "limit":128});
        let fields = payload
            .as_object()
            .ok_or_else(|| storage_error("managed command must be a record"))?;
        for (key, value) in fields {
            if key == "owner" {
                wire["run_id"] = value["run_id"].clone();
                wire["profile"] = value["profile"].clone();
            } else if wire.get(key).is_some() {
                wire[key] = value.clone();
            } else {
                return Err(storage_error("unknown managed command field"));
            }
        }
        if op == "effect.begin"
            && !matches!(
                wire["sealed_class"].as_str(),
                Some(
                    "workspace_read" | "workspace_write" | "foreground_process" | "process_control"
                )
            )
        {
            return Err(storage_error("managed sealed class invalid"));
        }
        if serde_json::to_vec(&wire)
            .map_err(|e| storage_error(e.to_string()))?
            .len()
            > METADATA_BYTES
        {
            return Err(storage_error(
                "managed command exceeds 1 MiB transport bound",
            ));
        }
        let parameter_bytes =
            managed_parameter_bindings(op)
                .iter()
                .try_fold(0usize, |total, (field, count)| {
                    let value = wire
                        .get(*field)
                        .and_then(Value::as_str)
                        .ok_or_else(|| storage_error("managed text parameter kind invalid"))?;
                    total
                        .checked_add(
                            value.len().checked_mul(*count).ok_or_else(|| {
                                storage_error("managed aggregate parameter overflow")
                            })?,
                        )
                        .ok_or_else(|| storage_error("managed aggregate parameter overflow"))
                })?;
        if parameter_bytes > METADATA_BYTES {
            return Err(storage_error(
                "managed aggregate parameter bytes exceed 1 MiB bound",
            ));
        }
        if let Some(claim) = claim {
            let result = self
                .command_with_claim(
                    op,
                    &wire,
                    cancellation,
                    Some(claim),
                    StorageRequestOptions {
                        state_owner,
                        report_health: true,
                        ..StorageRequestOptions::default()
                    },
                )
                .map_err(|message| StorageError {
                    code: "managed_submitted_unknown".into(),
                    message,
                })?;
            maintenance_data(result)
        } else if let Some(cancellation) = cancellation {
            self.command_data_with_cancellation_and_owner(op, &wire, cancellation, state_owner)
        } else {
            self.command_data_with_owner(op, &wire, state_owner)
        }
    }

    pub(crate) fn publish_command(
        &self,
        op: &str,
        payload: &Value,
        cancellation: &crate::RunCancellation,
        claim: Option<&Arc<ManagedMaintenanceClaim>>,
    ) -> Result<Value, StorageError> {
        self.managed_effect_command_claim(op, payload, Some(cancellation), claim, None)
    }

    /// Trusted SDK metadata lookup. IDs never create workspace authority.
    pub(crate) fn managed_object_census(
        &self,
    ) -> Result<Vec<crate::effects::ManagedObjectRef>, StorageError> {
        use crate::effects::journal::{decode_record, storage_error};
        let value = self.command_data("effect.object_census", &json!({}))?;
        if value.get("columns") != Some(&json!(["record_json"]))
            || value.get("truncated") != Some(&json!(false))
        {
            return Err(storage_error("managed census layout/truncation invalid"));
        }
        let rows = value
            .get("rows")
            .and_then(Value::as_array)
            .ok_or_else(|| storage_error("managed census rows missing"))?;
        if rows.len() > 128 {
            return Err(storage_error("managed census row bound exceeded"));
        }
        rows.iter()
            .map(|row| {
                decode_record::<crate::effects::ManagedObjectRef>(
                    &json!({"columns":["record_json"],"rows":[row],"truncated":false}),
                )
                .map_err(storage_error)?
                .ok_or_else(|| storage_error("managed census object missing"))
            })
            .collect()
    }
    pub fn managed_object_metadata(
        &self,
        request: &crate::effects::ManagedObjectReferencesRequest,
    ) -> Result<Option<crate::effects::ManagedObjectRef>, StorageError> {
        self.managed_object_metadata_with_cancellation(request, &managed_metadata_context())
    }
    pub(crate) fn managed_object_metadata_with_cancellation(
        &self,
        request: &crate::effects::ManagedObjectReferencesRequest,
        cancellation: &crate::RunCancellation,
    ) -> Result<Option<crate::effects::ManagedObjectRef>, StorageError> {
        use crate::effects::journal::storage_error;
        crate::effects::broker::validate_id("store", &request.store_id).map_err(storage_error)?;
        let prefix = request
            .object_id
            .split_once('-')
            .ok_or_else(|| storage_error("managed object identifier invalid"))?
            .0;
        if !["tree", "result", "intent"].contains(&prefix) {
            return Err(storage_error("managed object kind prefix invalid"));
        }
        crate::effects::broker::validate_id(prefix, &request.object_id).map_err(storage_error)?;
        let value = self.command_data_with_cancellation(
            "effect.object_metadata",
            &json!(request),
            cancellation,
        )?;
        let object: Option<crate::effects::ManagedObjectRef> =
            crate::effects::journal::decode_record(&value).map_err(storage_error)?;
        if object.as_ref().is_some_and(|object| {
            object.store_id != request.store_id || object.object_id != request.object_id
        }) {
            return Err(storage_error("managed object metadata identity mismatch"));
        }
        Ok(object)
    }
    pub fn managed_object_references(
        &self,
        request: &crate::effects::ManagedObjectReferencesRequest,
    ) -> Result<Vec<crate::effects::ManagedObjectReference>, StorageError> {
        self.managed_object_references_with_cancellation(request, &managed_metadata_context())
    }
    pub(crate) fn managed_object_references_with_cancellation(
        &self,
        request: &crate::effects::ManagedObjectReferencesRequest,
        cancellation: &crate::RunCancellation,
    ) -> Result<Vec<crate::effects::ManagedObjectReference>, StorageError> {
        use crate::effects::journal::storage_error;
        crate::effects::broker::validate_id("store", &request.store_id).map_err(storage_error)?;
        let prefix = request
            .object_id
            .split_once('-')
            .ok_or_else(|| storage_error("managed object identifier invalid"))?
            .0;
        if !["tree", "result", "intent", "view"].contains(&prefix) {
            return Err(storage_error("managed object kind prefix invalid"));
        }
        crate::effects::broker::validate_id(prefix, &request.object_id).map_err(storage_error)?;
        let value = self.command_data_with_cancellation(
            "effect.object_refs",
            &json!(request),
            cancellation,
        )?;
        const COLUMNS: [&str; 4] = ["store_id", "object_id", "reference_kind", "reference_id"];
        if value.get("columns") != Some(&json!(COLUMNS))
            || value.get("truncated") != Some(&json!(false))
        {
            return Err(storage_error("managed reference layout/truncation invalid"));
        }
        let rows = value
            .get("rows")
            .and_then(Value::as_array)
            .ok_or_else(|| storage_error("managed reference rows missing"))?;
        if rows.len() > 512 {
            return Err(storage_error("managed reference count exceeds bound"));
        }
        let mut references = Vec::with_capacity(rows.len());
        for row in rows {
            let cells = row
                .as_array()
                .ok_or_else(|| storage_error("managed reference row invalid"))?;
            if cells.len() != 4
                || serde_json::to_vec(row)
                    .map_err(|_| storage_error("managed reference serialization failed"))?
                    .len()
                    > 4096
            {
                return Err(storage_error("managed reference cell/byte bound invalid"));
            }
            let record: serde_json::Map<String, Value> = COLUMNS
                .iter()
                .zip(cells)
                .map(|(key, value)| (key.to_string(), value.clone()))
                .collect();
            let reference: crate::effects::ManagedObjectReference =
                serde_json::from_value(Value::Object(record))
                    .map_err(|_| storage_error("managed reference cell types invalid"))?;
            if reference.store_id != request.store_id || reference.object_id != request.object_id {
                return Err(storage_error("managed reference identity mismatch"));
            }
            references.push(reference);
        }
        Ok(references)
    }

    pub fn managed_effect_by_id(
        &self,
        effect_id: &str,
    ) -> Result<Option<crate::effects::ManagedEffectRecord>, StorageError> {
        self.managed_effect_by_id_with_cancellation(effect_id, &managed_metadata_context())
    }
    pub(crate) fn managed_effect_by_id_with_cancellation(
        &self,
        effect_id: &str,
        cancellation: &crate::RunCancellation,
    ) -> Result<Option<crate::effects::ManagedEffectRecord>, StorageError> {
        crate::effects::broker::validate_id("effect", effect_id)
            .map_err(crate::effects::journal::storage_error)?;
        let value = self.command_data_with_cancellation(
            "effect.by_id",
            &json!({"effect_id":effect_id}),
            cancellation,
        )?;
        crate::effects::journal::decode_record(&value)
            .map_err(crate::effects::journal::storage_error)
    }
    pub(crate) fn managed_run_query_binding(
        &self,
        run_id: &str,
        cancellation: &crate::RunCancellation,
    ) -> Result<Option<crate::effects::journal::ManagedRunQueryBinding>, StorageError> {
        let value = self.managed_effect_command_with_cancellation(
            "effect.run_binding",
            &json!({"run_id":run_id}),
            cancellation,
        )?;
        crate::effects::journal::decode_record(&value)
            .map_err(crate::effects::journal::storage_error)
    }

    pub(crate) fn managed_run_effect_list(
        &self,
        binding: &crate::effects::journal::ManagedRunQueryBinding,
        request: &crate::effects::ManagedRunEffectListRequest,
        cancellation: &crate::RunCancellation,
    ) -> Result<crate::effects::ManagedEffectPage, crate::effects::ManagedRunEffectError> {
        use crate::effects::ManagedRunEffectError as E;
        let wire = json!({"run_id":binding.owner.run_id,"profile":binding.owner.profile,"session_id":binding.owner.session_id,
            "workspace_id":binding.workspace.workspace_id,"branch_id":binding.workspace.branch_id,
            "after_effect_id":request.after_effect_id.as_deref().unwrap_or(""),"limit":request.limit});
        if let Some(cursor) = &request.after_effect_id {
            let value = self
                .managed_effect_command_with_cancellation("effect.run_cursor", &wire, cancellation)
                .map_err(|_| E::StorageUnavailable)?;
            let rows = crate::effects::journal::decode_effect_summaries(&value, 1)
                .map_err(|_| E::StorageUnavailable)?;
            if rows.len() != 1
                || rows[0].effect_id != *cursor
                || rows[0].run_id != binding.owner.run_id
                || rows[0].workspace_id != binding.workspace.workspace_id
                || rows[0].branch_id != binding.workspace.branch_id
                || rows[0].epoch != binding.epoch
            {
                return Err(E::Unavailable);
            }
        }
        let value = self
            .managed_effect_command_with_cancellation("effect.run_list", &wire, cancellation)
            .map_err(|_| E::StorageUnavailable)?;
        let entries = crate::effects::journal::decode_effect_summaries(&value, request.limit)
            .map_err(|_| E::StorageUnavailable)?;
        let mut previous = request.after_effect_id.as_deref().unwrap_or("");
        for entry in &entries {
            if entry.run_id != binding.owner.run_id
                || entry.workspace_id != binding.workspace.workspace_id
                || entry.branch_id != binding.workspace.branch_id
                || entry.epoch != binding.epoch
                || entry.effect_id.as_str() <= previous
            {
                return Err(E::StorageUnavailable);
            }
            previous = &entry.effect_id;
        }
        let has_more = if let Some(last) = entries.last() {
            let mut after = wire;
            after["after_effect_id"] = json!(last.effect_id);
            after["limit"] = json!(1);
            let value = self
                .managed_effect_command_with_cancellation(
                    "effect.run_list_has_more",
                    &after,
                    cancellation,
                )
                .map_err(|_| E::StorageUnavailable)?;
            let remaining = crate::effects::journal::decode_effect_summaries(&value, 1)
                .map_err(|_| E::StorageUnavailable)?;
            if remaining.iter().any(|entry| {
                entry.run_id != binding.owner.run_id
                    || entry.workspace_id != binding.workspace.workspace_id
                    || entry.branch_id != binding.workspace.branch_id
                    || entry.epoch != binding.epoch
                    || entry.effect_id <= last.effect_id
            }) {
                return Err(E::StorageUnavailable);
            }
            !remaining.is_empty()
        } else {
            false
        };
        let next_cursor = if has_more {
            entries.last().map(|entry| entry.effect_id.clone())
        } else {
            None
        };
        Ok(crate::effects::ManagedEffectPage {
            entries,
            next_cursor,
            has_more,
        })
    }

    pub fn managed_effect_list(
        &self,
        request: &crate::effects::ManagedEffectListRequest,
    ) -> Result<crate::effects::ManagedEffectPage, StorageError> {
        self.managed_effect_list_with_cancellation(request, &managed_metadata_context())
    }
    pub(crate) fn managed_effect_list_with_cancellation(
        &self,
        request: &crate::effects::ManagedEffectListRequest,
        cancellation: &crate::RunCancellation,
    ) -> Result<crate::effects::ManagedEffectPage, StorageError> {
        use crate::effects::journal::{decode_effect_summaries, storage_error};
        crate::effects::broker::validate_id("ws", &request.workspace_id).map_err(storage_error)?;
        if request.limit == 0 || request.limit > 128 {
            return Err(storage_error("managed page limit must be 1..=128"));
        }
        if let Some(cursor) = &request.after_effect_id {
            crate::effects::broker::validate_id("effect", cursor).map_err(storage_error)?;
        }
        let wire = json!({"workspace_id":request.workspace_id,"after_effect_id":request.after_effect_id.as_deref().unwrap_or(""),"limit":request.limit});
        let entries = decode_effect_summaries(
            &self.command_data_with_cancellation("effect.list", &wire, cancellation)?,
            request.limit,
        )
        .map_err(storage_error)?;
        let has_more = if let Some(last) = entries.last() {
            let value=self.command_data_with_cancellation("effect.list_has_more",&json!({"workspace_id":request.workspace_id,"after_effect_id":last.effect_id,"limit":1}), cancellation)?;
            if value.get("columns") != Some(&json!(["effect_id"]))
                || value.get("truncated") != Some(&json!(false))
            {
                return Err(storage_error("managed cursor query layout invalid"));
            }
            let rows = value
                .get("rows")
                .and_then(Value::as_array)
                .ok_or_else(|| storage_error("managed cursor rows missing"))?;
            if rows.len() > 1 {
                return Err(storage_error("managed cursor query exceeded one row"));
            }
            if let Some(row) = rows.first() {
                let cells = row
                    .as_array()
                    .ok_or_else(|| storage_error("managed cursor cells invalid"))?;
                if cells.len() != 1 {
                    return Err(storage_error("managed cursor column count invalid"));
                }
                crate::effects::broker::validate_id(
                    "effect",
                    cells[0]
                        .as_str()
                        .ok_or_else(|| storage_error("managed cursor must be text"))?,
                )
                .map_err(storage_error)?;
            }
            !rows.is_empty()
        } else {
            false
        };
        let next_cursor = if has_more {
            entries.last().map(|entry| entry.effect_id.clone())
        } else {
            None
        };
        Ok(crate::effects::ManagedEffectPage {
            entries,
            next_cursor,
            has_more,
        })
    }

    pub fn managed_effect_get(
        &self,
        request: &crate::effects::ManagedEffectGetRequest,
    ) -> Result<Option<crate::effects::ManagedEffectRecord>, StorageError> {
        self.managed_effect_get_with_cancellation(request, &managed_metadata_context())
    }
    pub(crate) fn managed_effect_get_with_cancellation(
        &self,
        request: &crate::effects::ManagedEffectGetRequest,
        cancellation: &crate::RunCancellation,
    ) -> Result<Option<crate::effects::ManagedEffectRecord>, StorageError> {
        let value = self.managed_effect_command_with_cancellation(
            "effect.get",
            &json!(request),
            cancellation,
        )?;
        let record: Option<crate::effects::ManagedEffectRecord> =
            crate::effects::journal::decode_record(&value)
                .map_err(crate::effects::journal::storage_error)?;
        Ok(record.filter(|record| {
            record.identity.owner == request.owner && record.identity.call_id == request.call_id
        }))
    }

    pub fn managed_workspace_head(
        &self,
        workspace: &crate::effects::ManagedWorkspaceIdentity,
    ) -> Result<crate::effects::ManagedWorkspaceHead, StorageError> {
        self.managed_workspace_head_with_cancellation(workspace, &managed_metadata_context())
    }
    pub(crate) fn managed_workspace_head_with_cancellation(
        &self,
        workspace: &crate::effects::ManagedWorkspaceIdentity,
        cancellation: &crate::RunCancellation,
    ) -> Result<crate::effects::ManagedWorkspaceHead, StorageError> {
        let value = self.managed_effect_command_with_cancellation(
            "effect.head",
            &json!({"workspace_id":workspace.workspace_id,"branch_id":workspace.branch_id}),
            cancellation,
        )?;
        crate::effects::journal::decode_record(&value)
            .map_err(crate::effects::journal::storage_error)?
            .ok_or_else(|| crate::effects::journal::storage_error("managed head missing"))
    }

    pub fn managed_workspace_publication(
        &self,
        workspace_id: &str,
        profile: &str,
    ) -> Result<Option<crate::effects::ManagedWorkspacePublication>, StorageError> {
        let document = json!({"workspace_id": workspace_id, "profile": profile});
        let payload = json!({
            "maintenance_json": serde_json::to_string(&document)
                .map_err(|_| crate::effects::journal::storage_error("managed metadata invalid"))?,
        });
        let value = self.managed_effect_command("effect.publication_get", &payload)?;
        crate::effects::journal::decode_record(&value)
            .map_err(crate::effects::journal::storage_error)
    }

    pub(crate) fn plugin_control_command(
        &self,
        op: &str,
        payload: &Value,
    ) -> Result<Value, StorageError> {
        const OPS: &[&str] = &[
            "plugin.lock_put",
            "plugin.harness_binding_matches",
            "plugin.lock_get",
            "plugin.lock_list",
            "plugin.ref_list",
            "plugin.activate",
            "plugin.activation_get",
            "plugin.activation_history",
            "plugin.retain",
            "plugin.retention_get",
            "plugin.release",
            "plugin.pin_for_owner",
            "plugin.pin_requirement_get",
            "plugin.collect",
            "plugin.graph_revoke",
            "plugin.graph_revocation_get",
            "plugin.state_object_put",
            "plugin.state_root_put",
            "plugin.state_root_get",
            "plugin.state_bind_run",
            "plugin.state_binding_get",
            "plugin.state_binding_advance",
            "plugin.state_roots_for_checkpoint",
            "plugin.state_session_nonterminal",
            "plugin.state_session_max_schema",
            "plugin.state_commit",
            "plugin.state_authorize",
            "plugin.state_session_key",
            "plugin.state_session_key_for",
            "plugin.state_object_get",
            "plugin.state_collect",
        ];
        if !OPS.contains(&op) {
            return Err(StorageError {
                code: "plugin_control_unavailable".to_string(),
                message: "plugin control operation is not registered".to_string(),
            });
        }
        self.plugin_state_collect_or_control(op, payload, None)
    }

    pub(crate) fn plugin_control_command_with_owner(
        &self,
        op: &str,
        payload: &Value,
        state_owner: Option<crate::plugins::PluginStateCandidateLease>,
    ) -> Result<Value, StorageError> {
        const OPS: &[&str] = &[
            "plugin.lock_put",
            "plugin.harness_binding_matches",
            "plugin.lock_get",
            "plugin.lock_list",
            "plugin.ref_list",
            "plugin.activate",
            "plugin.activation_get",
            "plugin.activation_history",
            "plugin.retain",
            "plugin.retention_get",
            "plugin.release",
            "plugin.pin_for_owner",
            "plugin.pin_requirement_get",
            "plugin.collect",
            "plugin.graph_revoke",
            "plugin.graph_revocation_get",
            "plugin.state_object_put",
            "plugin.state_root_put",
            "plugin.state_root_get",
            "plugin.state_bind_run",
            "plugin.state_binding_get",
            "plugin.state_binding_advance",
            "plugin.state_roots_for_checkpoint",
            "plugin.state_session_nonterminal",
            "plugin.state_session_max_schema",
            "plugin.state_commit",
            "plugin.state_authorize",
            "plugin.state_session_key",
            "plugin.state_session_key_for",
            "plugin.state_object_get",
            "plugin.state_collect",
        ];
        if !OPS.contains(&op) {
            return Err(StorageError {
                code: "plugin_control_unavailable".to_string(),
                message: "plugin control operation is not registered".to_string(),
            });
        }
        self.plugin_state_collect_or_control(op, payload, state_owner)
    }

    fn plugin_state_collect_or_control(
        &self,
        op: &str,
        payload: &Value,
        state_owner: Option<crate::plugins::PluginStateCandidateLease>,
    ) -> Result<Value, StorageError> {
        if op == "plugin.state_collect" {
            return self.plugin_state_collect_command(payload, true);
        }
        let result = self.command_data_with_owner(op, payload, state_owner);
        #[cfg(any(test, feature = "workspace-io-fault"))]
        if op == "plugin.state_object_put"
            && result.is_ok()
            && self
                .plugin_state_put_ack_loss
                .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            return Err(StorageError {
                code: "storage_unavailable".to_string(),
                message: "gateway storage worker exited unexpectedly".to_string(),
            });
        }
        result
    }

    /// Typed `plugin.state_collect` with an explicit health-report flag. Only
    /// explicit collector invocations report; backpressure-path reclamation
    /// passes `false` so it never clears debt on its own.
    pub(crate) fn plugin_state_collect_command(
        &self,
        payload: &Value,
        report_health: bool,
    ) -> Result<Value, StorageError> {
        const OP: &str = "plugin.state_collect";
        let result = self
            .command_with_claim(
                OP,
                payload,
                None,
                None,
                StorageRequestOptions {
                    report_health,
                    ..StorageRequestOptions::default()
                },
            )
            .map_err(|message| StorageError {
                code: "storage_unavailable".to_string(),
                message,
            })?;
        if result.get("ok") != Some(&Value::Bool(true)) {
            return Err(StorageError {
                code: result
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("storage_error")
                    .to_string(),
                message: result
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("storage command failed")
                    .to_string(),
            });
        }
        decode_command_data(result.get("data").cloned().unwrap_or(Value::Null))
    }

    pub(crate) fn plugin_control_command_for_proof(
        &self,
        op: &str,
        payload: &Value,
        budget_until: Option<Instant>,
    ) -> Result<Value, StorageError> {
        const OPS: &[&str] = &[
            "plugin.pin_for_owner",
            "plugin.pin_requirement_get",
            "plugin.harness_binding_matches",
        ];
        if !OPS.contains(&op) {
            return Err(StorageError {
                code: "plugin_control_unavailable".to_string(),
                message: "plugin control operation is not registered".to_string(),
            });
        }
        self.command_data_for_original_proof(op, payload, budget_until)
    }

    /// Narrow execution-guard read: only the exact graph-revocation op, always
    /// under the caller's original run cancellation. Ordinary history reads
    /// keep using the parent-less command path. The same original root is
    /// re-checked at the return boundary before the read result is accepted:
    /// a requested/expired original keeps its existing classification instead
    /// of becoming a missing-authority refusal. No new timer is minted.
    pub(crate) fn plugin_control_command_for_execution(
        &self,
        op: &str,
        payload: &Value,
        cancellation: &crate::RunCancellation,
    ) -> Result<Value, StorageError> {
        if op != "plugin.graph_revocation_get" {
            return Err(StorageError {
                code: "plugin_control_unavailable".to_string(),
                message: "plugin control operation is not registered".to_string(),
            });
        }
        let data = self.command_data_with_cancellation(op, payload, cancellation)?;
        cancellation.ensure_open().map_err(|code| StorageError {
            code: code.to_string(),
            message: code.to_string(),
        })?;
        Ok(data)
    }

    // ------------------------------------------------------------------
    // Typed repository commands (production read/write path).
    // ------------------------------------------------------------------

    /// One atomic admission: session (created or touched), first user
    /// message, run, child link, idempotency record, run.started event, and
    /// retention floor commit in a single transaction. The returned data
    /// carries `replayed`, `run`, `session`, `message`, and `idempotency`.
    pub fn admission_create(&self, payload: &Value) -> Result<Value, StorageError> {
        self.admission_create_with_owner(payload, None)
    }

    /// Admission carrying the unsettled migration candidate owner. The
    /// reservation sidecar travels with the request until the worker settles
    /// it, so a caller timeout cannot unprotect an admission that is still
    /// queued or executing behind an earlier collector.
    pub(crate) fn admission_create_with_owner(
        &self,
        payload: &Value,
        state_owner: Option<crate::plugins::PluginStateCandidateLease>,
    ) -> Result<Value, StorageError> {
        let hook = self
            .admission_precommit_hook
            .lock()
            .expect("admission hook")
            .take();
        if let Some(hook) = hook {
            hook(payload);
        }
        #[cfg(test)]
        if self
            .admission_precommit_fail
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            return Err(StorageError {
                code: "storage_unavailable".to_string(),
                message: "gateway storage worker exited unexpectedly".to_string(),
            });
        }
        // The shadow is the same command, not a second transaction. The
        // caller's payload and the immutable hook stay unchanged.
        #[cfg(test)]
        let transformed = {
            let transform = self
                .admission_payload_transform
                .lock()
                .expect("admission payload transform")
                .take();
            transform.map(|transform| admission_failpoint_shadow(payload, transform))
        };
        #[cfg(test)]
        let command_payload = transformed.as_ref().unwrap_or(payload);
        #[cfg(not(test))]
        let command_payload = payload;
        #[cfg(any(test, feature = "workspace-io-fault"))]
        let state_fail_payload = self
            .admission_state_fail
            .swap(false, std::sync::atomic::Ordering::AcqRel)
            .then(|| {
                let mut shadow = payload.clone();
                shadow["plugin_state_failpoint"] = json!("after_root_cas");
                shadow
            });
        #[cfg(not(any(test, feature = "workspace-io-fault")))]
        let state_fail_payload: Option<Value> = None;
        let command_payload = state_fail_payload.as_ref().unwrap_or(command_payload);
        let result = self.command_data_with_owner("admission.create", command_payload, state_owner);
        #[cfg(test)]
        {
            let observer = self
                .admission_result_observer
                .lock()
                .expect("admission result observer")
                .take();
            if let Some(observer) = observer {
                observer(AdmissionCommandCode {
                    ok: result.is_ok(),
                    code: match &result {
                        Ok(_) => "ok".to_string(),
                        Err(error) => error.code.clone(),
                    },
                });
            }
        }
        #[cfg(test)]
        if result.as_ref().is_ok()
            || result
                .as_ref()
                .is_err_and(|e| e.code == "failpoint_after_commit_before_publish")
        {
            let hook = self.admission_postcommit_hook.lock().unwrap().take();
            if let Some(hook) = hook {
                hook(payload);
            }
        }
        #[cfg(any(test, feature = "workspace-io-fault"))]
        if result.as_ref().is_ok()
            && self
                .admission_ack_loss
                .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            return Err(StorageError {
                code: "storage_unavailable".to_string(),
                message: "gateway storage worker exited unexpectedly".to_string(),
            });
        }
        #[cfg(test)]
        if result.as_ref().is_ok()
            && self
                .admission_secondary_decode_loss
                .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            return Err(StorageError {
                code: "storage_error".to_string(),
                message: "decode admission result: response body was not valid storage json"
                    .to_string(),
            });
        }
        result
    }
    /// Drops one successful admission command ack after the real transaction
    /// and postcommit hook. The returned error is the existing response-loss
    /// code. The original payload and transaction are unchanged.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub fn inject_admission_ack_loss(&self) {
        self.admission_ack_loss
            .store(true, std::sync::atomic::Ordering::Release);
    }
    /// Sets the bounded replay-read fault. Only this mutex is taken; callbacks
    /// are not invoked here.
    #[cfg(test)]
    pub(crate) fn arm_admission_replay_read_failures(&self, count: u32) {
        *self
            .admission_replay_fail_remaining
            .lock()
            .expect("admission replay fault") = count;
    }
    #[cfg(test)]
    pub(crate) fn inject_admission_postcommit_hook(
        &self,
        hook: impl FnOnce(&Value) + Send + 'static,
    ) {
        *self.admission_postcommit_hook.lock().unwrap() = Some(Box::new(hook));
    }

    /// Fixture-only Native seam after preparation and before the original
    /// guarded transaction. No effect grants or storage authority are exposed.
    pub fn inject_admission_precommit_hook(&self, hook: impl FnOnce(&Value) + Send + 'static) {
        *self
            .admission_precommit_hook
            .lock()
            .expect("admission hook") = Some(Box::new(hook));
    }

    /// Fixture-only one-shot failure after the prepared state root CAS inside
    /// the durable admission transaction. No authority or storage handle is
    /// exposed; the transaction is the real guarded admission command.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub fn inject_admission_state_fail(&self) {
        self.admission_state_fail
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Fixture-only one-shot loss of a successful `plugin.state_object_put`
    /// reply after the real durable object transaction.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub fn inject_plugin_state_put_ack_loss(&self) {
        self.plugin_state_put_ack_loss
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Fixture-only one-shot real SQL failpoint for the typed state collector.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub fn inject_plugin_state_collect_failpoint(&self) {
        self.plugin_state_collect_failpoint
            .store(true, std::sync::atomic::Ordering::Release);
    }

    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub(crate) fn take_plugin_state_collect_failpoint(&self) -> bool {
        self.plugin_state_collect_failpoint
            .swap(false, std::sync::atomic::Ordering::AcqRel)
    }

    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub(crate) fn plugin_state_collect_observer_hook(&self) -> Option<StorageUnitHook> {
        self.plugin_state_collect_observer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Fixture-only observer immediately before the caller issues the typed
    /// state collection command. It never changes the protected set or SQL.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub fn inject_plugin_state_collect_observer(&self, observer: StorageUnitHook) {
        *self
            .plugin_state_collect_observer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(observer);
    }

    /// Fixture-only observer of candidate reservations established before the
    /// durable put. It never changes the producer.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub fn observe_plugin_state_candidate_reservations(&self, observer: StorageStringHook) {
        self.plugin_state_candidates.set_observer(observer);
    }

    /// Fixture-only blocking observer after a real `plugin.state_object_put`
    /// became durable and before its producer returns. It does not alter the
    /// put, the candidate registry, or any collector input.
    #[cfg(feature = "workspace-io-fault")]
    pub fn inject_plugin_state_object_put_observer(&self, observer: StorageStringHook) {
        *self
            .plugin_state_object_put_observer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(observer);
    }

    #[cfg(feature = "workspace-io-fault")]
    pub(crate) fn plugin_state_object_put_observer_hook(&self) -> Option<StorageStringHook> {
        self.plugin_state_object_put_observer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Fixture-only blocking observer after the typed collector command
    /// returned and before the caller records collection health.
    #[cfg(feature = "workspace-io-fault")]
    pub fn inject_plugin_state_collect_result_observer(&self, observer: StorageBoolHook) {
        *self
            .plugin_state_collect_result_observer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(observer);
    }

    #[cfg(feature = "workspace-io-fault")]
    pub(crate) fn plugin_state_collect_result_observer_hook(&self) -> Option<StorageBoolHook> {
        self.plugin_state_collect_result_observer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Fixture-only observer at the caller's collector enqueue seam, after the
    /// epoch snapshot and before the typed request. It reports whether the
    /// collect reports health (explicit) or not (backpressure-path quiet) and
    /// changes no command, epoch, or health state.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub fn inject_plugin_state_collect_enqueue_observer(&self, observer: StorageBoolHook) {
        *self
            .plugin_state_collect_enqueue_observer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(observer);
    }

    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub(crate) fn plugin_state_collect_enqueue_observer_hook(&self) -> Option<StorageBoolHook> {
        self.plugin_state_collect_enqueue_observer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Fixture-only observation of the collector injection budget inputs
    /// (protected count, full wire bytes, aggregate weight). The values are
    /// computed by the existing worker code; the observer cannot change the
    /// fail-closed decision or the payload.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub fn observe_plugin_state_collect_budget(
        &self,
        observer: Arc<dyn Fn(usize, usize, usize) + Send + Sync>,
    ) {
        self.plugin_state_candidates.set_budget_observer(observer);
    }

    /// Fixture-only blocking hook at the storage worker's execution boundary.
    /// Armed only after the requests under test are already queued in the
    /// controlled order.
    #[cfg(feature = "workspace-io-fault")]
    pub fn inject_worker_execute_gate(&self, gate: StorageStringHook) {
        *self
            .worker_execute_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(gate);
    }

    #[cfg(feature = "workspace-io-fault")]
    pub fn clear_worker_execute_gate(&self) {
        *self
            .worker_execute_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    /// Fixture-only blocking observer right after the worker takes one
    /// `plugin.state_collect` snapshot and before its RSS/SQL runs. The
    /// reported generation is the sweep's covered generation; the observer
    /// can park the worker there but never changes the snapshot, the
    /// payload, or any health state. Armed only while the sweep under test
    /// is already queued.
    #[cfg(feature = "workspace-io-fault")]
    pub fn inject_plugin_state_collect_snapshot_observer(&self, observer: StorageGenerationHook) {
        *self
            .worker_collect_snapshot_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(observer);
    }

    #[cfg(feature = "workspace-io-fault")]
    pub fn clear_plugin_state_collect_snapshot_observer(&self) {
        *self
            .worker_collect_snapshot_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    /// Fixture-only shorter real RPC reply window. The queued worker request
    /// and its durable effect are unchanged; only how long a caller waits for
    /// the reply is bounded below the normal storage timeout.
    #[cfg(feature = "workspace-io-fault")]
    pub fn inject_control_reply_timeout_for_test(&self, timeout: Duration) {
        *self
            .control_reply_timeout_override
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(timeout);
    }

    #[cfg(feature = "workspace-io-fault")]
    pub fn clear_control_reply_timeout_for_test(&self) {
        *self
            .control_reply_timeout_override
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    /// Reads one durable admission identity without mutating repository state.
    pub fn admission_replay(
        &self,
        scope: &str,
        key: &str,
        request_hash: &str,
        request_selector: Option<&str>,
    ) -> Result<Value, StorageError> {
        #[cfg(test)]
        {
            let mut remaining = self
                .admission_replay_fail_remaining
                .lock()
                .expect("admission replay fault");
            if *remaining > 0 {
                *remaining -= 1;
                drop(remaining);
                return Err(StorageError {
                    code: "storage_unavailable".to_string(),
                    message: "gateway storage worker exited unexpectedly".to_string(),
                });
            }
        }
        self.command_data(
            "admission.replay",
            &json!({
                "idempotency_scope": scope,
                "idempotency_key": key,
                "request_hash": request_hash,
                "request_selector_present": request_selector.is_some(),
                "request_selector": request_selector.unwrap_or_default(),
            }),
        )
    }

    pub(crate) fn admission_replay_for_proof(
        &self,
        scope: &str,
        key: &str,
        request_hash: &str,
        request_selector: Option<&str>,
        budget_until: Option<Instant>,
    ) -> Result<Value, StorageError> {
        #[cfg(test)]
        {
            let mut remaining = self
                .admission_replay_fail_remaining
                .lock()
                .expect("admission replay fault");
            if *remaining > 0 {
                *remaining -= 1;
                drop(remaining);
                return Err(StorageError {
                    code: "storage_unavailable".to_string(),
                    message: "gateway storage worker exited unexpectedly".to_string(),
                });
            }
        }
        self.command_data_for_original_proof(
            "admission.replay",
            &json!({
                "idempotency_scope": scope,
                "idempotency_key": key,
                "request_hash": request_hash,
                "request_selector_present": request_selector.is_some(),
                "request_selector": request_selector.unwrap_or_default(),
            }),
            budget_until,
        )
    }

    pub fn session_create(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("session.create", payload)
    }

    pub fn session_touch(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("session.touch", payload)
    }

    /// Atomically binds trusted workspace display metadata to an idle session
    /// through the RSS session command, preserving unrelated metadata keys.
    pub fn session_workspace_bind(
        &self,
        session_id: &str,
        workspace: &Value,
    ) -> Result<Value, StorageError> {
        let workspace_json = serde_json::to_string(workspace).map_err(|error| StorageError {
            code: "invalid_payload".to_string(),
            message: format!("workspace binding serialization failed: {error}"),
        })?;
        self.command_data(
            "session.workspace_bind",
            &json!({
                "session_id": session_id,
                "workspace_json": workspace_json,
                "now_ms": crate::domain::timestamp() as i64,
            }),
        )?;
        self.session_get(session_id)
    }

    /// Cascades one session (messages, runs, events, links, approvals,
    /// compactions, delivery cursors, idempotency, run graph refs) in one transaction.
    pub fn session_delete(&self, session_id: &str) -> Result<Value, StorageError> {
        self.command_data("session.delete", &json!({ "session_id": session_id }))
    }

    pub fn message_append(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("message.append", payload)
    }

    pub fn message_list(
        &self,
        session_id: &str,
        after_ordinal: i64,
    ) -> Result<Value, StorageError> {
        self.command_data(
            "message.list",
            &json!({
                "session_id": session_id,
                "after_ordinal": after_ordinal,
            }),
        )
    }

    pub fn message_compact(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("message.compact", payload)
    }

    /// Appends one run event with transactional sequence allocation and
    /// retention pruning.
    pub fn event_append(&self, payload: &Value) -> Result<Value, StorageError> {
        let is_model_requested =
            payload.get("event_type").and_then(Value::as_str) == Some("model.requested");
        if is_model_requested
            && self
                .fail_model_requested_append
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(StorageError {
                code: "storage_unavailable".to_string(),
                message: "injected model.requested persist failure".to_string(),
            });
        }
        self.command_data("event.append", payload)
    }

    /// Atomic message + event commit for one provider or tool step.
    /// The store lock / SQLite transaction is released by the worker before
    /// the caller publishes live.
    pub fn step_commit(&self, payload: &Value) -> Result<Value, StorageError> {
        let mut payload = payload.clone();
        if self
            .fail_after_partial_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            payload["failpoint"] = json!("after_partial_write");
        } else if self
            .fail_after_commit_before_publish
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            payload["failpoint"] = json!("after_commit_before_publish");
        }
        self.command_data("step.commit", &payload)
    }

    /// Atomic two-event commit for one prepare pair (`tool.requested` then
    /// `tool.started`, same run, no message). Single SQLite transaction;
    /// failpoint passthrough mirrors [`Self::step_commit`].
    pub fn event_append_pair(&self, payload: &Value) -> Result<Value, StorageError> {
        let mut payload = payload.clone();
        if self
            .fail_after_partial_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            payload["failpoint"] = json!("after_partial_write");
        } else if self
            .fail_after_commit_before_publish
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            payload["failpoint"] = json!("after_commit_before_publish");
        }
        self.command_data("event.append_pair", &payload)
    }

    /// Reconcile requested/started tool effects that lack durable output.
    pub fn reconcile_effects(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("recovery.reconcile_effects", payload)
    }

    #[cfg(test)]
    pub(crate) fn mutate_graph_pin_for_test(
        &self,
        run_id: &str,
        mutation: &str,
    ) -> Result<Value, StorageError> {
        assert!(matches!(
            mutation,
            "drop_requirement"
                | "drop_binding"
                | "replace_ref"
                | "forge_restore_selection"
                | "drop_package_ref"
                | "forge_run_selection"
        ));
        self.command_data(
            "plugin.fixture_pin_state",
            &json!({"owner_id":run_id,"mutation":mutation}),
        )
    }

    /// Test failpoint: the next storage command fails before the worker runs.
    pub fn inject_persist_failure(&self) {
        self.fail_next
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test failpoint: the next `step.commit` aborts inside the SQLite
    /// transaction after partial writes so the whole step rolls back.
    pub fn inject_fail_after_partial_write(&self) {
        self.fail_after_partial_write
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test failpoint: the next `step.commit` succeeds durably then returns
    /// a typed error before the caller broadcasts. GET remains on the
    /// pre-commit snapshot until recovery loads the durable event.
    pub fn inject_fail_after_commit_before_publish(&self) {
        self.fail_after_commit_before_publish
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test failpoint: the next `event.append` for a `model.requested`
    /// boundary fails before SQLite runs. Other event types are ignored so
    /// the inner provider call is never reached.
    pub fn inject_fail_model_requested_append(&self) {
        self.fail_model_requested_append
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test failpoint: the next plugin-control write aborts inside its SQLite
    /// transaction after the partial statements, so that transaction rolls back.
    pub fn inject_fail_plugin_control_partial(&self) {
        self.fail_plugin_control_partial
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn take_plugin_control_failpoint(&self) -> bool {
        self.fail_plugin_control_partial
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }

    /// Test failpoint: the next storage command blocks until the returned
    /// guard is released. Used to prove GET/write can proceed without the
    /// GatewayStore lock being held across SQLite IO.
    pub fn inject_block_persist(&self) -> PersistBlockGuard {
        let inner = Arc::new(PersistBlockState {
            mutex: Mutex::new(()),
            entered: AtomicBool::new(false),
            released: AtomicBool::new(false),
            entered_cvar: Condvar::new(),
            released_cvar: Condvar::new(),
            #[cfg(test)]
            entered_schedule: PersistBlockSchedule::default(),
            #[cfg(test)]
            released_schedule: PersistBlockSchedule::default(),
        });
        *self.persist_block.lock().expect("persist block lock") = Some(Arc::clone(&inner));
        PersistBlockGuard { inner }
    }

    /// Arms a one-shot rendezvous of `parties` callers. Each guarded plugin
    /// command waits after its stale pre-check and before the mutation.
    /// The returned controller aborts every cloned waiter on drop.
    pub fn arm_plugin_control_precommit_gate(&self, parties: usize) -> PluginControlGateGuard {
        assert!(parties >= 1, "plugin precommit gate needs a participant");
        let inner = Arc::new(PluginControlGate {
            mutex: Mutex::new(PluginControlGateState {
                arrived: 0,
                completed: false,
                aborted: false,
            }),
            cvar: Condvar::new(),
            parties,
            deadline: Instant::now() + PLUGIN_CONTROL_FIXTURE_BOUND,
        });
        *self
            .plugin_control_precommit_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::clone(&inner));
        PluginControlGateGuard { inner }
    }

    /// Aborts cloned waiters and removes the current rendezvous slot.
    pub fn disarm_plugin_control_precommit_gate(&self) {
        let gate = self
            .plugin_control_precommit_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(gate) = gate {
            gate.abort();
        }
    }

    pub(crate) fn abort_plugin_control_precommit_gate(&self) {
        let gate = self
            .plugin_control_precommit_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(gate) = gate {
            gate.abort();
        }
    }

    pub(crate) fn enter_plugin_control_precommit_gate(&self) -> Result<(), StorageError> {
        let gate = self
            .plugin_control_precommit_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(gate) = gate else {
            return Ok(());
        };
        let mut state = gate.lock();
        if state.completed {
            return Err(plugin_control_fixture_error(PLUGIN_CONTROL_FIXTURE_CLOSED));
        }
        if state.aborted {
            return Err(plugin_control_fixture_error(PLUGIN_CONTROL_FIXTURE_ABORTED));
        }
        if Instant::now() >= gate.deadline {
            state.aborted = true;
            gate.cvar.notify_all();
            return Err(plugin_control_fixture_error(PLUGIN_CONTROL_FIXTURE_TIMEOUT));
        }
        state.arrived = state.arrived.saturating_add(1);
        if state.arrived == gate.parties {
            state.completed = true;
            gate.cvar.notify_all();
            return Ok(());
        }
        if state.arrived > gate.parties {
            return Err(plugin_control_fixture_error(PLUGIN_CONTROL_FIXTURE_CLOSED));
        }
        while !state.completed && !state.aborted {
            let now = Instant::now();
            if now >= gate.deadline {
                state.aborted = true;
                gate.cvar.notify_all();
                return Err(plugin_control_fixture_error(PLUGIN_CONTROL_FIXTURE_TIMEOUT));
            }
            let (next, timeout) = gate
                .cvar
                .wait_timeout(state, gate.deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if timeout.timed_out() && !state.completed && !state.aborted {
                state.aborted = true;
                gate.cvar.notify_all();
                return Err(plugin_control_fixture_error(PLUGIN_CONTROL_FIXTURE_TIMEOUT));
            }
        }
        if state.aborted {
            return Err(plugin_control_fixture_error(PLUGIN_CONTROL_FIXTURE_ABORTED));
        }
        if state.completed {
            return Ok(());
        }
        Err(plugin_control_fixture_error(PLUGIN_CONTROL_FIXTURE_TIMEOUT))
    }

    /// Arms a one-shot pause between retain's graph pre-read and its command.
    pub fn arm_plugin_retain_precommit_pause(&self) -> PluginRetainPauseGuard {
        let inner = Arc::new(PluginRetainPause {
            mutex: Mutex::new(PluginRetainPauseState {
                entered: false,
                released: false,
                aborted: false,
            }),
            cvar: Condvar::new(),
            deadline: Instant::now() + PLUGIN_CONTROL_FIXTURE_BOUND,
        });
        *self
            .plugin_retain_precommit_pause
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::clone(&inner));
        PluginRetainPauseGuard { inner }
    }

    pub(crate) fn enter_plugin_retain_precommit_pause(&self) -> Result<(), StorageError> {
        let pause = self
            .plugin_retain_precommit_pause
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(pause) = pause else {
            return Ok(());
        };
        let mut state = lock_retain(&pause);
        state.entered = true;
        pause.cvar.notify_all();
        while !state.released && !state.aborted {
            let now = Instant::now();
            if now >= pause.deadline {
                state.aborted = true;
                pause.cvar.notify_all();
                return Err(plugin_control_fixture_error(PLUGIN_CONTROL_FIXTURE_TIMEOUT));
            }
            let (next, timeout) = pause
                .cvar
                .wait_timeout(state, pause.deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if timeout.timed_out() && !state.released && !state.aborted {
                state.aborted = true;
                pause.cvar.notify_all();
                return Err(plugin_control_fixture_error(PLUGIN_CONTROL_FIXTURE_TIMEOUT));
            }
        }
        if state.aborted {
            return Err(plugin_control_fixture_error(PLUGIN_CONTROL_FIXTURE_ABORTED));
        }
        Ok(())
    }

    /// Runs once after this activation's command returns and before the caller
    /// builds its result. A later legitimate activation can commit here without
    /// a sleep or a process-global lock.
    pub fn arm_plugin_activate_receipt_hook(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self
            .plugin_activate_receipt_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(hook));
    }

    pub(crate) fn begin_plugin_activate_receipt_attempt(&self) -> PluginActivateReceiptAttempt {
        PluginActivateReceiptAttempt {
            hook: self
                .plugin_activate_receipt_hook
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take(),
        }
    }

    /// One atomic terminal commit: run status transition plus terminal
    /// events (and optional assistant message) in a single transaction.
    /// The returned data carries the run row and the run's event rows.
    pub fn run_terminal(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("run.terminal", payload)
    }

    pub fn run_create(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("run.create", payload)
    }

    /// A guarded typed run status transition (0 rows is a typed
    /// `transition_conflict`).
    pub fn run_transition(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("run.transition", payload)
    }

    pub fn run_get(&self, run_id: &str) -> Result<Value, StorageError> {
        self.command_data("run.get", &json!({ "run_id": run_id }))
    }

    pub(crate) fn run_get_for_proof(
        &self,
        run_id: &str,
        budget_until: Option<Instant>,
    ) -> Result<Value, StorageError> {
        self.command_data_for_original_proof("run.get", &json!({ "run_id": run_id }), budget_until)
    }

    pub fn session_get(&self, session_id: &str) -> Result<Value, StorageError> {
        self.command_data("session.get", &json!({ "session_id": session_id }))
    }

    /// Reads one delivery cursor row (`session_id`, `consumer`,
    /// `last_event_seq`, `updated_at_ms`); an empty `rows` array means no
    /// cursor was ever persisted for the consumer.
    pub fn delivery_get(&self, session_id: &str, consumer: &str) -> Result<Value, StorageError> {
        self.command_data(
            "delivery.get",
            &json!({ "session_id": session_id, "consumer": consumer }),
        )
    }

    /// Monotonic validated cursor advance for run-event delivery: the value
    /// must not exceed the session's high-water event sequence.
    pub fn delivery_advance(
        &self,
        session_id: &str,
        consumer: &str,
        event_seq: i64,
    ) -> Result<Value, StorageError> {
        self.command_data(
            "delivery.advance",
            &json!({
                "session_id": session_id,
                "consumer": consumer,
                "event_seq": event_seq,
                "now_ms": timestamp() as i64,
            }),
        )
    }

    /// Monotonic unvalidated cursor upsert for transport-level values (for
    /// example the Telegram getUpdates offset) that are unrelated to run
    /// event sequences.
    pub fn delivery_set(
        &self,
        session_id: &str,
        consumer: &str,
        value: i64,
    ) -> Result<Value, StorageError> {
        self.command_data(
            "delivery.set",
            &json!({
                "session_id": session_id,
                "consumer": consumer,
                "event_seq": value,
                "now_ms": timestamp() as i64,
            }),
        )
    }

    /// Replays one run's retained events with precise
    /// oldest/high-water cursors (`cursor_too_old` below the floor).
    pub fn event_replay(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("event.replay", payload)
    }

    pub fn job_create(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("job.create", payload)
    }

    pub fn job_update(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("job.update", payload)
    }

    pub fn job_delete(&self, job_id: &str) -> Result<Value, StorageError> {
        self.command_data("job.delete", &json!({ "job_id": job_id }))
    }

    pub fn approval_request(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("approval.request", payload)
    }

    pub fn approval_get(&self, approval_id: &str) -> Result<Value, StorageError> {
        self.command_data("approval.get", &json!({ "approval_id": approval_id }))
    }

    pub fn approval_list(&self, run_id: &str, session_id: &str) -> Result<Value, StorageError> {
        self.command_data(
            "approval.list",
            &json!({ "run_id": run_id, "session_id": session_id }),
        )
    }

    pub fn approval_resolve(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("approval.resolve", payload)
    }

    pub fn approval_expire(&self, payload: &Value) -> Result<Value, StorageError> {
        #[cfg(feature = "config-fixture")]
        let hook = self
            .approval_expire_hook
            .lock()
            .expect("approval expiry hook")
            .take();
        #[cfg(feature = "config-fixture")]
        let completed = hook.map(|hook| {
            (hook.before)();
            hook.completed
        });
        let result = self.command_data("approval.expire", payload);
        #[cfg(feature = "config-fixture")]
        if let Some(completed) = completed {
            completed(result.is_ok());
        }
        result
    }

    /// Fixture-local one-shot observer immediately before approval expiry IO.
    /// No payload or SQL is exposed, and the callback runs outside the lock.
    #[cfg(feature = "config-fixture")]
    pub fn inject_approval_expire_hook(
        &self,
        before: impl FnOnce() + Send + 'static,
        completed: impl FnOnce(bool) + Send + 'static,
    ) {
        *self
            .approval_expire_hook
            .lock()
            .expect("approval expiry hook") = Some(ApprovalExpireHook {
            before: Box::new(before),
            completed: Box::new(completed),
        });
    }

    pub fn compaction_start(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("compaction.start", payload)
    }

    pub fn compaction_get(&self, compaction_id: &str) -> Result<Value, StorageError> {
        self.command_data("compaction.get", &json!({ "compaction_id": compaction_id }))
    }

    pub fn compaction_latest(&self, session_id: &str) -> Result<Value, StorageError> {
        self.command_data("compaction.latest", &json!({ "session_id": session_id }))
    }

    pub fn compaction_commit(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("compaction.commit", payload)
    }

    pub fn compaction_fail(&self, payload: &Value) -> Result<Value, StorageError> {
        self.command_data("compaction.fail", payload)
    }

    /// Restart recovery: migrates the schema, recovers every interrupted
    /// active run to the documented terminal restart state in transactional
    /// bounded batches (exactly once per run, guarded by
    /// `recovery_records`), and rebuilds the in-memory store from the
    /// cursor-paginated normalized dump.
    pub fn load(&self) -> Result<GatewayStore, String> {
        let migrated = self
            .command_data("migrate", &json!({}))
            .map_err(|error| format!("migrate gateway state: {error}"))?;
        if migrated.get("schema_version") != Some(&json!(6)) {
            return Err(format!(
                "gateway schema migrated to an unexpected version: {migrated}"
            ));
        }
        let mut recovered = 1i64;
        let mut rounds = 0u32;
        while recovered > 0 {
            let result = self
                .command_data(
                    "recovery.recover_active",
                    &json!({
                        "reason": "gateway_restart",
                        "details_json": "{}",
                        "now_ms": timestamp(),
                        "max_rows": RECOVERY_BATCH,
                        "max_bytes": LOAD_PAGE_BYTES,
                        "max_events": self.max_events,
                    }),
                )
                .map_err(|error| format!("recover interrupted runs: {error}"))?;
            recovered = result.get("recovered").and_then(Value::as_i64).unwrap_or(0);
            rounds += 1;
            if rounds > 10_000 {
                return Err("restart recovery did not converge".to_string());
            }
        }
        crate::effects::journal::recover_managed_effects(self)
            .map_err(|e| format!("recover managed effects: {e}"))?;
        let mut remaining = 1i64;
        let mut effect_rounds = 0u32;
        while remaining > 0 {
            let result = self
                .command_data(
                    "recovery.reconcile_effects",
                    &json!({
                        "now_ms": timestamp(),
                        "max_rows": RECOVERY_BATCH,
                    }),
                )
                .map_err(|error| format!("reconcile interrupted effects: {error}"))?;
            remaining = first_rows_affected(&result);
            effect_rounds += 1;
            if effect_rounds > 10_000 {
                return Err("effect reconciliation did not converge".to_string());
            }
        }
        let data = self
            .command_data(
                "load.all",
                &json!({
                    "max_rows": LOAD_PAGE_ROWS,
                    "max_bytes": LOAD_PAGE_BYTES,
                    "load_cap": LOAD_CAP_ROWS,
                }),
            )
            .map_err(|error| format!("load gateway state: {error}"))?;
        GatewayStore::from_load(&data, self.broadcast_capacity)
    }
}

impl StorageWorker {
    /// Signals the worker to exit and joins it, exactly once (idempotent
    /// under concurrent calls and `Drop`).
    fn shutdown(&self) {
        // Every caller waits behind the join, including callers that observe
        // `closed` while the first shutdown still owns a live worker. `closed`
        // fences new commands; it is not a completion signal.
        let mut thread = self.thread.lock().expect("storage thread lock");
        if self.closed.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        let _ = self.shutdown.send(());
        if let Some(thread) = thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for GatewayPersistence {
    /// Signals the worker to exit and joins it so no storage thread outlives
    /// the persistence handle.
    fn drop(&mut self) {
        self.worker.shutdown();
    }
}

#[derive(Default)]
pub struct GatewayStore {
    pub(crate) sessions: BTreeMap<String, SessionRecord>,
    pub(crate) runs: HashMap<String, RunRecord>,
    pub(crate) jobs: BTreeMap<String, JobRecord>,
    pub(crate) idempotency: HashMap<String, IdempotencyRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct IdempotencyRecord {
    pub(crate) request_hash: String,
    pub(crate) run_id: String,
    pub(crate) workspace_identity_json: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SessionRecord {
    pub(crate) view: SessionView,
    pub(crate) messages: Vec<SessionMessage>,
}

#[derive(Clone)]
pub(crate) struct RunRecord {
    pub(crate) run_id: String,
    pub(crate) session_id: String,
    pub(crate) parent_run_id: Option<String>,
    pub(crate) status: String,
    pub(crate) events: Vec<GatewayEvent>,
    /// Live delivery channel; `None` once the run's stream was closed (the
    /// bounded terminal retry expired) so SSE subscribers are never held
    /// forever without a terminal event.
    pub(crate) sender: Option<broadcast::Sender<GatewayEvent>>,
    /// Legacy boolean stop flag kept for in-memory compatibility; the
    /// authoritative typed cancellation lives in the service RunHandle.
    #[allow(dead_code)]
    pub(crate) cancel_requested: Arc<AtomicBool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct JobRecord {
    pub(crate) view: JobView,
    pub(crate) output: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct JobView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) schedule: Value,
    pub(crate) prompt: String,
    pub(crate) deliver: Value,
    pub(crate) skills: Vec<String>,
    pub(crate) repeat: Option<i64>,
    pub(crate) enabled: bool,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
    pub(crate) last_run_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct WorkspaceBinding {
    pub(crate) selector: String,
    pub(crate) canonical_path: String,
    pub(crate) selected_name: Option<String>,
    pub(crate) generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SessionView {
    pub(crate) id: String,
    pub(crate) object: String,
    pub(crate) title: Option<String>,
    pub(crate) model: String,
    pub(crate) provider: Option<String>,
    pub(crate) source: String,
    pub(crate) system_prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) workspace: Option<WorkspaceBinding>,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
    pub(crate) message_count: usize,
    pub(crate) end_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SessionMessage {
    pub(crate) id: String,
    pub(crate) session_id: String,
    pub(crate) role: String,
    pub(crate) content: Value,
    pub(crate) created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) finish_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) parent_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) token_estimate: Option<i64>,
    #[serde(default, skip_serializing_if = "is_null_or_empty")]
    pub(crate) metadata: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ordinal: Option<i64>,
}

fn is_null_or_empty(value: &Value) -> bool {
    value.is_null() || value.as_object().is_some_and(|object| object.is_empty())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GatewayEvent {
    pub(crate) event_id: String,
    pub(crate) seq: u64,
    pub(crate) event: String,
    pub(crate) run_id: String,
    pub(crate) timestamp: u64,
    pub(crate) data: Value,
}

impl GatewayEvent {
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(
            self.event.as_str(),
            "run.completed" | "run.cancelled" | "run.failed"
        )
    }

    pub(crate) fn into_sse(self) -> axum::response::sse::Event {
        let event_name = self.event.clone();
        let mut payload = serde_json::Map::new();
        payload.insert("event_id".to_string(), Value::String(self.event_id.clone()));
        payload.insert("seq".to_string(), json!(self.seq));
        payload.insert("event".to_string(), Value::String(self.event));
        payload.insert("run_id".to_string(), Value::String(self.run_id));
        payload.insert("timestamp".to_string(), json!(self.timestamp));
        match self.data {
            Value::Object(fields) => payload.extend(fields),
            data => {
                payload.insert("data".to_string(), data);
            }
        }
        let data =
            serde_json::to_string(&Value::Object(payload)).unwrap_or_else(|_| "{}".to_string());
        axum::response::sse::Event::default()
            .event(event_name)
            .data(data)
    }
}

/// Maps a normalized run status back to the gateway's in-memory status
/// vocabulary. The DB persists only `running` for active runs (a gateway
/// `stopping` state is in-memory only); restart recovery converts every
/// non-terminal DB status to `failed` before load, so any leftover active
/// status maps defensively to `started`.
fn memory_status(db_status: &str) -> &'static str {
    match db_status {
        "completed" => "completed",
        "failed" => "failed",
        "cancelled" => "cancelled",
        _ => "started",
    }
}

impl GatewayStore {
    /// Rebuilds the in-memory store from the normalized `load.all` dump.
    /// Validation is explicit and hard-failing: duplicate ids, unknown
    /// session/message references, unknown parent runs, and event sequence
    /// gaps are all rejected (agent correctness never depends on SQLite
    /// foreign-key enforcement, which the core host does not enable).
    fn from_load(data: &Value, broadcast_capacity: usize) -> Result<Self, String> {
        let session_rows = load_rows(data, "sessions")?;
        let message_rows = load_rows(data, "messages")?;
        let run_rows = load_rows(data, "runs")?;
        let event_rows = load_rows(data, "events")?;
        let job_rows = load_rows(data, "jobs")?;
        let idempotency_rows = load_rows(data, "idempotency")?;

        let mut sessions = BTreeMap::new();
        for row in session_rows {
            let id = string_cell(&row, 0, "session id")?;
            let metadata = json_optional_cell(&row, 13, "session metadata")?.unwrap_or(Value::Null);
            let workspace = metadata
                .get("workspace")
                .filter(|value| !value.is_null())
                .map(|value| {
                    serde_json::from_value(value.clone())
                        .map_err(|_| "invalid workspace binding metadata".to_string())
                })
                .transpose()?;
            let view = SessionView {
                id: id.clone(),
                object: "hermes.session".to_string(),
                title: optional_string(&row, 17),
                model: string_cell(&row, 10, "session model")?,
                provider: optional_string(&row, 11),
                source: string_cell(&row, 2, "session platform")?,
                system_prompt: optional_string(&row, 9),
                workspace,
                created_at: int_cell(&row, 15, "session created_at")? as u64,
                updated_at: int_cell(&row, 16, "session updated_at")? as u64,
                message_count: 0,
                end_reason: optional_string(&row, 18),
            };
            if sessions
                .insert(
                    id.clone(),
                    SessionRecord {
                        view,
                        messages: Vec::new(),
                    },
                )
                .is_some()
            {
                return Err(format!("duplicate session row: {id}"));
            }
        }
        let mut messages_by_session: HashMap<String, Vec<SessionMessage>> = HashMap::new();
        for row in message_rows {
            let session_id = string_cell(&row, 2, "message session id")?;
            if !sessions.contains_key(&session_id) {
                return Err(format!("message references unknown session: {session_id}"));
            }
            let message = SessionMessage {
                id: string_cell(&row, 1, "message id")?,
                session_id: session_id.clone(),
                role: string_cell(&row, 3, "message role")?,
                content: crate::domain::decode_message_content(&json_cell(
                    &row,
                    4,
                    "message content",
                )?),
                created_at: int_cell(&row, 13, "message created_at")? as u64,
                run_id: optional_string(&row, 11),
                finish_reason: optional_string(&row, 12),
                name: optional_string(&row, 5),
                tool_call_id: optional_string(&row, 6),
                parent_message_id: optional_string(&row, 7),
                token_estimate: row
                    .get(8)
                    .and_then(Value::as_i64)
                    .filter(|value| *value != 0),
                metadata: json_optional_cell(&row, 10, "message metadata")?.unwrap_or(Value::Null),
                ordinal: row.first().and_then(Value::as_i64),
            };
            messages_by_session
                .entry(session_id)
                .or_default()
                .push(message);
        }
        for (session_id, mut messages) in messages_by_session {
            messages.sort_by_key(|message| (message.ordinal.unwrap_or(0), message.created_at));
            let session = sessions
                .get_mut(&session_id)
                .expect("session presence was validated above");
            session.messages = messages;
            session.view.message_count = session.messages.len();
        }

        let mut runs = HashMap::new();
        for row in run_rows {
            let run_id = string_cell(&row, 0, "run id")?;
            let session_id = string_cell(&row, 1, "run session id")?;
            if !sessions.contains_key(&session_id) {
                return Err(format!("run references unknown session: {session_id}"));
            }
            let (sender, _) = broadcast::channel(broadcast_capacity);
            let run = RunRecord {
                run_id: run_id.clone(),
                session_id,
                parent_run_id: optional_string(&row, 2),
                status: memory_status(&string_cell(&row, 3, "run status")?).to_string(),
                events: Vec::new(),
                sender: Some(sender),
                cancel_requested: Arc::new(AtomicBool::new(false)),
            };
            if runs.insert(run_id.clone(), run).is_some() {
                return Err(format!("duplicate run row: {run_id}"));
            }
        }
        // Parent references must exist (the RSS layer enforces this on
        // write; load re-validates so correctness never depends on FK).
        for run in runs.values() {
            if let Some(parent) = run.parent_run_id.as_deref()
                && !runs.contains_key(parent)
            {
                return Err(format!("run references unknown parent run: {parent}"));
            }
        }
        let mut events_by_run: HashMap<String, Vec<GatewayEvent>> = HashMap::new();
        for row in event_rows {
            let run_id = string_cell(&row, 1, "event run id")?;
            if !runs.contains_key(&run_id) {
                return Err(format!("event references unknown run: {run_id}"));
            }
            let event = GatewayEvent {
                event_id: string_cell(&row, 2, "event id")?,
                seq: int_cell(&row, 0, "event seq")? as u64,
                event: string_cell(&row, 3, "event type")?,
                run_id: run_id.clone(),
                timestamp: int_cell(&row, 5, "event created_at")? as u64,
                data: json_cell(&row, 4, "event payload")?,
            };
            events_by_run.entry(run_id).or_default().push(event);
        }
        for (run_id, mut events) in events_by_run {
            events.sort_by_key(|event| event.seq);
            let mut seen = HashSet::new();
            let first_seq = events.first().map(|event| event.seq).unwrap_or(1);
            for (index, event) in events.iter().enumerate() {
                let expected_seq = first_seq + index as u64;
                if event.seq != expected_seq || !seen.insert(event.event_id.clone()) {
                    return Err(format!(
                        "event sequence gap or duplicate for run {run_id}: expected {expected_seq}, got {}",
                        event.seq
                    ));
                }
            }
            runs.get_mut(&run_id)
                .expect("run presence was validated above")
                .events = events;
        }

        let mut jobs = BTreeMap::new();
        for row in job_rows {
            let id = string_cell(&row, 0, "job id")?;
            let repeat = int_cell(&row, 6, "job repeat")?;
            let job = JobRecord {
                view: JobView {
                    id: id.clone(),
                    name: string_cell(&row, 1, "job name")?,
                    schedule: json_cell(&row, 2, "job schedule")?,
                    prompt: string_cell(&row, 3, "job prompt")?,
                    deliver: json_cell(&row, 4, "job deliver")?,
                    skills: json_array_strings(&row, 5, "job skills")?,
                    repeat: (repeat > 0).then_some(repeat),
                    enabled: int_cell(&row, 7, "job enabled")? != 0,
                    created_at: int_cell(&row, 9, "job created_at")? as u64,
                    updated_at: int_cell(&row, 10, "job updated_at")? as u64,
                    last_run_at: {
                        let value = int_cell(&row, 11, "job last_run_at")?;
                        (value > 0).then_some(value as u64)
                    },
                },
                output: json_optional_cell(&row, 8, "job output")?,
            };
            if jobs.insert(id.clone(), job).is_some() {
                return Err(format!("duplicate job row: {id}"));
            }
        }

        let mut idempotency = HashMap::new();
        for row in idempotency_rows {
            if string_cell(&row, 0, "idempotency scope")? == "native.tool-pin" {
                // Internal original receipts are not caller idempotency keys.
                continue;
            }
            let key = string_cell(&row, 1, "idempotency key")?;
            let state = string_cell(&row, 5, "idempotency state")?;
            if state == "completed" {
                let response = json_cell(&row, 6, "idempotency response")?;
                let record = IdempotencyRecord {
                    request_hash: string_cell(&row, 2, "idempotency request hash")?,
                    run_id: string_cell(&row, 4, "idempotency resource id")?,
                    workspace_identity_json: response
                        .get("workspace_identity")
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|error| {
                            format!("idempotency workspace identity is invalid: {error}")
                        })?,
                };
                if idempotency.insert(key.clone(), record).is_some() {
                    return Err(format!("duplicate idempotency row: {key}"));
                }
            }
        }

        Ok(Self {
            sessions,
            runs,
            jobs,
            idempotency,
        })
    }
}

fn load_rows(data: &Value, key: &str) -> Result<Vec<Vec<Value>>, String> {
    let nested = data
        .get(key)
        .ok_or_else(|| format!("load.all result omitted {key} rows"))?;
    crate::sqlite_storage_rows::sqlite_storage_rows(nested)
        .map_err(|error| format!("load.all {key}: {error}"))
}

fn string_cell(row: &[Value], index: usize, label: &str) -> Result<String, String> {
    row.get(index)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("load.all row missing {label}"))
}

fn optional_string(row: &[Value], index: usize) -> Option<String> {
    row.get(index)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn int_cell(row: &[Value], index: usize, label: &str) -> Result<i64, String> {
    row.get(index)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("load.all row missing {label}"))
}

fn json_cell(row: &[Value], index: usize, label: &str) -> Result<Value, String> {
    match row.get(index) {
        Some(Value::String(text)) => {
            serde_json::from_str(text).map_err(|error| format!("decode {label}: {error}"))
        }
        Some(other) => Ok(other.clone()),
        None => Err(format!("load.all row missing {label}")),
    }
}

fn decode_command_data(data: Value) -> Result<Value, StorageError> {
    if data.get("rows").is_none() {
        return Ok(data);
    }
    let rows =
        crate::sqlite_storage_rows::sqlite_storage_rows(&data).map_err(|message| StorageError {
            code: "storage_error".to_string(),
            message,
        })?;
    match data {
        Value::Object(mut map) => {
            map.insert("rows".into(), json!(rows));
            Ok(Value::Object(map))
        }
        other => Ok(other),
    }
}

fn first_rows_affected(data: &Value) -> i64 {
    let Some(first) = data
        .get("results")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
    else {
        return 0;
    };
    if first.get("kind").and_then(Value::as_str) != Some("execute") {
        return 0;
    }
    first
        .get("execute")
        .and_then(|exec| exec.get("rows_affected"))
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

fn json_optional_cell(row: &[Value], index: usize, label: &str) -> Result<Option<Value>, String> {
    match row.get(index) {
        Some(Value::String(text)) if text.is_empty() => Ok(None),
        Some(Value::String(text)) => serde_json::from_str(text)
            .map(Some)
            .map_err(|error| format!("decode {label}: {error}")),
        Some(Value::Null) | None => Ok(None),
        Some(other) => Ok(Some(other.clone())),
    }
}

fn json_array_strings(row: &[Value], index: usize, label: &str) -> Result<Vec<String>, String> {
    let value = json_cell(row, index, label)?;
    value
        .as_array()
        .ok_or_else(|| format!("{label} is not an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("{label} contains a non-string"))
        })
        .collect()
}

/// Appends one session message and updates the session view counters.
pub(crate) fn append_message(
    view: &mut SessionView,
    messages: &mut Vec<SessionMessage>,
    role: &str,
    content: Value,
    run_id: Option<String>,
    finish_reason: Option<String>,
) -> SessionMessage {
    let message = SessionMessage {
        id: Uuid::new_v4().to_string(),
        session_id: view.id.clone(),
        role: role.to_string(),
        content: crate::domain::decode_message_content(&content),
        created_at: timestamp(),
        run_id,
        finish_reason,
        name: None,
        tool_call_id: None,
        parent_message_id: None,
        token_estimate: None,
        metadata: Value::Null,
        ordinal: None,
    };
    messages.push(message.clone());
    view.message_count = messages.len();
    view.updated_at = timestamp();
    message
}

#[cfg(test)]
mod persist_block_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::thread::JoinHandle;

    const BOUND: Duration = Duration::from_secs(10);

    fn block() -> Arc<PersistBlockGuard> {
        Arc::new(PersistBlockGuard {
            inner: Arc::new(PersistBlockState {
                mutex: Mutex::new(()),
                entered: AtomicBool::new(false),
                released: AtomicBool::new(false),
                entered_cvar: Condvar::new(),
                released_cvar: Condvar::new(),
                entered_schedule: PersistBlockSchedule::default(),
                released_schedule: PersistBlockSchedule::default(),
            }),
        })
    }

    // Rescue only after saving the observation. Drop also releases controls
    // and joins the exact native owners if an earlier assertion unwinds.
    struct Owners {
        block: Arc<PersistBlockGuard>,
        resume: Option<mpsc::Sender<()>>,
        threads: Vec<JoinHandle<()>>,
        joined: Arc<AtomicUsize>,
        failed: Arc<AtomicBool>,
    }

    impl Owners {
        fn new(block: Arc<PersistBlockGuard>, resume: mpsc::Sender<()>) -> Self {
            Self {
                block,
                resume: Some(resume),
                threads: Vec::new(),
                joined: Arc::default(),
                failed: Arc::default(),
            }
        }

        fn resume(&mut self) {
            if let Some(resume) = self.resume.take() {
                let _ = resume.send(());
            }
        }
    }

    impl Drop for Owners {
        fn drop(&mut self) {
            self.resume();
            {
                let _guard = self
                    .block
                    .inner
                    .mutex
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                self.block.inner.entered.store(true, Ordering::SeqCst);
                self.block.inner.released.store(true, Ordering::SeqCst);
                self.block.inner.entered_cvar.notify_all();
                self.block.inner.released_cvar.notify_all();
            }
            for thread in self.threads.drain(..) {
                if thread.join().is_err() {
                    self.failed.store(true, Ordering::SeqCst);
                }
                self.joined.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    #[test]
    fn signals_before_waits_are_observed_without_another_notification() {
        let block = block();
        block.release();
        block.release();
        block.inner.enter_and_wait();
        block.wait_entered();
        assert!(block.inner.entered.load(Ordering::SeqCst));
        assert!(block.inner.released.load(Ordering::SeqCst));
    }

    #[test]
    fn release_recovers_a_poisoned_predicate_mutex_during_unwind() {
        struct ReleaseOnDrop<'a>(&'a PersistBlockGuard);
        impl Drop for ReleaseOnDrop<'_> {
            fn drop(&mut self) {
                self.0.release();
            }
        }

        let block = block();
        let poisoned = std::panic::catch_unwind(|| {
            let _guard = block.inner.mutex.lock().unwrap();
            std::panic::panic_any(37_u8);
        });
        assert_eq!(poisoned.unwrap_err().downcast_ref::<u8>(), Some(&37));
        assert!(block.inner.mutex.is_poisoned());
        // Check the fallible control outside unwind first, so a regression
        // reports an ordinary assertion rather than a double-panic abort.
        let released = std::panic::catch_unwind(|| block.release());
        assert!(
            released.is_ok(),
            "release must retain its non-panicking cleanup contract"
        );
        let unwound = std::panic::catch_unwind(|| {
            let _release = ReleaseOnDrop(&block);
            std::panic::panic_any(73_u8);
        });
        assert_eq!(unwound.unwrap_err().downcast_ref::<u8>(), Some(&73));
        assert!(block.inner.released.load(Ordering::SeqCst));
    }

    #[test]
    fn controlled_owner_cleanup_joins_and_preserves_the_first_unwind() {
        for cleanup_panic in [false, true] {
            let block = block();
            let (arrived, at_wait) = mpsc::channel();
            let (resume, resumed) = mpsc::channel();
            *block.inner.entered_schedule.before_wait.lock().unwrap() = Some((arrived, resumed));
            let mut owners = Owners::new(Arc::clone(&block), resume);
            let joined = Arc::clone(&owners.joined);
            let failed = Arc::clone(&owners.failed);
            owners.threads.push(std::thread::spawn(move || {
                block.wait_entered();
                if cleanup_panic {
                    std::panic::panic_any(91_u8);
                }
            }));
            at_wait
                .recv_timeout(BOUND)
                .expect("original waiter is held before parking");
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _owners = owners;
                std::panic::panic_any(73_u8);
            }));
            assert_eq!(unwound.unwrap_err().downcast_ref::<u8>(), Some(&73));
            assert_eq!(joined.load(Ordering::SeqCst), 1);
            assert_eq!(failed.load(Ordering::SeqCst), cleanup_panic);
        }
    }

    #[test]
    fn released_notification_cannot_pass_a_waiter_holding_the_predicate_mutex() {
        let block = block();
        let (arrived, at_wait) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        let (started, signal_started) = mpsc::channel();
        let (signalled, signal_published) = mpsc::channel();
        *block.inner.released_schedule.before_wait.lock().unwrap() = Some((arrived, resumed));
        *block.inner.released_schedule.signal_started.lock().unwrap() = Some(started);
        *block.inner.released_schedule.signalled.lock().unwrap() = Some(signalled);
        let mut owners = Owners::new(Arc::clone(&block), resume);
        let joined = Arc::clone(&owners.joined);
        let failed = Arc::clone(&owners.failed);
        let (done, completion) = mpsc::channel();
        let command = Arc::clone(&block);
        owners.threads.push(std::thread::spawn(move || {
            command.inner.enter_and_wait();
            let _ = done.send(());
        }));
        at_wait
            .recv_timeout(BOUND)
            .expect("command holds predicate mutex after checking false");
        let releaser = Arc::clone(&block);
        owners
            .threads
            .push(std::thread::spawn(move || releaser.release()));
        signal_started
            .recv_timeout(BOUND)
            .expect("real release started");
        let published_before_wait = signal_published
            .recv_timeout(Duration::from_secs(1))
            .is_ok();
        owners.resume();
        let completed = completion.recv_timeout(BOUND).is_ok();
        drop(owners);
        assert!(
            completed,
            "release notification lost; published_before_wait={published_before_wait}; original owners joined"
        );
        assert_eq!(joined.load(Ordering::SeqCst), 2);
        assert!(!failed.load(Ordering::SeqCst));
    }

    #[test]
    fn entered_notification_cannot_pass_a_waiter_holding_the_predicate_mutex() {
        let block = block();
        // Entry is the only wait under test in this slice.
        block.release();
        let (arrived, at_wait) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        let (started, signal_started) = mpsc::channel();
        let (signalled, signal_published) = mpsc::channel();
        *block.inner.entered_schedule.before_wait.lock().unwrap() = Some((arrived, resumed));
        *block.inner.entered_schedule.signal_started.lock().unwrap() = Some(started);
        *block.inner.entered_schedule.signalled.lock().unwrap() = Some(signalled);
        let mut owners = Owners::new(Arc::clone(&block), resume);
        let joined = Arc::clone(&owners.joined);
        let failed = Arc::clone(&owners.failed);
        let (done, completion) = mpsc::channel();
        let waiter = Arc::clone(&block);
        owners.threads.push(std::thread::spawn(move || {
            waiter.wait_entered();
            let _ = done.send(());
        }));
        at_wait
            .recv_timeout(BOUND)
            .expect("waiter holds predicate mutex after checking false");
        let producer = Arc::clone(&block);
        owners
            .threads
            .push(std::thread::spawn(move || producer.inner.enter_and_wait()));
        signal_started
            .recv_timeout(BOUND)
            .expect("real producer started");
        // The old producer publishes while the waiter still owns the mutex.
        // A repaired producer must wait for that mutex. This timeout selects
        // the schedule only; the saved completion below determines RED.
        let published_before_wait = signal_published
            .recv_timeout(Duration::from_secs(1))
            .is_ok();
        owners.resume();
        let completed = completion.recv_timeout(BOUND).is_ok();
        // On RED, the only original notification has already been lost.
        // A rescue notification retires the original waiter before asserting.
        drop(owners);
        assert!(
            completed,
            "entry notification lost; published_before_wait={published_before_wait}; original owners joined"
        );
        assert_eq!(joined.load(Ordering::SeqCst), 2);
        assert!(!failed.load(Ordering::SeqCst));
    }
}

#[cfg(test)]
mod storage_shutdown_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn context_snapshot_decoder_rejects_missing_session_and_inconsistent_markers() {
        let query =
            |rows: Value| json!({"columns":[], "rows":rows, "truncated":false, "next_cursor":null});
        let data = json!({"session":query(json!([["session", "", "", "", "", "", "", 1]])),
            "messages":query(json!([])), "summary_loaded":true, "latest":query(json!([]))});
        assert!(CompactionContextSnapshot::decode(data.clone()).is_ok());
        let mut malformed = Vec::new();
        let mut v = data.clone();
        v["session"]["authority"] = json!("unexpected");
        malformed.push(v);
        let mut v = data.clone();
        v["messages"].as_object_mut().unwrap().remove("columns");
        malformed.push(v);
        let mut v = data.clone();
        v["session"]["rows"] = json!([]);
        malformed.push(v);
        let mut v = data.clone();
        v["session"]["rows"] = json!([["session", "", "", "", "", "", "", "broken"]]);
        malformed.push(v);
        let mut v = data.clone();
        v["summary_loaded"] = json!(false);
        malformed.push(v);
        let mut v = data.clone();
        v["messages"]["rows"] = json!(vec![json!([]); 128]);
        malformed.push(v);
        let mut v = data.clone();
        v["messages"]["rows"] = json!(vec![json!([]); 129]);
        malformed.push(v);
        let mut v = data.clone();
        v["messages"]["rows"] = json!([{"cells":"invalid"}]);
        malformed.push(v);
        let mut v = data.clone();
        v["latest"]["truncated"] = json!(true);
        malformed.push(v);
        let mut v = data.clone();
        v["authority"] = json!("unexpected");
        malformed.push(v);
        let mut v = data.clone();
        v.as_object_mut().unwrap().remove("summary_loaded");
        malformed.push(v);
        for invalid in malformed {
            assert!(
                CompactionContextSnapshot::decode(invalid.clone()).is_err(),
                "must reject {invalid}"
            );
        }
    }

    #[test]
    fn concurrent_storage_shutdown_waits_for_the_owned_worker_join() {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let (sender, _requests) = mpsc::channel();
        let (shutdown, stop) = mpsc::channel();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let finished = Arc::new(AtomicBool::new(false));
        let finished_worker = Arc::clone(&finished);
        let thread = std::thread::spawn(move || {
            stop.recv().unwrap();
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            finished_worker.store(true, Ordering::Release);
        });
        let worker = Arc::new(StorageWorker {
            sender,
            shutdown,
            thread: std::sync::Mutex::new(Some(thread)),
            closed: AtomicBool::new(false),
            executed_commands: Arc::default(),
        });
        let first = {
            let worker = Arc::clone(&worker);
            std::thread::spawn(move || worker.shutdown())
        };
        let entered =
            entered_rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()));
        let (returned_tx, returned_rx) = mpsc::sync_channel(1);
        let second = {
            let worker = Arc::clone(&worker);
            let finished = Arc::clone(&finished);
            std::thread::spawn(move || {
                worker.shutdown();
                returned_tx.send(finished.load(Ordering::Acquire)).unwrap();
            })
        };
        // Preserve an early return observation before releasing the same owned
        // worker. Cleanup cannot turn this captured failure into a pass.
        let early = returned_rx.recv_timeout(Duration::from_millis(50));
        release_tx.send(()).unwrap();
        first.join().unwrap();
        second.join().unwrap();
        entered.expect("first shutdown reached the live owned worker");
        let joined = early.unwrap_or_else(|_| {
            returned_rx
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .unwrap()
        });
        assert!(
            joined,
            "concurrent shutdown returned before the owned worker joined"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "shared cleanup budget"
        );
        worker.shutdown();
    }
}

/// A sequential plain put must not be refused by a late sidecar release from
/// the previously settled put: the worker releases its reservation clone before
/// publishing that reply, so the next caller either observes the pending dirty
/// generation and sweeps it, or records its own last drop on return.
#[cfg(all(test, feature = "workspace-io-fault"))]
mod plugin_state_put_settle_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    const BOUND: Duration = Duration::from_secs(10);

    /// Owns this fixture's unique assigned-temp directory. Explicit cleanup at
    /// the normal end reports I/O errors; `Drop` is the unwind fallback and
    /// removes only this directory, without panicking or printing.
    struct OwnedTestRoot {
        path: std::path::PathBuf,
        removed: bool,
    }

    impl OwnedTestRoot {
        fn create() -> Self {
            let path = std::path::PathBuf::from(
                std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"),
            )
            .join(format!("state-put-settle-{}", Uuid::new_v4().simple()));
            std::fs::create_dir_all(&path).expect("state put settle temp root");
            Self {
                path,
                removed: false,
            }
        }

        fn sqlite_path(&self) -> std::path::PathBuf {
            self.path.join("state.sqlite")
        }

        fn cleanup(&mut self) -> std::io::Result<()> {
            match std::fs::remove_dir_all(&self.path) {
                Ok(()) => {
                    self.removed = true;
                    Ok(())
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.removed = true;
                    Ok(())
                }
                Err(error) => Err(error),
            }
        }
    }

    impl Drop for OwnedTestRoot {
        fn drop(&mut self) {
            if !self.removed {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    fn open_persistence(root: &OwnedTestRoot) -> Arc<GatewayPersistence> {
        let persistence = Arc::new(
            GatewayPersistence::open(&AgentGatewayConfig::default(), &root.sqlite_path())
                .expect("open the real storage worker"),
        );
        persistence.load().expect("load the storage schema");
        persistence
    }

    /// Bounded wait for the real worker to park at the settlement boundary.
    /// A miss is reported as a failed observation, never retried.
    fn wait_settled(guard: &PersistBlockGuard) {
        let deadline = Instant::now() + BOUND;
        let mut inner = guard
            .inner
            .mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while !guard.inner.entered.load(Ordering::SeqCst) {
            let now = Instant::now();
            assert!(
                now < deadline,
                "the storage worker never reached the put settlement boundary"
            );
            let (next, _) = guard
                .inner
                .entered_cvar
                .wait_timeout(inner, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner = next;
        }
    }

    /// Releases the parked worker on unwind so the persistence drop can join
    /// its thread. Cleanup never turns a captured failure into a pass.
    struct SettleGate(Arc<PersistBlockGuard>);

    impl Drop for SettleGate {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    #[test]
    fn plain_put_after_settled_put_must_not_be_refused_by_late_sidecar_release() {
        let mut root = OwnedTestRoot::create();
        let persistence = open_persistence(&root);
        let store = crate::plugins::PluginStateStore::open(Arc::clone(&persistence));
        let payload =
            crate::plugins::PluginStatePayload::parse(r#"{"settle":"plain"}"#).expect("payload");
        let package = "org.rustscript.test.state";
        let artifact = "artifact-state";

        let gate = SettleGate(Arc::new(persistence.block_state_owner_settle_for_test()));
        let first = store.put_object(package, artifact, 1, &payload);
        assert!(
            first.is_ok(),
            "the first plain put must be accepted: {:?}",
            first
                .as_ref()
                .err()
                .map(|error| (error.code, error.message.as_str()))
        );

        // The real worker released its reservation clone and then published
        // this put's reply, so the caller now observes the settled state: no
        // registry owner and the release's dirty generation recorded.
        wait_settled(&gate.0);
        let settled_len = store.candidate_registry_len_for_test();
        let (settled_dirty, settled_swept, settled_sealed) =
            store.candidate_dirty_generations_for_test();
        eprintln!(
            "put settle window: registry_len={settled_len} dirty={settled_dirty} \
             swept={settled_swept} sealed={settled_sealed}"
        );

        // The next sequential put's caller-side check sees the pending dirty
        // generation and takes the existing bounded collector arm, whose
        // enqueue releases the park; a candidate reservation would release it
        // instead if no generation were visible.
        let reservations = Arc::new(AtomicUsize::new(0));
        let release_on_reserve = Arc::clone(&gate.0);
        let count = Arc::clone(&reservations);
        persistence.observe_plugin_state_candidate_reservations(Arc::new(
            move |_object_id: &str| {
                count.fetch_add(1, Ordering::SeqCst);
                release_on_reserve.release();
            },
        ));
        let release_on_collect = Arc::clone(&gate.0);
        persistence.inject_plugin_state_collect_enqueue_observer(Arc::new(
            move |_report_health: bool| release_on_collect.release(),
        ));

        let second = store.put_object(package, artifact, 1, &payload);
        let refused = second
            .as_ref()
            .err()
            .map(|error| (error.code, error.message.clone()));
        assert!(
            second.is_ok(),
            "a sequential plain put issued after a settled plain put must not be \
             refused: error={refused:?} settle_window=(registry_len={settled_len}, \
             dirty={settled_dirty}, swept={settled_swept}) \
             reservations={}",
            reservations.load(Ordering::SeqCst)
        );
        assert_eq!(
            store.candidate_registry_len_for_test(),
            0,
            "both settled puts must leave no Native reservation owner"
        );
        // Settlement drops release the worker first, then this fixture's store,
        // persistence, and finally its own directory.
        drop(gate);
        drop(store);
        persistence.shutdown();
        drop(persistence);
        root.cleanup()
            .expect("remove the owned state put settle root");
    }
}
