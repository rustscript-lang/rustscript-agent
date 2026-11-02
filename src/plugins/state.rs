//! Bounded, versioned Native plugin state.
//!
//! Objects are immutable canonical JSON documents. A root is a revisioned
//! pointer owned by exactly one run or session. A run binding pins the exact
//! root revision it may read or advance, so a later session schema switch does
//! not move an older run onto new data. Storage commands are the existing
//! closed typed RSS worker; object persistence and the root/binding CAS are
//! separate transactions.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::GatewayPersistence;

pub const STATE_DOCUMENT_MAX_BYTES: usize = 64 * 1024;
const STATE_MAX_DEPTH: usize = 8;
const STATE_MAX_ENTRIES: usize = 256;
const STATE_MAX_ARRAY: usize = 128;
const STATE_MAX_KEY_BYTES: usize = 64;
const STATE_MAX_STRING_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginStateScope {
    Invocation,
    Run,
    Session,
}

impl PluginStateScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invocation => "invocation",
            Self::Run => "run",
            Self::Session => "session",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "invocation" => Some(Self::Invocation),
            "run" => Some(Self::Run),
            "session" => Some(Self::Session),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginStateError {
    pub code: &'static str,
    pub message: String,
}

impl PluginStateError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn storage(error: crate::gateway::store::StorageError) -> Self {
        let code = match error.code.as_str() {
            "plugin_state_object_conflict" => "plugin_state_object_conflict",
            "plugin_state_root_missing" => "plugin_state_root_missing",
            "plugin_state_conflict" => "plugin_state_conflict",
            "plugin_state_binding_invalid" => "plugin_state_binding_invalid",
            "plugin_state_binding_conflict" => "plugin_state_binding_conflict",
            "plugin_state_unavailable" => "plugin_state_unavailable",
            _ => "plugin_state_unavailable",
        };
        Self::new(code, error.message)
    }
}

impl std::fmt::Display for PluginStateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PluginStateError {}

/// Canonical, resource-free JSON document. Construction validates the bounds
/// and normalizes object key order; the public schema never exposes a raw map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginStatePayload {
    canonical_json: String,
}

impl PluginStatePayload {
    pub fn parse(input: &str) -> Result<Self, PluginStateError> {
        let value: Value = serde_json::from_str(input).map_err(|_| {
            PluginStateError::new(
                "plugin_state_invalid_document",
                "state document is not JSON",
            )
        })?;
        if !value.is_object() {
            return Err(PluginStateError::new(
                "plugin_state_invalid_document",
                "state document must be a JSON object",
            ));
        }
        let mut entries = 0usize;
        validate_value(&value, 0, &mut entries)?;
        let canonical_json = serde_json::to_string(&value).map_err(|_| {
            PluginStateError::new(
                "plugin_state_invalid_document",
                "state document is not encodable",
            )
        })?;
        if canonical_json.len() > STATE_DOCUMENT_MAX_BYTES {
            return Err(PluginStateError::new(
                "plugin_state_budget_exceeded",
                "state document exceeds the byte budget",
            ));
        }
        Ok(Self { canonical_json })
    }

    pub fn empty() -> Self {
        Self {
            canonical_json: "{}".into(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.canonical_json
    }

    pub fn byte_len(&self) -> usize {
        self.canonical_json.len()
    }

    pub fn to_json(&self) -> Value {
        serde_json::from_str(&self.canonical_json).expect("validated state document")
    }
}

fn validate_value(
    value: &Value,
    depth: usize,
    entries: &mut usize,
) -> Result<(), PluginStateError> {
    if depth > STATE_MAX_DEPTH {
        return Err(PluginStateError::new(
            "plugin_state_budget_exceeded",
            "state document depth exceeds the budget",
        ));
    }
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(number) => {
            if number.as_i64().is_none() {
                return Err(PluginStateError::new(
                    "plugin_state_invalid_document",
                    "state numbers must be signed integers",
                ));
            }
            Ok(())
        }
        Value::String(text) => {
            if text.len() > STATE_MAX_STRING_BYTES {
                return Err(PluginStateError::new(
                    "plugin_state_budget_exceeded",
                    "state string exceeds the budget",
                ));
            }
            Ok(())
        }
        Value::Array(items) => {
            if items.len() > STATE_MAX_ARRAY {
                return Err(PluginStateError::new(
                    "plugin_state_budget_exceeded",
                    "state array exceeds the budget",
                ));
            }
            for item in items {
                validate_value(item, depth + 1, entries)?;
            }
            Ok(())
        }
        Value::Object(fields) => {
            for (key, item) in fields {
                *entries += 1;
                if *entries > STATE_MAX_ENTRIES {
                    return Err(PluginStateError::new(
                        "plugin_state_budget_exceeded",
                        "state entries exceed the budget",
                    ));
                }
                if key.len() > STATE_MAX_KEY_BYTES {
                    return Err(PluginStateError::new(
                        "plugin_state_budget_exceeded",
                        "state key exceeds the budget",
                    ));
                }
                validate_value(item, depth + 1, entries)?;
            }
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginStateObject {
    pub object_id: String,
    pub package_id: String,
    pub artifact_id: String,
    pub schema: u32,
    pub payload: PluginStatePayload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginStateRoot {
    pub owner_kind: String,
    pub owner_id: String,
    pub workspace_id: String,
    pub branch_id: String,
    pub plugin_id: String,
    pub package_id: String,
    pub artifact_id: String,
    pub schema: u32,
    pub revision: u64,
    pub object_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginStateBinding {
    pub run_id: String,
    pub session_id: String,
    pub workspace_id: String,
    pub branch_id: String,
    pub plugin_id: String,
    pub package_id: String,
    pub artifact_id: String,
    pub owner_kind: String,
    pub owner_id: String,
    pub graph_id: String,
    pub epoch: u64,
    pub schema: u32,
    pub revision: u64,
    pub object_id: String,
    pub checkpoint_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginStateSnapshot {
    pub binding: PluginStateBinding,
    pub payload: PluginStatePayload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginStateRootKey {
    pub owner_kind: String,
    pub owner_id: String,
    pub workspace_id: String,
    pub branch_id: String,
    pub plugin_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginStateBindRequest {
    pub run_id: String,
    pub session_id: String,
    pub workspace_id: String,
    pub branch_id: String,
    pub plugin_id: String,
    pub package_id: String,
    pub artifact_id: String,
    pub scope: PluginStateScope,
    pub graph_id: String,
    pub epoch: u64,
    pub schema: u32,
    pub checkpoint_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginStateRestoreRequest {
    pub scope: PluginStateScope,
    pub run_id: String,
    pub session_id: String,
    pub workspace_id: String,
    pub branch_id: String,
    pub plugin_id: String,
    pub package_id: String,
    pub artifact_id: String,
    pub graph_id: String,
    pub epoch: u64,
    pub checkpoint_id: String,
    pub roots: Vec<PluginStateRootRef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginStateRootRef {
    pub owner_kind: String,
    pub owner_id: String,
    pub workspace_id: String,
    pub branch_id: String,
    pub plugin_id: String,
    pub package_id: String,
    pub artifact_id: String,
    pub schema: u32,
    pub revision: u64,
    pub object_id: String,
}

/// A compiled pure migration entry from one signed package. The program has no
/// host imports and receives only the old schema plus its bounded document.
#[derive(Clone)]
pub struct PluginStateMigrationProgram {
    program: Arc<rustscript_vm::Program>,
    entry: String,
    pub target_schema: u32,
}

impl std::fmt::Debug for PluginStateMigrationProgram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PluginStateMigrationProgram")
            .field("entry", &self.entry)
            .field("target_schema", &self.target_schema)
            .finish()
    }
}

impl PluginStateMigrationProgram {
    pub fn new(program: Arc<rustscript_vm::Program>, entry: String, target_schema: u32) -> Self {
        Self {
            program,
            entry,
            target_schema,
        }
    }

    pub fn evaluate(
        &self,
        from_schema: u32,
        payload: &PluginStatePayload,
        cancellation: &crate::RunCancellation,
    ) -> Result<PluginStatePayload, PluginStateError> {
        cancellation
            .ensure_open()
            .map_err(|error| PluginStateError::new("cancelled", error))?;
        if from_schema == 0 || from_schema >= self.target_schema {
            return Err(PluginStateError::new(
                "state_incompatible",
                "migration source schema is not older than the target",
            ));
        }
        let input = serde_json::json!({
            "from_schema": from_schema,
            "to_schema": self.target_schema,
            "document": payload.as_str(),
        });
        let value = crate::runtime::rss_runner::eval_captured_pure_export_with_input(
            Arc::clone(&self.program),
            &self.entry,
            input,
        )
        .map_err(|error| PluginStateError::new("plugin_state_migration_failed", error))?;
        cancellation
            .ensure_open()
            .map_err(|error| PluginStateError::new("cancelled", error))?;
        let decoded = crate::domain::vm_value_to_json(&value);
        let object = decoded.as_object().ok_or_else(|| {
            PluginStateError::new(
                "plugin_state_migration_failed",
                "migration result is not a map",
            )
        })?;
        let schema = object
            .get("schema")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                PluginStateError::new(
                    "plugin_state_migration_failed",
                    "migration result has no integer schema",
                )
            })?;
        if schema != self.target_schema {
            return Err(PluginStateError::new(
                "plugin_state_migration_failed",
                "migration returned the wrong schema",
            ));
        }
        let document = object
            .get("document")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PluginStateError::new(
                    "plugin_state_migration_failed",
                    "migration result has no string document",
                )
            })?;
        PluginStatePayload::parse(document)
            .map_err(|error| PluginStateError::new("plugin_state_migration_failed", error.message))
    }
}

/// Per-root writer fence. State commits enter a shared lease; a checkpoint
/// freezes the exact root it captures, waits for earlier writers outside the
/// global commit gate, and blocks later writers until its commit point.
#[derive(Default)]
pub(crate) struct PluginStateWriters {
    slots: Mutex<HashMap<String, Arc<PluginStateWriterSlot>>>,
}

#[derive(Default)]
struct PluginStateWriterSlot {
    state: Mutex<PluginStateWriterSlotState>,
    settled: Condvar,
}

#[derive(Default)]
struct PluginStateWriterSlotState {
    frozen: bool,
    active: usize,
}

pub(crate) struct PluginStateWriterLease {
    slot: Arc<PluginStateWriterSlot>,
}

impl Drop for PluginStateWriterLease {
    fn drop(&mut self) {
        let mut state = self
            .slot
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active = state.active.saturating_sub(1);
        self.slot.settled.notify_all();
    }
}

pub(crate) struct PluginStateWriterFreeze {
    slot: Arc<PluginStateWriterSlot>,
}

/// Fixture-only observer of Native reservation establishment. It fires after
/// the id is registered and before the durable write; it never mutates the
/// producer, the reservation, or any collector input.
#[cfg(any(test, feature = "workspace-io-fault"))]
pub(crate) type PluginStateReservationObserver = Arc<dyn Fn(&str) + Send + Sync>;

/// Native hard bounds for the unified reservation registry. These are explicit
/// Native capacity limits: they are independent of the admission
/// `max_concurrent_runs` setting (which only checks positivity) and of the
/// short-RPC pending permit, so reservations never consume either. A full
/// registry refuses new objects with a typed budget error while already-held
/// commit/abandon owners still settle.
pub(crate) const PLUGIN_STATE_MAX_RESERVATIONS: usize = 65_536;
pub(crate) const PLUGIN_STATE_MAX_RESERVATION_BYTES: usize = 8 * 1024 * 1024;

/// Collector health state. A fresh worker starts at `NeedsSweep`: it never
/// defaults to a `false` debt flag that pretends a sweep already happened. The
/// first related put proves one bounded sweep before the registry may report
/// `Healthy`; any collector error, timeout, or overbudget keeps `Debt` until an
/// explicit successful sweep recovers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CollectorHealthState {
    NeedsSweep,
    Healthy,
    Debt,
}

/// Worker-ordered collector health plus the collect execution epoch. Health is
/// written only by the storage worker at the command execution boundary in
/// FIFO order, never by callers from reply arrival order, so a delayed older
/// success can never clear a newer failure. The epoch moves forward on every
/// worker collect execution; a caller-side timeout marks debt only when the
/// worker recorded nothing newer since its request was sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CollectorHealth {
    state: CollectorHealthState,
    epoch: u64,
}

impl Default for CollectorHealth {
    fn default() -> Self {
        Self {
            state: CollectorHealthState::NeedsSweep,
            epoch: 0,
        }
    }
}

/// Unified in-process registry of Native reservations for every plugin state
/// object that has not reached a formal reference yet: guest staged objects,
/// migration candidates, trusted switch outputs, and the initial/maintenance
/// puts staged toward prepared/commit/abandon. Each entry is reference-counted:
/// the producer owner, every unsettled storage request sidecar, and each
/// staged/prepared holder own one count, and the id stays protected until the
/// last owner settles. Counts and bytes are hard-bounded (see
/// [`PLUGIN_STATE_MAX_RESERVATIONS`]); health is worker-ordered (see
/// [`CollectorHealth`]). Entries are opaque object identities only: the
/// registry never serializes VM state, guest resources, grants, or authority,
/// and reservations are never rebuilt from JSON or guest ids.
#[derive(Default)]
pub(crate) struct PluginStateCandidates {
    state: Mutex<PluginStateCandidateState>,
    #[cfg(any(test, feature = "workspace-io-fault"))]
    observer: Mutex<Option<PluginStateReservationObserver>>,
    /// Fixture-only observation of the collector injection budget inputs. It
    /// reports the already-computed (count, wire bytes, aggregate weight) and
    /// never changes the fail-closed decision.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    budget_observer: Mutex<Option<PluginStateCollectBudgetObserver>>,
}

/// Fixture-only reporter of the collector injection budget inputs.
#[cfg(any(test, feature = "workspace-io-fault"))]
pub(crate) type PluginStateCollectBudgetObserver = Arc<dyn Fn(usize, usize, usize) + Send + Sync>;

#[derive(Default)]
struct PluginStateCandidateState {
    owners: BTreeMap<String, usize>,
    bytes: usize,
    health: CollectorHealth,
    /// Monotonic count of last-owner releases (formal commit/abandon
    /// settlements) not yet covered by a successful sweep. Fixed-size; never
    /// a per-id table. An ordinary release only advances this counter and
    /// never writes health: it makes the registry dirty (sweep-pending), not
    /// failure Debt.
    dirty_generation: u64,
    /// Newest dirty generation covered by a successful worker sweep. A sweep
    /// only clears the generation it actually observed; releases that land
    /// while the sweep runs (or after) stay pending for the next sweep.
    swept_generation: u64,
    /// Fail-closed latch for counter overflow. While set, no sweep may report
    /// clean and every new put is refused; it can never wrap or saturate
    /// into a false clean claim.
    dirty_sealed: bool,
}

/// One strong Native reservation owner: a counted reference to a single
/// registry id. Cloning shares ownership (the count grows); dropping releases
/// exactly one count. Dropping never enqueues storage work, never waits on the
/// worker, and never synthesizes authority: it only releases this reference.
/// Storage requests carry a clone as an explicit sidecar so the id stays
/// protected until the worker settles that request, even after the caller has
/// released its own reference or timed out waiting for the reply.
pub(crate) struct PluginStateCandidateLease {
    candidates: Arc<PluginStateCandidates>,
    object_id: String,
}

impl Clone for PluginStateCandidateLease {
    fn clone(&self) -> Self {
        self.candidates.add_owner(&self.object_id);
        Self {
            candidates: Arc::clone(&self.candidates),
            object_id: self.object_id.clone(),
        }
    }
}

impl Drop for PluginStateCandidateLease {
    fn drop(&mut self) {
        // Release only this reference. Settlement-time reclamation is explicit
        // at the abandonment points (never on the worker thread, never while
        // a global gate is held).
        self.candidates.release(&self.object_id);
    }
}

impl PluginStateCandidates {
    fn add_owner(&self, object_id: &str) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = state.owners.get_mut(object_id) {
            *count = count.saturating_add(1);
        }
    }

    pub(crate) fn reserve(
        self: &Arc<Self>,
        object_id: &str,
    ) -> Result<PluginStateCandidateLease, PluginStateError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.owners.contains_key(object_id) {
            if state.owners.len() >= PLUGIN_STATE_MAX_RESERVATIONS
                || state.bytes.saturating_add(object_id.len()) > PLUGIN_STATE_MAX_RESERVATION_BYTES
            {
                return Err(PluginStateError::new(
                    "plugin_state_budget_exceeded",
                    "state reservation registry is full; new objects are refused",
                ));
            }
            state.bytes = state.bytes.saturating_add(object_id.len());
            state.owners.insert(object_id.to_string(), 1);
        } else {
            let count = state
                .owners
                .get_mut(object_id)
                .expect("reserved state object owner");
            *count = count.saturating_add(1);
        }
        drop(state);
        #[cfg(any(test, feature = "workspace-io-fault"))]
        if let Some(observer) = self
            .observer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        {
            observer(object_id);
        }
        Ok(PluginStateCandidateLease {
            candidates: Arc::clone(self),
            object_id: object_id.to_string(),
        })
    }

    fn release(&self, object_id: &str) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last = state
            .owners
            .get_mut(object_id)
            .map(|count| {
                *count = count.saturating_sub(1);
                *count == 0
            })
            .unwrap_or(true);
        if last && state.owners.remove(object_id).is_some() {
            state.bytes = state.bytes.saturating_sub(object_id.len());
            // The last Native owner settled (commit or abandon, durable or
            // not): record one bounded dirty generation for later
            // worker-ordered reclamation. Same-registry-lock update, Drop
            // context only: no RPC, no enqueue, no waiting, no global gate.
            // Health is untouched here; the registry simply becomes
            // sweep-pending, never failure Debt.
            match state.dirty_generation.checked_add(1) {
                Some(next) => state.dirty_generation = next,
                None => state.dirty_sealed = true,
            }
        }
    }

    /// Storage-worker only snapshot for one `plugin.state_collect`
    /// execution: the protection set plus the dirty generation it covers.
    /// Both are read under the same registry lock so a later successful
    /// sweep only clears the generation it actually observed; releases that
    /// land while the sweep runs stay pending.
    pub(crate) fn snapshot_for_collect(&self) -> (Vec<String>, u64) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            state.owners.keys().cloned().collect(),
            state.dirty_generation,
        )
    }

    /// Pure capacity peek for one id: true when registering a NEW id would
    /// exceed the Native count/byte bounds. Existing ids only add an owner
    /// and never hit the bounds. No mutation, no health effect: the caller
    /// reports the exact budget code without spending a sweep that a full
    /// registry would fail anyway.
    pub(crate) fn would_exceed_bounds(&self, object_id: &str) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        !state.owners.contains_key(object_id)
            && (state.owners.len() >= PLUGIN_STATE_MAX_RESERVATIONS
                || state.bytes.saturating_add(object_id.len()) > PLUGIN_STATE_MAX_RESERVATION_BYTES)
    }

    /// Single-lock admission view for the put path: current worker-ordered
    /// health plus whether a dirty generation still needs a bounded sweep.
    /// A sealed overflow reports Debt so every new put is refused fail-closed
    /// without ever claiming a sweep cleared it.
    pub(crate) fn admission_snapshot(&self) -> (CollectorHealthState, bool) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.dirty_sealed {
            return (CollectorHealthState::Debt, true);
        }
        (
            state.health.state,
            state.swept_generation != state.dirty_generation,
        )
    }

    pub(crate) fn health(&self) -> CollectorHealth {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .health
    }

    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub(crate) fn collection_debt(&self) -> bool {
        self.health().state == CollectorHealthState::Debt
    }

    /// Storage-worker only: record one `plugin.state_collect` execution that
    /// really succeeded (transport ok AND the typed envelope carries
    /// `ok: true`). The sweep covers exactly `snapshot_generation`; newer
    /// releases stay pending for the next sweep. Only an explicit sweep
    /// proves recovery and clears Debt/NeedsSweep; a quiet success advances
    /// the swept marker but never recovers health on its own. A sealed
    /// overflow keeps Debt fail-closed and never reports clean.
    pub(crate) fn record_collect_success(&self, snapshot_generation: u64, report_health: bool) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.health.epoch = state.health.epoch.saturating_add(1);
        if state.dirty_sealed {
            state.health.state = CollectorHealthState::Debt;
            return;
        }
        if snapshot_generation > state.swept_generation {
            state.swept_generation = snapshot_generation;
        }
        if report_health {
            state.health.state = CollectorHealthState::Healthy;
        }
    }

    /// Storage-worker only: record one `plugin.state_collect` execution that
    /// failed for any reason (transport/IO/runner error, typed `ok: false`,
    /// Native overbudget, unencodable protection set). Called in worker
    /// execution order for explicit AND quiet sweeps alike, so a real quiet
    /// failure always keeps Debt even when its caller already moved on.
    pub(crate) fn record_collect_failure(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.health.epoch = state.health.epoch.saturating_add(1);
        state.health.state = CollectorHealthState::Debt;
    }

    /// Caller-side collect with an unknown outcome (reply timeout or transport
    /// loss): fail-safe debt, but only when the worker recorded no newer
    /// execution since this request was sent. A late worker success is never
    /// shadowed by a stale caller timeout.
    pub(crate) fn note_collect_outcome_unknown(&self, since_epoch: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.health.epoch == since_epoch {
            state.health.state = CollectorHealthState::Debt;
        }
    }

    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub(crate) fn set_observer(&self, observer: PluginStateReservationObserver) {
        *self
            .observer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(observer);
    }

    /// Fixture-only observation of the collector budget inputs. Read-only: the
    /// values are already computed by the worker and the decision is unchanged.
    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub(crate) fn set_budget_observer(&self, observer: PluginStateCollectBudgetObserver) {
        *self
            .budget_observer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(observer);
    }

    #[cfg(any(test, feature = "workspace-io-fault"))]
    pub(crate) fn report_collect_budget_inputs(&self, count: usize, wire: usize, aggregate: usize) {
        if let Some(observer) = self
            .budget_observer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        {
            observer(count, wire, aggregate);
        }
    }

    #[cfg(feature = "workspace-io-fault")]
    pub(crate) fn len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .owners
            .len()
    }

    /// Fixture-only holder of a real Native reservation. It adds no durable
    /// object and grants no authority; it only keeps an id protected until the
    /// returned lease is dropped. It releases exactly its own reference, like
    /// every production owner.
    #[cfg(feature = "workspace-io-fault")]
    pub(crate) fn reserve_for_test(self: &Arc<Self>, object_id: &str) -> PluginStateCandidateLease {
        self.reserve(object_id)
            .expect("test reservation fits the Native registry bounds")
    }
}

impl Drop for PluginStateWriterFreeze {
    fn drop(&mut self) {
        let mut state = self
            .slot
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.frozen = false;
        self.slot.settled.notify_all();
    }
}

impl PluginStateWriters {
    fn slot(&self, key: &str) -> Arc<PluginStateWriterSlot> {
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(slots.entry(key.to_string()).or_default())
    }

    fn enter(
        &self,
        key: &str,
        deadline: Instant,
        cancelled: impl Fn() -> bool,
    ) -> Result<PluginStateWriterLease, PluginStateError> {
        let slot = self.slot(key);
        let mut state = slot
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while state.frozen {
            if cancelled() {
                return Err(PluginStateError::new(
                    "cancelled",
                    "state writer was cancelled before publication",
                ));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(PluginStateError::new(
                    "plugin_state_busy",
                    "state root is frozen by a checkpoint",
                ));
            }
            let wait = deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(50));
            let (next, _) = slot
                .settled
                .wait_timeout(state, wait)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
        }
        state.active += 1;
        drop(state);
        Ok(PluginStateWriterLease { slot })
    }

    fn freeze(
        &self,
        key: &str,
        deadline: Instant,
        cancelled: impl Fn() -> bool,
    ) -> Result<PluginStateWriterFreeze, PluginStateError> {
        let slot = self.slot(key);
        let mut state = slot
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while state.active > 0 {
            if cancelled() {
                return Err(PluginStateError::new(
                    "cancelled",
                    "checkpoint cancelled while waiting for state writers",
                ));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(PluginStateError::new(
                    "plugin_state_busy",
                    "state writer did not settle before the checkpoint deadline",
                ));
            }
            let wait = deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(50));
            let (next, _) = slot
                .settled
                .wait_timeout(state, wait)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
        }
        state.frozen = true;
        drop(state);
        Ok(PluginStateWriterFreeze { slot })
    }
}

pub(crate) fn plugin_state_writer_key(binding: &PluginStateBinding) -> PluginStateRootKey {
    PluginStateRootKey {
        owner_kind: binding.owner_kind.clone(),
        owner_id: binding.owner_id.clone(),
        workspace_id: binding.workspace_id.clone(),
        branch_id: binding.branch_id.clone(),
        plugin_id: binding.plugin_id.clone(),
    }
}

fn writer_key_id(key: &PluginStateRootKey) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
        key.owner_kind, key.owner_id, key.workspace_id, key.branch_id, key.plugin_id
    )
}

pub struct PluginStateStore {
    persistence: Arc<GatewayPersistence>,
}

#[cfg(feature = "workspace-io-fault")]
pub struct PluginStateWriterHold {
    _lease: PluginStateWriterLease,
}

impl Clone for PluginStateStore {
    fn clone(&self) -> Self {
        Self {
            persistence: Arc::clone(&self.persistence),
        }
    }
}

impl PluginStateStore {
    pub fn open(persistence: Arc<GatewayPersistence>) -> Self {
        Self { persistence }
    }

    fn command(&self, op: &str, payload: Value) -> Result<Value, PluginStateError> {
        self.command_with_owner(op, payload, None)
    }

    fn command_with_owner(
        &self,
        op: &str,
        payload: Value,
        owner: Option<PluginStateCandidateLease>,
    ) -> Result<Value, PluginStateError> {
        self.persistence
            .plugin_control_command_with_owner(op, &payload, owner)
            .map_err(PluginStateError::storage)
    }

    pub fn put_object(
        &self,
        package_id: &str,
        artifact_id: &str,
        schema: u32,
        payload: &PluginStatePayload,
    ) -> Result<PluginStateObject, PluginStateError> {
        // The immediate owner is released on return; the request sidecar keeps
        // the id protected until the worker settles the put. Callers that need
        // protection past settle (staged, prepared, migration, switch) use
        // `put_object_reserved` and hold the returned owner across commit or
        // abandonment instead.
        let (object, _immediate) =
            self.put_object_reserved(package_id, artifact_id, schema, payload)?;
        Ok(object)
    }

    /// Writes one durable object through the unified Native reservation
    /// lifecycle: health is proven first, the reservation is registered before
    /// the durable write, and the returned owner keeps the id protected until
    /// the caller settles (commit) or abandons it. The full reservation owner
    /// (id, registry membership, request sidecar) is established before the
    /// durable write, so a put whose reply was lost still has a bounded
    /// settlement path instead of leaking an unprotected object.
    pub(crate) fn put_object_reserved(
        &self,
        package_id: &str,
        artifact_id: &str,
        schema: u32,
        payload: &PluginStatePayload,
    ) -> Result<(PluginStateObject, PluginStateCandidateLease), PluginStateError> {
        let object_id = uuid::Uuid::new_v4().to_string();
        self.put_object_reserved_with_id(&object_id, package_id, artifact_id, schema, payload)
    }

    pub(crate) fn put_object_reserved_with_id(
        &self,
        object_id: &str,
        package_id: &str,
        artifact_id: &str,
        schema: u32,
        payload: &PluginStatePayload,
    ) -> Result<(PluginStateObject, PluginStateCandidateLease), PluginStateError> {
        if schema == 0 || schema > 64 {
            return Err(PluginStateError::new(
                "plugin_state_invalid_schema",
                "state schema is outside the accepted range",
            ));
        }
        // Refuse new objects while the existing bounded collector cannot prove
        // a sweep. A fresh worker proves one sweep first; debt refuses until
        // an explicit successful sweep recovers.
        //
        // The Native registry bound is checked first as a pure peek: a full
        // registry reports its exact budget code without spending a sweep
        // (whose injected protection set would exceed the same budget while
        // full and mask the precise capacity reason with Debt).
        if self
            .persistence
            .plugin_state_candidates
            .would_exceed_bounds(object_id)
        {
            return Err(PluginStateError::new(
                "plugin_state_budget_exceeded",
                "state reservation registry is full; new objects are refused",
            ));
        }
        self.ensure_object_capacity()?;
        let reservation = self
            .persistence
            .plugin_state_candidates
            .reserve(object_id)?;
        let object = match self.put_object_with_owner_id(
            object_id,
            package_id,
            artifact_id,
            schema,
            payload,
            Some(reservation.clone()),
        ) {
            Ok(object) => object,
            Err(error) => {
                // The put may have become durable even when its reply was lost.
                // Release this producer's owner, then enqueue the same bounded
                // worker-ordered reclamation from this caller thread so the
                // abandoned object cannot accumulate across unknown puts. The
                // request sidecar in the storage worker kept it protected until
                // the request settled; this sweep runs after that settle.
                drop(reservation);
                let _ = self.collect_orphans_quiet();
                return Err(error);
            }
        };
        Ok((object, reservation))
    }

    fn ensure_object_capacity(&self) -> Result<(), PluginStateError> {
        // The caller check is only early refusal, never an execution permit:
        // the worker re-applies the same decision at its own put boundary.
        // Debt refuses with typed backpressure (one bounded quiet sweep still
        // runs so refused traffic cannot grow the disk, but it never clears
        // Debt itself). A fresh worker or any pending dirty generation proves
        // one bounded explicit sweep before the put is enqueued.
        let (health_state, pending) = self
            .persistence
            .plugin_state_candidates
            .admission_snapshot();
        match health_state {
            CollectorHealthState::Debt => {
                // Typed backpressure: refuse the new object. One bounded
                // worker-ordered reclamation still runs so refused traffic
                // cannot grow the disk while degraded; that sweep never clears
                // debt itself. Only an explicit successful collector recovers.
                let _ = self.collect_orphans_quiet();
                Err(PluginStateError::new(
                    "plugin_state_unavailable",
                    "state collection is degraded; new objects are refused",
                ))
            }
            CollectorHealthState::Healthy if !pending => Ok(()),
            _ => {
                // A fresh worker never defaults to swept: the first related
                // put proves one bounded sweep before going Healthy, and any
                // pending dirty generation is reclaimed first. Any error,
                // timeout, or overbudget keeps Debt and refuses.
                self.collect_orphans().map_err(|_| {
                    PluginStateError::new(
                        "plugin_state_unavailable",
                        "state collection is not proven; new objects are refused",
                    )
                })
            }
        }
    }

    /// Builds one candidate through the real typed producer. The attempted id
    /// is returned even when the write is refused, so a caller can prove that a
    /// backpressured attempt never became durable.
    #[cfg(feature = "workspace-io-fault")]
    pub fn candidate_put_for_test(
        &self,
        package_id: &str,
        artifact_id: &str,
        schema: u32,
        payload: &PluginStatePayload,
    ) -> (String, Result<PluginStateObject, PluginStateError>) {
        let object_id = uuid::Uuid::new_v4().to_string();
        let result = self
            .put_object_reserved_with_id(&object_id, package_id, artifact_id, schema, payload)
            .map(|(object, lease)| {
                drop(lease);
                object
            });
        (object_id, result)
    }

    #[cfg(feature = "workspace-io-fault")]
    pub fn candidate_registry_len_for_test(&self) -> usize {
        self.persistence.plugin_state_candidates.len()
    }

    /// Holds one real candidate reservation until the returned lease drops.
    /// The id need not be a durable object; the collector's protected set is
    /// the same Native registry used by the production producer.
    #[cfg(feature = "workspace-io-fault")]
    pub fn hold_candidate_reservation_for_test(&self, object_id: &str) -> impl Drop + use<> {
        self.persistence
            .plugin_state_candidates
            .reserve_for_test(object_id)
    }

    #[cfg(feature = "workspace-io-fault")]
    pub fn collection_debt_for_test(&self) -> bool {
        self.persistence.plugin_state_candidates.collection_debt()
    }

    /// Fixture-only view of the bounded dirty bookkeeping: (dirty
    /// generation, swept generation, sealed-overflow latch). A test asserts
    /// progress as `swept` covering the `dirty` observed at abandon time;
    /// per-id tables are never exposed.
    #[cfg(feature = "workspace-io-fault")]
    pub fn candidate_dirty_generations_for_test(&self) -> (u64, u64, bool) {
        let state = self
            .persistence
            .plugin_state_candidates
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            state.dirty_generation,
            state.swept_generation,
            state.dirty_sealed,
        )
    }

    fn put_object_with_owner_id(
        &self,
        object_id: &str,
        package_id: &str,
        artifact_id: &str,
        schema: u32,
        payload: &PluginStatePayload,
        owner: Option<PluginStateCandidateLease>,
    ) -> Result<PluginStateObject, PluginStateError> {
        let data = self.command_with_owner(
            "plugin.state_object_put",
            serde_json::json!({
                "object_id": object_id,
                "package_id": package_id,
                "artifact_id": artifact_id,
                "schema_version": schema,
                "document_json": payload.as_str(),
                "document_bytes": payload.byte_len(),
                "now_ms": now_ms(),
            }),
            owner,
        )?;
        if data.get("object_id").and_then(Value::as_str) != Some(object_id) {
            return Err(PluginStateError::new(
                "plugin_state_object_missing",
                "stored state object identity did not match",
            ));
        }
        #[cfg(feature = "workspace-io-fault")]
        if let Some(observer) = self.persistence.plugin_state_object_put_observer_hook() {
            observer(object_id);
        }
        Ok(PluginStateObject {
            object_id: object_id.to_string(),
            package_id: package_id.to_string(),
            artifact_id: artifact_id.to_string(),
            schema,
            payload: payload.clone(),
        })
    }

    pub fn object_payload(&self, object_id: &str) -> Result<PluginStatePayload, PluginStateError> {
        let data = self.command(
            "plugin.state_object_get",
            serde_json::json!({"object_id": object_id}),
        )?;
        let rows = crate::sqlite_storage_rows::sqlite_storage_rows(&data).map_err(|_| {
            PluginStateError::new("plugin_state_unavailable", "state object row is invalid")
        })?;
        let row = rows.first().ok_or_else(|| {
            PluginStateError::new("plugin_state_object_missing", "state object is missing")
        })?;
        let document = text_at(row, 2)?;
        PluginStatePayload::parse(&document)
    }

    pub fn root(
        &self,
        key: &PluginStateRootKey,
    ) -> Result<Option<PluginStateRoot>, PluginStateError> {
        let data = self.command(
            "plugin.state_root_get",
            serde_json::json!({
                "owner_kind": key.owner_kind,
                "owner_id": key.owner_id,
                "workspace_id": key.workspace_id,
                "branch_id": key.branch_id,
                "plugin_id": key.plugin_id,
            }),
        )?;
        let rows = crate::sqlite_storage_rows::sqlite_storage_rows(&data).map_err(|_| {
            PluginStateError::new("plugin_state_unavailable", "state root row is invalid")
        })?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        Ok(Some(root_from_row(row)?))
    }

    pub fn cas_root(
        &self,
        key: &PluginStateRootKey,
        expected_revision: u64,
        object: &PluginStateObject,
    ) -> Result<PluginStateRoot, PluginStateError> {
        self.cas_root_with_owner(key, expected_revision, object, None)
    }

    pub(crate) fn cas_root_with_owner(
        &self,
        key: &PluginStateRootKey,
        expected_revision: u64,
        object: &PluginStateObject,
        owner: Option<PluginStateCandidateLease>,
    ) -> Result<PluginStateRoot, PluginStateError> {
        let data = self.command_with_owner(
            "plugin.state_root_put",
            serde_json::json!({
                "owner_kind": key.owner_kind,
                "owner_id": key.owner_id,
                "workspace_id": key.workspace_id,
                "branch_id": key.branch_id,
                "plugin_id": key.plugin_id,
                "package_id": object.package_id,
                "artifact_id": object.artifact_id,
                "schema_version": object.schema,
                "expected_revision": expected_revision,
                "object_id": object.object_id,
                "now_ms": now_ms(),
            }),
            owner,
        )?;
        let revision = data
            .get("revision")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                PluginStateError::new("plugin_state_unavailable", "state CAS returned no revision")
            })?;
        Ok(PluginStateRoot {
            owner_kind: key.owner_kind.clone(),
            owner_id: key.owner_id.clone(),
            workspace_id: key.workspace_id.clone(),
            branch_id: key.branch_id.clone(),
            plugin_id: key.plugin_id.clone(),
            package_id: object.package_id.clone(),
            artifact_id: object.artifact_id.clone(),
            schema: object.schema,
            revision,
            object_id: object.object_id.clone(),
        })
    }

    fn ensure_root(
        &self,
        key: &PluginStateRootKey,
        request: &PluginStateBindRequest,
    ) -> Result<PluginStateRoot, PluginStateError> {
        if let Some(root) = self.root(key)? {
            if root.schema != request.schema {
                return Err(PluginStateError::new(
                    "state_incompatible",
                    "existing state schema differs from the admitted graph schema",
                ));
            }
            return Ok(root);
        }
        let payload = PluginStatePayload::empty();
        let (object, owner) = self.put_object_reserved(
            &request.package_id,
            &request.artifact_id,
            request.schema,
            &payload,
        )?;
        match self.cas_root_with_owner(key, 0, &object, Some(owner)) {
            Ok(root) => Ok(root),
            Err(error) if error.code == "plugin_state_conflict" => {
                let root = self.root(key)?.ok_or(error)?;
                if root.schema != request.schema {
                    return Err(PluginStateError::new(
                        "state_incompatible",
                        "concurrent state root schema differs from the admitted graph schema",
                    ));
                }
                Ok(root)
            }
            Err(error) => Err(error),
        }
    }

    pub fn binding(&self, run_id: &str) -> Result<Option<PluginStateSnapshot>, PluginStateError> {
        let data = self.command(
            "plugin.state_binding_get",
            serde_json::json!({ "run_id": run_id }),
        )?;
        let rows = crate::sqlite_storage_rows::sqlite_storage_rows(&data).map_err(|_| {
            PluginStateError::new("plugin_state_unavailable", "state binding row is invalid")
        })?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        snapshot_from_row(row)
    }

    pub fn bind_run(
        &self,
        request: &PluginStateBindRequest,
    ) -> Result<PluginStateSnapshot, PluginStateError> {
        if let Some(existing) = self.binding(&request.run_id)? {
            validate_binding(&existing.binding, request)?;
            return Ok(existing);
        }
        let owner_id = match request.scope {
            PluginStateScope::Run => request.run_id.clone(),
            PluginStateScope::Session => request.session_id.clone(),
            PluginStateScope::Invocation => {
                return Err(PluginStateError::new(
                    "plugin_state_invalid",
                    "invocation state has no durable run binding",
                ));
            }
        };
        let key = PluginStateRootKey {
            owner_kind: request.scope.as_str().to_string(),
            owner_id: owner_id.clone(),
            workspace_id: request.workspace_id.clone(),
            branch_id: request.branch_id.clone(),
            plugin_id: request.plugin_id.clone(),
        };
        let root = self.ensure_root(&key, request)?;
        let data = self.command(
            "plugin.state_bind_run",
            serde_json::json!({
                "run_id": request.run_id,
                "session_id": request.session_id,
                "workspace_id": request.workspace_id,
                "branch_id": request.branch_id,
                "plugin_id": request.plugin_id,
                "package_id": root.package_id,
                "artifact_id": root.artifact_id,
                "owner_kind": request.scope.as_str(),
                "owner_id": owner_id,
                "graph_id": request.graph_id,
                "epoch": request.epoch,
                "schema_version": root.schema,
                "revision": root.revision,
                "object_id": root.object_id,
                "checkpoint_id": request.checkpoint_id,
                "now_ms": now_ms(),
            }),
        )?;
        if data.get("run_id").and_then(Value::as_str) != Some(request.run_id.as_str()) {
            return Err(PluginStateError::new(
                "plugin_state_binding_invalid",
                "run state binding did not persist",
            ));
        }
        self.binding(&request.run_id)?.ok_or_else(|| {
            PluginStateError::new(
                "plugin_state_binding_missing",
                "run state binding is missing",
            )
        })
    }

    pub fn commit(
        &self,
        snapshot: &PluginStateSnapshot,
        payload: &PluginStatePayload,
    ) -> Result<PluginStateSnapshot, PluginStateError> {
        let deadline = Instant::now() + Duration::from_secs(30);
        self.commit_with_deadline(snapshot, payload, deadline, None)
    }

    pub fn commit_with_cancellation(
        &self,
        snapshot: &PluginStateSnapshot,
        payload: &PluginStatePayload,
        cancellation: &crate::RunCancellation,
    ) -> Result<PluginStateSnapshot, PluginStateError> {
        let deadline = cancellation
            .deadline_instant()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(30));
        self.commit_with_deadline(snapshot, payload, deadline, Some(cancellation))
    }

    fn commit_with_deadline(
        &self,
        snapshot: &PluginStateSnapshot,
        payload: &PluginStatePayload,
        deadline: Instant,
        cancellation: Option<&crate::RunCancellation>,
    ) -> Result<PluginStateSnapshot, PluginStateError> {
        let binding = &snapshot.binding;
        let key = plugin_state_writer_key(binding);
        let _writer = self.persistence.plugin_state_writers().enter(
            &writer_key_id(&key),
            deadline,
            || cancellation.is_some_and(|cancel| cancel.requested().is_some()),
        )?;
        let (object, owner) = self.put_object_reserved(
            &binding.package_id,
            &binding.artifact_id,
            binding.schema,
            payload,
        )?;
        let data = match self.command_with_owner(
            "plugin.state_commit",
            serde_json::json!({
                "run_id": binding.run_id,
                "owner_kind": binding.owner_kind,
                "owner_id": binding.owner_id,
                "workspace_id": binding.workspace_id,
                "branch_id": binding.branch_id,
                "plugin_id": binding.plugin_id,
                "package_id": binding.package_id,
                "artifact_id": binding.artifact_id,
                "expected_revision": binding.revision,
                "expected_object_id": binding.object_id,
                "schema_version": object.schema,
                "object_id": object.object_id,
                "now_ms": now_ms(),
            }),
            Some(owner),
        ) {
            Ok(data) => data,
            Err(error) => {
                let _ = self.collect_orphans();
                return Err(error);
            }
        };
        let _ = self.collect_orphans();
        let revision = data
            .get("revision")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                PluginStateError::new("plugin_state_conflict", "state commit returned no revision")
            })?;
        let mut binding = binding.clone();
        binding.revision = revision;
        binding.object_id = object.object_id;
        binding.schema = object.schema;
        Ok(PluginStateSnapshot {
            binding,
            payload: payload.clone(),
        })
    }

    pub(crate) fn acquire_writer_key(
        &self,
        key: &PluginStateRootKey,
        cancellation: &crate::RunCancellation,
    ) -> Result<PluginStateWriterLease, PluginStateError> {
        let deadline = cancellation
            .deadline_instant()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(30));
        self.persistence
            .plugin_state_writers()
            .enter(&writer_key_id(key), deadline, || {
                cancellation.requested().is_some()
            })
    }

    pub(crate) fn freeze_writer(
        &self,
        binding: &PluginStateBinding,
        cancellation: &crate::RunCancellation,
    ) -> Result<PluginStateWriterFreeze, PluginStateError> {
        let deadline = cancellation
            .deadline_instant()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(30));
        let key = plugin_state_writer_key(binding);
        self.persistence
            .plugin_state_writers()
            .freeze(&writer_key_id(&key), deadline, || {
                cancellation.requested().is_some()
            })
    }

    #[cfg(feature = "workspace-io-fault")]
    pub fn hold_writer_for_test(
        &self,
        binding: &PluginStateBinding,
        cancellation: &crate::RunCancellation,
    ) -> Result<PluginStateWriterHold, PluginStateError> {
        let deadline = cancellation
            .deadline_instant()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(30));
        let key = plugin_state_writer_key(binding);
        let lease = self.persistence.plugin_state_writers().enter(
            &writer_key_id(&key),
            deadline,
            || cancellation.requested().is_some(),
        )?;
        Ok(PluginStateWriterHold { _lease: lease })
    }

    pub fn migrate_root(
        &self,
        key: &PluginStateRootKey,
        expected_revision: u64,
        object: &PluginStateObject,
    ) -> Result<PluginStateRoot, PluginStateError> {
        self.migrate_root_with_owner(key, expected_revision, object, None)
    }

    pub(crate) fn migrate_root_with_owner(
        &self,
        key: &PluginStateRootKey,
        expected_revision: u64,
        object: &PluginStateObject,
        owner: Option<PluginStateCandidateLease>,
    ) -> Result<PluginStateRoot, PluginStateError> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let _writer =
            self.persistence
                .plugin_state_writers()
                .enter(&writer_key_id(key), deadline, || false)?;
        self.cas_root_with_owner(key, expected_revision, object, owner)
    }

    pub fn checkpoint_roots(
        &self,
        run_id: &str,
    ) -> Result<Vec<PluginStateRootRef>, PluginStateError> {
        let data = self.command(
            "plugin.state_roots_for_checkpoint",
            serde_json::json!({ "run_id": run_id }),
        )?;
        let rows = crate::sqlite_storage_rows::sqlite_storage_rows(&data).map_err(|_| {
            PluginStateError::new("plugin_state_unavailable", "state root rows are invalid")
        })?;
        rows.iter().map(|row| root_ref_from_row(row)).collect()
    }

    pub fn restore_binding(
        &self,
        request: &PluginStateRestoreRequest,
    ) -> Result<PluginStateSnapshot, PluginStateError> {
        let selected = select_restore_root(request)?;
        let selected = selected.clone();
        let owner_id = match request.scope {
            PluginStateScope::Run => request.run_id.clone(),
            PluginStateScope::Session => request.session_id.clone(),
            PluginStateScope::Invocation => {
                return Err(PluginStateError::new(
                    "plugin_state_invalid",
                    "invocation state has no durable restore root",
                ));
            }
        };
        if selected.owner_kind != request.scope.as_str() {
            return Err(PluginStateError::new(
                "plugin_state_root_mismatch",
                "checkpoint state root owner kind does not match the restored graph",
            ));
        }
        let key = PluginStateRootKey {
            owner_kind: request.scope.as_str().to_string(),
            owner_id: owner_id.clone(),
            workspace_id: request.workspace_id.clone(),
            branch_id: request.branch_id.clone(),
            plugin_id: request.plugin_id.clone(),
        };
        let object = PluginStateObject {
            object_id: selected.object_id.clone(),
            package_id: selected.package_id.clone(),
            artifact_id: selected.artifact_id.clone(),
            schema: selected.schema,
            payload: PluginStatePayload::empty(),
        };
        let root = match self.root(&key)? {
            Some(root) => {
                if root.schema != selected.schema
                    || root.object_id != selected.object_id
                    || root.package_id != selected.package_id
                    || root.artifact_id != selected.artifact_id
                {
                    return Err(PluginStateError::new(
                        "plugin_state_root_mismatch",
                        "restored branch already has different state root",
                    ));
                }
                root
            }
            None => self.cas_root(&key, 0, &object)?,
        };
        let snapshot = self.bind_run(&PluginStateBindRequest {
            run_id: request.run_id.clone(),
            session_id: request.session_id.clone(),
            workspace_id: request.workspace_id.clone(),
            branch_id: request.branch_id.clone(),
            plugin_id: request.plugin_id.clone(),
            package_id: request.package_id.clone(),
            artifact_id: request.artifact_id.clone(),
            scope: request.scope,
            graph_id: request.graph_id.clone(),
            epoch: request.epoch,
            schema: selected.schema,
            checkpoint_id: request.checkpoint_id.clone(),
        })?;
        if snapshot.binding.revision != root.revision
            || snapshot.binding.object_id != root.object_id
        {
            return Err(PluginStateError::new(
                "plugin_state_root_mismatch",
                "restored run binding does not reference the restored root",
            ));
        }
        Ok(snapshot)
    }

    pub fn authorize(
        &self,
        binding: &PluginStateBinding,
        profile: &str,
        graph_id: &str,
        now_ms: u64,
    ) -> Result<(), PluginStateError> {
        let data = self.command(
            "plugin.state_authorize",
            serde_json::json!({
                "run_id": binding.run_id,
                "session_id": binding.session_id,
                "profile": profile,
                "plugin_id": binding.plugin_id,
                "package_id": binding.package_id,
                "artifact_id": binding.artifact_id,
                "owner_kind": binding.owner_kind,
                "owner_id": binding.owner_id,
                "graph_id": graph_id,
                "workspace_id": binding.workspace_id,
                "branch_id": binding.branch_id,
                "epoch": binding.epoch,
                "now_ms": now_ms,
            }),
        )?;
        let rows = crate::sqlite_storage_rows::sqlite_storage_rows(&data).map_err(|_| {
            PluginStateError::new(
                "plugin_state_unavailable",
                "state authorization row is invalid",
            )
        })?;
        let status = rows
            .first()
            .and_then(|row| row.first())
            .and_then(Value::as_str)
            .unwrap_or("");
        if status == "ok" {
            Ok(())
        } else {
            Err(PluginStateError::new(
                "plugin_state_unauthorized",
                if status.is_empty() {
                    "state authorization denied".to_string()
                } else {
                    status.to_string()
                },
            ))
        }
    }

    pub fn session_root_key(
        &self,
        session_id: &str,
        plugin_id: &str,
    ) -> Result<Option<PluginStateRootKey>, PluginStateError> {
        let data = self.command(
            "plugin.state_session_key",
            serde_json::json!({"session_id": session_id, "plugin_id": plugin_id}),
        )?;
        let rows = crate::sqlite_storage_rows::sqlite_storage_rows(&data).map_err(|_| {
            PluginStateError::new(
                "plugin_state_unavailable",
                "session state key row is invalid",
            )
        })?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        Ok(Some(PluginStateRootKey {
            owner_kind: "session".into(),
            owner_id: session_id.into(),
            workspace_id: text_at(row, 0)?,
            branch_id: text_at(row, 1)?,
            plugin_id: text_at(row, 2)?,
        }))
    }

    pub fn session_root_key_for(
        &self,
        session_id: &str,
        plugin_id: &str,
        workspace_id: &str,
        branch_id: &str,
    ) -> Result<Option<PluginStateRootKey>, PluginStateError> {
        let data = self.command(
            "plugin.state_session_key_for",
            serde_json::json!({
                "session_id": session_id,
                "plugin_id": plugin_id,
                "workspace_id": workspace_id,
                "branch_id": branch_id,
            }),
        )?;
        let rows = crate::sqlite_storage_rows::sqlite_storage_rows(&data).map_err(|_| {
            PluginStateError::new(
                "plugin_state_unavailable",
                "session state key row is invalid",
            )
        })?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        Ok(Some(PluginStateRootKey {
            owner_kind: "session".into(),
            owner_id: session_id.into(),
            workspace_id: text_at(row, 0)?,
            branch_id: text_at(row, 1)?,
            plugin_id: text_at(row, 2)?,
        }))
    }

    pub fn managed_run_identity(&self, run_id: &str) -> Option<(String, String, u64)> {
        let cancellation = crate::RunCancellation::with_deadline(
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        );
        self.persistence
            .managed_run_query_binding(run_id, &cancellation)
            .ok()
            .flatten()
            .map(|binding| {
                (
                    binding.workspace.workspace_id,
                    binding.workspace.branch_id,
                    binding.epoch,
                )
            })
    }

    /// Bounded cleanup of unreferenced objects. Root, run-binding,
    /// checkpoint-receipt, durable prepared-receipt, and in-flight reservation
    /// refs are preserved; at most 64 recent orphans remain. The protected set
    /// is read by the same existing storage worker at the command's execution
    /// boundary, never from a caller snapshot. Health is recorded by the worker
    /// in execution order: a failed sweep keeps bounded debt so later object
    /// writes are refused with typed backpressure until an explicit successful
    /// sweep recovers, instead of accumulating durable orphans.
    pub fn collect_orphans(&self) -> Result<(), PluginStateError> {
        self.collect_orphans_inner(true)
    }

    /// Backpressure-path reclamation: runs the same bounded worker-ordered
    /// collection but never clears debt on its own. Used when refusing new
    /// objects so refused traffic cannot grow the disk while degraded.
    pub(crate) fn collect_orphans_quiet(&self) -> Result<(), PluginStateError> {
        self.collect_orphans_inner(false)
    }

    fn collect_orphans_inner(&self, report_health: bool) -> Result<(), PluginStateError> {
        #[cfg(any(test, feature = "workspace-io-fault"))]
        if let Some(observer) = self.persistence.plugin_state_collect_observer_hook() {
            observer();
        }
        #[cfg(any(test, feature = "workspace-io-fault"))]
        let failpoint = if self.persistence.take_plugin_state_collect_failpoint() {
            "after_partial_write"
        } else {
            ""
        };
        #[cfg(not(any(test, feature = "workspace-io-fault")))]
        let failpoint = "";
        let since_epoch = self.persistence.plugin_state_candidates.health().epoch;
        #[cfg(any(test, feature = "workspace-io-fault"))]
        if let Some(observer) = self
            .persistence
            .plugin_state_collect_enqueue_observer_hook()
        {
            observer(report_health);
        }
        let result = self.persistence.plugin_state_collect_command(
            &serde_json::json!({ "failpoint": failpoint, "protected_ids_json": "[]" }),
            report_health,
        );
        #[cfg(feature = "workspace-io-fault")]
        if let Some(observer) = self.persistence.plugin_state_collect_result_observer_hook() {
            observer(result.is_ok());
        }
        match result {
            Ok(_) => Ok(()),
            Err(error) => {
                // Unknown outcome (reply timeout or transport loss): mark debt
                // only when the worker is gone and the request can never still
                // execute. While the worker is alive, a timed-out request may
                // still be queued (parked or backlogged) and the worker
                // records its real outcome in execution order; a caller
                // timeout must never fabricate debt, nor clear anything. A
                // delayed older success can never clear a newer failure: the
                // worker already recorded its own result in execution order.
                if !self.persistence.is_storage_worker_running() {
                    self.persistence
                        .plugin_state_candidates
                        .note_collect_outcome_unknown(since_epoch);
                }
                Err(PluginStateError::storage(error))
            }
        }
    }

    #[cfg(feature = "workspace-io-fault")]
    pub fn collect_orphans_result_for_test(&self) -> Result<(), PluginStateError> {
        self.collect_orphans()
    }

    pub fn session_nonterminal_runs(&self, session_id: &str) -> Result<u64, PluginStateError> {
        let data = self.command(
            "plugin.state_session_nonterminal",
            serde_json::json!({ "session_id": session_id }),
        )?;
        first_u64(&data, "plugin_state_unavailable")
    }

    pub fn session_max_schema(&self, plugin_id: &str) -> Result<u64, PluginStateError> {
        let data = self.command(
            "plugin.state_session_max_schema",
            serde_json::json!({ "plugin_id": plugin_id }),
        )?;
        first_u64(&data, "plugin_state_unavailable")
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn text_at(row: &[Value], index: usize) -> Result<String, PluginStateError> {
    row.get(index)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            PluginStateError::new(
                "plugin_state_unavailable",
                "state row text field is invalid",
            )
        })
}

fn u64_at(row: &[Value], index: usize) -> Result<u64, PluginStateError> {
    row.get(index)
        .and_then(Value::as_u64)
        .or_else(|| {
            row.get(index)
                .and_then(Value::as_i64)
                .and_then(|value| u64::try_from(value).ok())
        })
        .ok_or_else(|| {
            PluginStateError::new(
                "plugin_state_unavailable",
                "state row integer field is invalid",
            )
        })
}

fn u32_at(row: &[Value], index: usize) -> Result<u32, PluginStateError> {
    u32::try_from(u64_at(row, index)?).map_err(|_| {
        PluginStateError::new("plugin_state_invalid_schema", "state schema is invalid")
    })
}

fn root_from_row(row: &[Value]) -> Result<PluginStateRoot, PluginStateError> {
    Ok(PluginStateRoot {
        owner_kind: text_at(row, 0)?,
        owner_id: text_at(row, 1)?,
        workspace_id: text_at(row, 2)?,
        branch_id: text_at(row, 3)?,
        plugin_id: text_at(row, 4)?,
        package_id: text_at(row, 5)?,
        artifact_id: text_at(row, 6)?,
        schema: u32_at(row, 7)?,
        revision: u64_at(row, 8)?,
        object_id: text_at(row, 9)?,
    })
}

fn root_ref_from_row(row: &[Value]) -> Result<PluginStateRootRef, PluginStateError> {
    Ok(PluginStateRootRef {
        owner_kind: text_at(row, 0)?,
        owner_id: text_at(row, 1)?,
        workspace_id: text_at(row, 2)?,
        branch_id: text_at(row, 3)?,
        plugin_id: text_at(row, 4)?,
        package_id: text_at(row, 5)?,
        artifact_id: text_at(row, 6)?,
        schema: u32_at(row, 7)?,
        revision: u64_at(row, 8)?,
        object_id: text_at(row, 9)?,
    })
}

fn snapshot_from_row(row: &[Value]) -> Result<Option<PluginStateSnapshot>, PluginStateError> {
    if row.len() < 17 {
        return Err(PluginStateError::new(
            "plugin_state_unavailable",
            "state binding row is truncated",
        ));
    }
    let binding = PluginStateBinding {
        run_id: text_at(row, 0)?,
        session_id: text_at(row, 1)?,
        workspace_id: text_at(row, 2)?,
        branch_id: text_at(row, 3)?,
        plugin_id: text_at(row, 4)?,
        package_id: text_at(row, 5)?,
        artifact_id: text_at(row, 6)?,
        owner_kind: text_at(row, 7)?,
        owner_id: text_at(row, 8)?,
        graph_id: text_at(row, 9)?,
        epoch: u64_at(row, 10)?,
        schema: u32_at(row, 11)?,
        revision: u64_at(row, 12)?,
        object_id: text_at(row, 13)?,
        checkpoint_id: text_at(row, 14)?,
    };
    let document = text_at(row, 15)?;
    let payload = PluginStatePayload::parse(&document)?;
    Ok(Some(PluginStateSnapshot { binding, payload }))
}

fn validate_binding(
    binding: &PluginStateBinding,
    request: &PluginStateBindRequest,
) -> Result<(), PluginStateError> {
    let owner = match request.scope {
        PluginStateScope::Run => request.run_id.as_str(),
        PluginStateScope::Session => request.session_id.as_str(),
        PluginStateScope::Invocation => {
            return Err(PluginStateError::new(
                "plugin_state_binding_conflict",
                "invocation state has no durable binding",
            ));
        }
    };
    if binding.session_id != request.session_id
        || binding.workspace_id != request.workspace_id
        || binding.branch_id != request.branch_id
        || binding.plugin_id != request.plugin_id
        || binding.package_id != request.package_id
        || binding.artifact_id != request.artifact_id
        || binding.owner_kind != request.scope.as_str()
        || binding.owner_id != owner
        || binding.graph_id != request.graph_id
        || binding.schema != request.schema
    {
        return Err(PluginStateError::new(
            "plugin_state_binding_conflict",
            "existing run state binding belongs to another owner or graph",
        ));
    }
    Ok(())
}

fn select_restore_root(
    request: &PluginStateRestoreRequest,
) -> Result<&PluginStateRootRef, PluginStateError> {
    let mut candidates = request.roots.iter().filter(|root| {
        root.owner_kind == request.scope.as_str()
            && root.plugin_id == request.plugin_id
            && root.workspace_id == request.workspace_id
    });
    let selected = candidates.next().ok_or_else(|| {
        PluginStateError::new(
            "plugin_state_root_missing",
            "checkpoint has no root for this run or session",
        )
    })?;
    if candidates.next().is_some() {
        return Err(PluginStateError::new(
            "plugin_state_root_mismatch",
            "checkpoint has multiple state roots for this owner and plugin",
        ));
    }
    if selected.package_id != request.package_id || selected.artifact_id != request.artifact_id {
        return Err(PluginStateError::new(
            "plugin_state_root_mismatch",
            "checkpoint state root package does not match",
        ));
    }
    if selected.owner_id.is_empty()
        || selected.branch_id.is_empty()
        || selected.object_id.is_empty()
    {
        return Err(PluginStateError::new(
            "plugin_state_root_mismatch",
            "checkpoint state root owner, branch, or object is empty",
        ));
    }
    if selected.schema == 0 || selected.schema > 64 || selected.revision == 0 {
        return Err(PluginStateError::new(
            "plugin_state_root_mismatch",
            "checkpoint state root schema or revision is invalid",
        ));
    }
    Ok(selected)
}

fn first_u64(data: &Value, code: &'static str) -> Result<u64, PluginStateError> {
    let rows = crate::sqlite_storage_rows::sqlite_storage_rows(data)
        .map_err(|_| PluginStateError::new(code, "state query row is invalid"))?;
    rows.first()
        .and_then(|row| row.first())
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
        })
        .ok_or_else(|| PluginStateError::new(code, "state query returned no value"))
}

/// A pure migration entry must be exported by exactly one package source and
/// that file may import only `json` and `bytes` plus package-local modules.
pub fn validate_state_migration_source(
    package: &crate::plugins::InstalledPackage,
    entry: &str,
) -> Result<(), &'static str> {
    let marker = format!("pub fn {entry}(");
    let mut found: Option<&str> = None;
    for (path, bytes) in &package.sources {
        let Ok(source) = std::str::from_utf8(bytes) else {
            continue;
        };
        if source.contains(&marker) {
            if found.is_some() {
                return Err("plugin_state_migration_ambiguous");
            }
            found = Some(path.as_str());
        }
    }
    let path = found.ok_or("plugin_state_migration_missing")?;
    let source = package
        .sources
        .get(path)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .ok_or("plugin_state_migration_missing")?;
    for line in source.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix("use ") else {
            continue;
        };
        let module = rest.split([';', ':', ' ', '{']).next().unwrap_or("").trim();
        if module.is_empty() {
            continue;
        }
        let local = package
            .sources
            .keys()
            .any(|key| key == &format!("{module}.rss") || key.starts_with(&format!("{module}/")));
        if !local && module != "json" && module != "bytes" {
            return Err("plugin_state_migration_impure");
        }
    }
    Ok(())
}
