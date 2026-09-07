//! Generic capability lifecycle tokens: prepare, commit, recovery.
//!
//! These tests drive the Rust lifecycle engine and the
//! `agent_runtime::tool_prepare` / `agent_runtime::tool_commit` host
//! boundary. Public tool names stay opaque metadata.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rustscript_agent::capabilities::{
    ApprovalGate, CancellationFlag, CapabilityLifecycle, CapabilityOwner, CapabilityRisk,
    DurableStarted, DurableToolLifecycle, ExecutionLease, LifecycleClock, LifecycleError,
    LifecycleLimits, PrepareMetadata, PrepareOutcome, TokenIssuer,
};
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner};
use rustscript_vm::Value as VmValue;
use serde_json::{Value, json};

struct SequenceLog {
    events: Mutex<Vec<String>>,
}

impl SequenceLog {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
        })
    }

    fn push(&self, event: impl Into<String>) {
        self.events.lock().expect("sequence log").push(event.into());
    }

    fn snapshot(&self) -> Vec<String> {
        self.events.lock().expect("sequence log").clone()
    }
}

struct ScriptedClock {
    now_ms: Mutex<u64>,
    instant: Mutex<Instant>,
}

impl ScriptedClock {
    fn new(now_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            now_ms: Mutex::new(now_ms),
            instant: Mutex::new(Instant::now()),
        })
    }

    fn set_now_ms(&self, now_ms: u64) {
        *self.now_ms.lock().expect("clock ms") = now_ms;
    }
}

impl LifecycleClock for ScriptedClock {
    fn now_ms(&self) -> u64 {
        *self.now_ms.lock().expect("clock ms")
    }

    fn now(&self) -> Instant {
        *self.instant.lock().expect("clock instant")
    }
}

struct LoggingIssuer {
    log: Arc<SequenceLog>,
    next: Mutex<u64>,
}

impl LoggingIssuer {
    fn new(log: Arc<SequenceLog>) -> Arc<Self> {
        Arc::new(Self {
            log,
            next: Mutex::new(1),
        })
    }
}

impl TokenIssuer for LoggingIssuer {
    fn issue(&self) -> String {
        self.log.push("token");
        let mut next = self.next.lock().expect("issuer");
        let id = *next;
        *next += 1;
        format!("tok-{id}")
    }
}

struct MemoryDurable {
    log: Arc<SequenceLog>,
    active: Mutex<bool>,
    parent_ok: Mutex<bool>,
    fail_started: Mutex<bool>,
    started: Mutex<Vec<DurableStarted>>,
    results: Mutex<HashMap<String, Value>>,
    interrupted: Mutex<Vec<String>>,
}

impl MemoryDurable {
    fn new(log: Arc<SequenceLog>) -> Arc<Self> {
        Arc::new(Self {
            log,
            active: Mutex::new(true),
            parent_ok: Mutex::new(true),
            fail_started: Mutex::new(false),
            started: Mutex::new(Vec::new()),
            results: Mutex::new(HashMap::new()),
            interrupted: Mutex::new(Vec::new()),
        })
    }

    fn fail_next_started(&self) {
        *self.fail_started.lock().expect("fail started") = true;
    }

    fn started_records(&self) -> Vec<DurableStarted> {
        self.started.lock().expect("started").clone()
    }

    fn seed_result(&self, call_id: &str, result: Value) {
        self.results
            .lock()
            .expect("results")
            .insert(call_id.to_string(), result);
    }

    fn set_active(&self, active: bool) {
        *self.active.lock().expect("active") = active;
    }

    fn set_parent_ok(&self, ok: bool) {
        *self.parent_ok.lock().expect("parent") = ok;
    }

    fn interrupted(&self) -> Vec<String> {
        self.interrupted.lock().expect("interrupted").clone()
    }
}

impl DurableToolLifecycle for MemoryDurable {
    fn assert_active_run(&self, _run_id: &str) -> Result<(), LifecycleError> {
        if *self.active.lock().expect("active") {
            Ok(())
        } else {
            Err(LifecycleError::InactiveRun)
        }
    }

    fn prepare_parent(
        &self,
        _run_id: &str,
        _call_id: &str,
        _tool_name: &str,
    ) -> Result<(), LifecycleError> {
        if *self.parent_ok.lock().expect("parent") {
            Ok(())
        } else {
            Err(LifecycleError::MissingParent)
        }
    }

    fn replay_result(
        &self,
        _run_id: &str,
        call_id: &str,
        _tool_name: &str,
    ) -> Result<Option<Value>, LifecycleError> {
        Ok(self.results.lock().expect("results").get(call_id).cloned())
    }

    fn commit_started(&self, record: &DurableStarted) -> Result<(), LifecycleError> {
        self.log.push("started");
        let mut fail = self.fail_started.lock().expect("fail started");
        if *fail {
            *fail = false;
            return Err(LifecycleError::StartedCommitFailed(
                "injected started failure".to_string(),
            ));
        }
        drop(fail);
        self.started.lock().expect("started").push(record.clone());
        Ok(())
    }

    fn commit_result(&self, call_id: &str, result: &Value) -> Result<Value, LifecycleError> {
        self.log.push("result");
        self.results
            .lock()
            .expect("results")
            .insert(call_id.to_string(), result.clone());
        Ok(json!({
            "ok": true,
            "kind": "committed",
            "call_id": call_id,
            "result": result,
        }))
    }

    fn interrupt(&self, call_id: &str) -> Result<(), LifecycleError> {
        self.log.push("interrupted");
        self.interrupted
            .lock()
            .expect("interrupted")
            .push(call_id.to_string());
        Ok(())
    }
}

struct AllowAll;

impl ApprovalGate for AllowAll {
    fn authorize(&self, metadata: &PrepareMetadata) -> Result<CapabilityRisk, LifecycleError> {
        Ok(metadata.risk_class)
    }
}

struct DenyAll {
    reason: String,
}

impl ApprovalGate for DenyAll {
    fn authorize(&self, _metadata: &PrepareMetadata) -> Result<CapabilityRisk, LifecycleError> {
        Err(LifecycleError::ApprovalDenied {
            reason: self.reason.clone(),
        })
    }
}

struct CeilingGate {
    ceiling: CapabilityRisk,
}

impl ApprovalGate for CeilingGate {
    fn authorize(&self, metadata: &PrepareMetadata) -> Result<CapabilityRisk, LifecycleError> {
        if metadata.risk_class > self.ceiling {
            return Err(LifecycleError::ApprovalCeiling {
                requested: metadata.risk_class,
                ceiling: self.ceiling,
            });
        }
        Ok(self.ceiling)
    }
}

struct FlagCancel {
    cancelled: AtomicBool,
}

impl FlagCancel {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
        })
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

impl CancellationFlag for FlagCancel {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

fn owner() -> CapabilityOwner {
    CapabilityOwner::new("profile-a", "session-a", "run-a").expect("owner")
}

fn metadata(call_id: &str, name: &str) -> PrepareMetadata {
    PrepareMetadata {
        run_id: "run-a".to_string(),
        call_id: call_id.to_string(),
        tool_name: name.to_string(),
        argument_digest: "digest-a".to_string(),
        registry_identity: "registry-a".to_string(),
        risk_class: CapabilityRisk::Read,
        summary: "read fixture".to_string(),
    }
}

fn engine(log: Arc<SequenceLog>, durable: Arc<MemoryDurable>) -> CapabilityLifecycle {
    CapabilityLifecycle::builder()
        .owner(owner())
        .registry_identity("registry-a")
        .workspace("/tmp/workspace-a")
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(10_000)
        .clock(Arc::clone(&ScriptedClock::new(1_000)) as Arc<dyn LifecycleClock>)
        .tokens(LoggingIssuer::new(log) as Arc<dyn TokenIssuer>)
        .durable(durable as Arc<dyn DurableToolLifecycle>)
        .approval(Arc::new(AllowAll) as Arc<dyn ApprovalGate>)
        .generation(1)
        .build()
        .expect("lifecycle")
}

#[test]
fn prepare_commits_started_before_issuing_token() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));

    let outcome = lifecycle
        .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
        .expect("prepare should succeed");
    let PrepareOutcome::Execute {
        execution_token,
        deadline_ms,
    } = outcome
    else {
        panic!("expected execute token, got {outcome:?}");
    };

    assert_eq!(execution_token, "tok-1");
    assert_eq!(deadline_ms, 10_000);
    assert_eq!(log.snapshot(), ["started", "token"]);
    let started = durable.started_records();
    assert_eq!(started.len(), 1);
    assert_eq!(started[0].call_id, "call-1");
    assert_eq!(started[0].tool_name, "fixture_only_tool");
    assert_eq!(started[0].argument_digest, "digest-a");
    assert_eq!(started[0].registry_identity, "registry-a");
    assert_eq!(started[0].generation, 1);

    durable.fail_next_started();
    let failed = lifecycle
        .prepare(&owner(), metadata("call-2", "fixture_only_tool"))
        .expect_err("failed started commit must not issue a token");
    assert_eq!(
        failed,
        LifecycleError::StartedCommitFailed("injected started failure".to_string())
    );
    assert_eq!(log.snapshot(), ["started", "token", "started"]);
    assert_eq!(durable.started_records().len(), 1);
}

#[test]
fn prepare_rejects_owner_mismatch() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let other = CapabilityOwner::new("other-profile", "session-a", "run-a").expect("other");
    let error = lifecycle
        .prepare(&other, metadata("call-1", "fixture_only_tool"))
        .expect_err("foreign owner must not receive a token");
    assert_eq!(
        error,
        LifecycleError::OwnerMismatch {
            expected: "profile-a/session-a/run-a".to_string(),
            actual: "other-profile/session-a/run-a".to_string(),
        }
    );
    assert!(log.snapshot().is_empty());
    assert!(durable.started_records().is_empty());

    let mut foreign_run = metadata("call-1", "fixture_only_tool");
    foreign_run.run_id = "run-b".to_string();
    let error = lifecycle
        .prepare(&owner(), foreign_run)
        .expect_err("metadata run must match frozen owner");
    assert_eq!(
        error,
        LifecycleError::OwnerMismatch {
            expected: "profile-a/session-a/run-a".to_string(),
            actual: "profile-a/session-a/run-b".to_string(),
        }
    );
    assert!(log.snapshot().is_empty());
}

#[test]
fn prepare_replays_durable_terminal_result_without_token() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let replayed = json!({"ok": true, "content": "already done"});
    durable.seed_result("call-1", replayed.clone());
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let outcome = lifecycle
        .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
        .expect("replay should succeed");
    assert_eq!(outcome, PrepareOutcome::Replay { result: replayed });
    assert!(log.snapshot().is_empty());
    assert!(durable.started_records().is_empty());
}

#[test]
fn prepare_requires_active_run_and_parent() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    durable.set_active(false);
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let error = lifecycle
        .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
        .expect_err("inactive run must not start");
    assert_eq!(error, LifecycleError::InactiveRun);
    assert!(log.snapshot().is_empty());

    durable.set_active(true);
    durable.set_parent_ok(false);
    let error = lifecycle
        .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
        .expect_err("missing parent must not start");
    assert_eq!(error, LifecycleError::MissingParent);
    assert!(log.snapshot().is_empty());
}

#[test]
fn prepare_enforces_approval_denial_and_ceiling() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let denied = CapabilityLifecycle::builder()
        .owner(owner())
        .registry_identity("registry-a")
        .workspace("/tmp/workspace-a")
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(10_000)
        .clock(ScriptedClock::new(1_000) as Arc<dyn LifecycleClock>)
        .tokens(LoggingIssuer::new(Arc::clone(&log)) as Arc<dyn TokenIssuer>)
        .durable(Arc::clone(&durable) as Arc<dyn DurableToolLifecycle>)
        .approval(Arc::new(DenyAll {
            reason: "write requires approval".to_string(),
        }) as Arc<dyn ApprovalGate>)
        .generation(1)
        .build()
        .expect("denied lifecycle");
    let error = denied
        .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
        .expect_err("denied approval must not start");
    assert_eq!(
        error,
        LifecycleError::ApprovalDenied {
            reason: "write requires approval".to_string(),
        }
    );
    assert!(log.snapshot().is_empty());

    let ceiling = CapabilityLifecycle::builder()
        .owner(owner())
        .registry_identity("registry-a")
        .workspace("/tmp/workspace-a")
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(10_000)
        .clock(ScriptedClock::new(1_000) as Arc<dyn LifecycleClock>)
        .tokens(LoggingIssuer::new(Arc::clone(&log)) as Arc<dyn TokenIssuer>)
        .durable(Arc::clone(&durable) as Arc<dyn DurableToolLifecycle>)
        .approval(Arc::new(CeilingGate {
            ceiling: CapabilityRisk::Read,
        }) as Arc<dyn ApprovalGate>)
        .generation(1)
        .build()
        .expect("ceiling lifecycle");
    let mut write = metadata("call-2", "fixture_only_tool");
    write.risk_class = CapabilityRisk::Write;
    let error = ceiling
        .prepare(&owner(), write)
        .expect_err("write above read ceiling must not start");
    assert_eq!(
        error,
        LifecycleError::ApprovalCeiling {
            requested: CapabilityRisk::Write,
            ceiling: CapabilityRisk::Read,
        }
    );
    assert!(log.snapshot().is_empty());
}

#[test]
fn prepare_rejects_deadline_elapsed() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let clock = ScriptedClock::new(10_000);
    let lifecycle = CapabilityLifecycle::builder()
        .owner(owner())
        .registry_identity("registry-a")
        .workspace("/tmp/workspace-a")
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(10_000)
        .clock(Arc::clone(&clock) as Arc<dyn LifecycleClock>)
        .tokens(LoggingIssuer::new(Arc::clone(&log)) as Arc<dyn TokenIssuer>)
        .durable(Arc::clone(&durable) as Arc<dyn DurableToolLifecycle>)
        .approval(Arc::new(AllowAll) as Arc<dyn ApprovalGate>)
        .generation(1)
        .build()
        .expect("lifecycle");
    let error = lifecycle
        .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
        .expect_err("deadline must fail closed");
    assert_eq!(error, LifecycleError::DeadlineElapsed);
    assert!(log.snapshot().is_empty());

    clock.set_now_ms(9_999);
    lifecycle
        .prepare(&owner(), metadata("call-2", "fixture_only_tool"))
        .expect("time remaining should prepare");
}

fn token_of(outcome: PrepareOutcome) -> String {
    match outcome {
        PrepareOutcome::Execute {
            execution_token, ..
        } => execution_token,
        other => panic!("expected execute token, got {other:?}"),
    }
}

#[test]
fn prepare_rejects_cancellation() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let cancel = FlagCancel::new();
    cancel.cancel();
    let lifecycle = CapabilityLifecycle::builder()
        .owner(owner())
        .registry_identity("registry-a")
        .workspace("/tmp/workspace-a")
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(10_000)
        .clock(ScriptedClock::new(1_000) as Arc<dyn LifecycleClock>)
        .tokens(LoggingIssuer::new(Arc::clone(&log)) as Arc<dyn TokenIssuer>)
        .durable(Arc::clone(&durable) as Arc<dyn DurableToolLifecycle>)
        .approval(Arc::new(AllowAll) as Arc<dyn ApprovalGate>)
        .cancellation(Arc::clone(&cancel) as Arc<dyn CancellationFlag>)
        .generation(1)
        .build()
        .expect("lifecycle");
    let error = lifecycle
        .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
        .expect_err("cancelled run must not start");
    assert_eq!(error, LifecycleError::Cancelled);
    assert!(log.snapshot().is_empty());
}

#[test]
fn prepare_rejects_registry_mismatch_and_call_limit() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = CapabilityLifecycle::builder()
        .owner(owner())
        .registry_identity("registry-a")
        .workspace("/tmp/workspace-a")
        .limits(LifecycleLimits {
            max_tool_calls: 1,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(10_000)
        .clock(ScriptedClock::new(1_000) as Arc<dyn LifecycleClock>)
        .tokens(LoggingIssuer::new(Arc::clone(&log)) as Arc<dyn TokenIssuer>)
        .durable(Arc::clone(&durable) as Arc<dyn DurableToolLifecycle>)
        .approval(Arc::new(AllowAll) as Arc<dyn ApprovalGate>)
        .generation(1)
        .build()
        .expect("lifecycle");
    let mut mismatched = metadata("call-1", "fixture_only_tool");
    mismatched.registry_identity = "registry-other".to_string();
    let error = lifecycle
        .prepare(&owner(), mismatched)
        .expect_err("frozen registry identity must match");
    assert_eq!(error, LifecycleError::RegistryMismatch);
    assert!(log.snapshot().is_empty());

    lifecycle
        .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
        .expect("first call");
    let error = lifecycle
        .prepare(&owner(), metadata("call-2", "fixture_only_tool"))
        .expect_err("call limit");
    assert_eq!(error, LifecycleError::LimitExceeded);
    assert_eq!(log.snapshot(), ["started", "token"]);
}

#[test]
fn prepare_rejects_second_token_for_unresolved_call() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    lifecycle
        .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
        .expect("first prepare");
    let error = lifecycle
        .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
        .expect_err("same-run retry must not issue a second token");
    assert_eq!(error, LifecycleError::UnresolvedCall);
    assert_eq!(error.code(), "unresolved_call");
    assert_eq!(log.snapshot(), ["started", "token"]);
    assert_eq!(durable.started_records().len(), 1);
}

#[test]
fn commit_validates_ownership_single_close_and_bounds() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let token = token_of(
        lifecycle
            .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
            .expect("prepare"),
    );
    let other = CapabilityOwner::new("other-profile", "session-a", "run-a").expect("other");
    let error = lifecycle
        .commit(&other, &token, json!({"ok": true, "content": "x"}))
        .expect_err("foreign owner cannot close");
    assert_eq!(
        error,
        LifecycleError::OwnerMismatch {
            expected: "profile-a/session-a/run-a".to_string(),
            actual: "other-profile/session-a/run-a".to_string(),
        }
    );

    let huge = "x".repeat(5000);
    let error = lifecycle
        .commit(&owner(), &token, json!({"ok": true, "content": huge}))
        .expect_err("output budget");
    assert_eq!(error, LifecycleError::ResultTooLarge);

    let committed = lifecycle
        .commit(&owner(), &token, json!({"ok": true, "content": "done"}))
        .expect("commit");
    assert_eq!(committed.envelope["kind"], json!("committed"));
    assert_eq!(committed.envelope["call_id"], json!("call-1"));
    assert_eq!(log.snapshot(), ["started", "token", "result"]);

    let error = lifecycle
        .commit(&owner(), &token, json!({"ok": true, "content": "again"}))
        .expect_err("single close");
    assert_eq!(error, LifecycleError::DuplicateClose);

    let error = lifecycle
        .commit(&owner(), "forged-token", json!({"ok": true}))
        .expect_err("unforgeable");
    assert_eq!(error, LifecycleError::TokenUnknown);
}

#[test]
fn recover_open_tokens_interrupts_without_reuse() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let token = token_of(
        lifecycle
            .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
            .expect("prepare"),
    );
    let recovered = lifecycle.recover_open_tokens().expect("recover");
    assert_eq!(recovered, ["call-1"]);
    assert_eq!(durable.interrupted(), ["call-1"]);
    let error = lifecycle
        .commit(&owner(), &token, json!({"ok": true, "content": "late"}))
        .expect_err("interrupted token cannot commit");
    assert_eq!(error, LifecycleError::Interrupted);
}

#[test]
fn authorize_returns_bounded_immutable_claims_for_open_token() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let token = token_of(
        lifecycle
            .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
            .expect("prepare"),
    );
    let claims = lifecycle
        .authorize(&owner(), &token, CapabilityRisk::Read)
        .expect("open token must authorize");
    assert_eq!(claims.owner, owner());
    assert_eq!(claims.call_id, "call-1");
    assert_eq!(claims.tool_name, "fixture_only_tool");
    assert_eq!(claims.argument_digest, "digest-a");
    assert_eq!(claims.registry_identity, "registry-a");
    assert_eq!(claims.risk_ceiling, CapabilityRisk::Read);
    assert_eq!(claims.output_budget, 4096);
    assert_eq!(claims.generation, 1);
    assert_eq!(claims.deadline_ms, 10_000);
    assert_eq!(claims.workspace.as_os_str(), "/tmp/workspace-a");
    let mut mutated = claims.clone();
    mutated.call_id = "forged".to_string();
    let reread = lifecycle
        .authorize(&owner(), &token, CapabilityRisk::Read)
        .expect("claims stay immutable");
    assert_eq!(reread.call_id, "call-1");
}

#[test]
fn authorize_rejects_invalid_state_owner_deadline_cancel_generation_and_ceiling() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let cancel = FlagCancel::new();
    let clock = ScriptedClock::new(1_000);
    let lifecycle = CapabilityLifecycle::builder()
        .owner(owner())
        .registry_identity("registry-a")
        .workspace("/tmp/workspace-a")
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(10_000)
        .clock(Arc::clone(&clock) as Arc<dyn LifecycleClock>)
        .tokens(LoggingIssuer::new(Arc::clone(&log)) as Arc<dyn TokenIssuer>)
        .durable(Arc::clone(&durable) as Arc<dyn DurableToolLifecycle>)
        .approval(Arc::new(AllowAll) as Arc<dyn ApprovalGate>)
        .cancellation(Arc::clone(&cancel) as Arc<dyn CancellationFlag>)
        .generation(1)
        .build()
        .expect("lifecycle");
    let token = token_of(
        lifecycle
            .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
            .expect("prepare"),
    );
    let other = CapabilityOwner::new("other-profile", "session-a", "run-a").expect("other");
    assert_eq!(
        lifecycle
            .authorize(&other, &token, CapabilityRisk::Read)
            .expect_err("foreign owner"),
        LifecycleError::OwnerMismatch {
            expected: "profile-a/session-a/run-a".to_string(),
            actual: "other-profile/session-a/run-a".to_string(),
        }
    );
    assert_eq!(
        lifecycle
            .authorize(&owner(), "forged-token", CapabilityRisk::Read)
            .expect_err("unknown"),
        LifecycleError::TokenUnknown
    );
    assert_eq!(
        lifecycle
            .authorize(&owner(), &token, CapabilityRisk::Write)
            .expect_err("ceiling"),
        LifecycleError::ApprovalCeiling {
            requested: CapabilityRisk::Write,
            ceiling: CapabilityRisk::Read,
        }
    );
    clock.set_now_ms(10_000);
    assert_eq!(
        lifecycle
            .authorize(&owner(), &token, CapabilityRisk::Read)
            .expect_err("deadline"),
        LifecycleError::DeadlineElapsed
    );
    clock.set_now_ms(1_000);
    cancel.cancel();
    assert_eq!(
        lifecycle
            .authorize(&owner(), &token, CapabilityRisk::Read)
            .expect_err("cancelled"),
        LifecycleError::Cancelled
    );

    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let committed = token_of(
        lifecycle
            .prepare(&owner(), metadata("call-2", "fixture_only_tool"))
            .expect("prepare"),
    );
    lifecycle
        .commit(&owner(), &committed, json!({"ok": true, "content": "done"}))
        .expect("commit");
    assert_eq!(
        lifecycle
            .authorize(&owner(), &committed, CapabilityRisk::Read)
            .expect_err("committed"),
        LifecycleError::DuplicateClose
    );
    let interrupted = token_of(
        lifecycle
            .prepare(&owner(), metadata("call-3", "fixture_only_tool"))
            .expect("prepare"),
    );
    lifecycle.recover_open_tokens().expect("recover");
    assert_eq!(
        lifecycle
            .authorize(&owner(), &interrupted, CapabilityRisk::Read)
            .expect_err("interrupted"),
        LifecycleError::Interrupted
    );
}

#[test]
fn panic_cleanup_interrupts_open_lease() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let token = token_of(
        lifecycle
            .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
            .expect("prepare"),
    );
    let panicked = catch_unwind(AssertUnwindSafe(|| {
        let _lease: ExecutionLease = lifecycle.lease(&token).expect("lease");
        panic!("tool body panicked");
    }));
    assert!(panicked.is_err());
    assert_eq!(durable.interrupted(), ["call-1"]);
    let error = lifecycle
        .commit(&owner(), &token, json!({"ok": true, "content": "late"}))
        .expect_err("panic cleanup closes the token");
    assert_eq!(error, LifecycleError::Interrupted);
}

#[test]
fn host_prepare_and_commit_treat_tool_names_as_opaque() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let host = AgentHostBridges {
        lifecycle: Some(Arc::new(lifecycle)),
        capability_owner: Some(owner()),
        ..AgentHostBridges::default()
    };
    let source = r#"
        pub fn run(input: map) -> map {
            let prepared: map = agent_runtime::tool_prepare({
                run_id: "run-a",
                call_id: "call-1",
                name: "fixture_only_tool",
                argument_digest: "digest-a",
                registry_identity: "registry-a",
                risk_class: "read",
                summary: "read fixture",
            });
            agent_runtime::tool_commit(prepared.execution_token, {
                ok: true,
                content: "from-rss",
            })
        }
    "#;
    let result = AgentRunner::from_source(source, AgentConfig::default())
        .expect("compile")
        .with_host(host)
        .run_with_context(VmValue::map(vec![]))
        .expect("run");
    let VmValue::Map(fields) = result else {
        panic!("expected map envelope, got {result:?}");
    };
    let kind = fields.get(&VmValue::string("kind")).expect("kind");
    assert_eq!(kind, &VmValue::string("committed"));
    assert_eq!(log.snapshot(), ["started", "token", "result"]);
    assert_eq!(durable.started_records()[0].tool_name, "fixture_only_tool");
}

#[test]
fn host_prepare_without_commit_interrupts_on_drop() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let host = AgentHostBridges {
        lifecycle: Some(Arc::new(lifecycle)),
        capability_owner: Some(owner()),
        ..AgentHostBridges::default()
    };
    let source = r#"
        pub fn run(input: map) -> map {
            agent_runtime::tool_prepare({
                run_id: "run-a",
                call_id: "call-1",
                name: "fixture_only_tool",
                argument_digest: "digest-a",
                registry_identity: "registry-a",
                risk_class: "read",
                summary: "read fixture",
            })
        }
    "#;
    let result = AgentRunner::from_source(source, AgentConfig::default())
        .expect("compile")
        .with_host(host)
        .run_with_context(VmValue::map(vec![]))
        .expect("run");
    let VmValue::Map(fields) = result else {
        panic!("expected map envelope, got {result:?}");
    };
    let kind = fields.get(&VmValue::string("kind")).expect("kind");
    assert_eq!(kind, &VmValue::string("execute"));
    assert_eq!(durable.interrupted(), ["call-1"]);
    assert_eq!(log.snapshot(), ["started", "token", "interrupted"]);
}

#[test]
fn host_commit_disarms_lease_so_drop_does_not_interrupt() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let host = AgentHostBridges {
        lifecycle: Some(Arc::new(lifecycle)),
        capability_owner: Some(owner()),
        ..AgentHostBridges::default()
    };
    let source = r#"
        pub fn run(input: map) -> map {
            let prepared: map = agent_runtime::tool_prepare({
                run_id: "run-a",
                call_id: "call-1",
                name: "fixture_only_tool",
                argument_digest: "digest-a",
                registry_identity: "registry-a",
                risk_class: "read",
                summary: "read fixture",
            });
            agent_runtime::tool_commit(prepared.execution_token, {
                ok: true,
                content: "from-rss",
            })
        }
    "#;
    AgentRunner::from_source(source, AgentConfig::default())
        .expect("compile")
        .with_host(host)
        .run_with_context(VmValue::map(vec![]))
        .expect("run");
    assert!(durable.interrupted().is_empty());
    assert_eq!(log.snapshot(), ["started", "token", "result"]);
}

#[test]
fn host_same_run_retry_does_not_issue_second_token() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let host = AgentHostBridges {
        lifecycle: Some(Arc::new(lifecycle)),
        capability_owner: Some(owner()),
        ..AgentHostBridges::default()
    };
    let source = r#"
        pub fn run(input: map) -> map {
            let first: map = agent_runtime::tool_prepare({
                run_id: "run-a",
                call_id: "call-1",
                name: "fixture_only_tool",
                argument_digest: "digest-a",
                registry_identity: "registry-a",
                risk_class: "read",
                summary: "read fixture",
            });
            let second: map = agent_runtime::tool_prepare({
                run_id: "run-a",
                call_id: "call-1",
                name: "fixture_only_tool",
                argument_digest: "digest-a",
                registry_identity: "registry-a",
                risk_class: "read",
                summary: "read fixture",
            });
            { first: first, second: second }
        }
    "#;
    let result = AgentRunner::from_source(source, AgentConfig::default())
        .expect("compile")
        .with_host(host)
        .run_with_context(VmValue::map(vec![]))
        .expect("run");
    let VmValue::Map(fields) = result else {
        panic!("expected map envelope, got {result:?}");
    };
    let second = fields.get(&VmValue::string("second")).expect("second");
    let VmValue::Map(second) = second else {
        panic!("expected second map, got {second:?}");
    };
    let ok = second.get(&VmValue::string("ok")).expect("ok");
    assert_eq!(ok, &VmValue::Bool(false));
    let error = second.get(&VmValue::string("error")).expect("error");
    let VmValue::Map(error) = error else {
        panic!("expected error map, got {error:?}");
    };
    assert_eq!(
        error.get(&VmValue::string("code")).expect("code"),
        &VmValue::string("unresolved_call")
    );
    assert_eq!(log.snapshot(), ["started", "token", "interrupted"]);
    assert_eq!(durable.interrupted(), ["call-1"]);
}

#[test]
fn host_panic_after_prepare_interrupts_open_token() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let host = AgentHostBridges {
        lifecycle: Some(Arc::new(lifecycle)),
        capability_owner: Some(owner()),
        ..AgentHostBridges::default()
    };
    let source = r#"
        pub fn run(input: map) -> map {
            let prepared: map = agent_runtime::tool_prepare({
                run_id: "run-a",
                call_id: "call-1",
                name: "fixture_only_tool",
                argument_digest: "digest-a",
                registry_identity: "registry-a",
                risk_class: "read",
                summary: "read fixture",
            });
            assert(false);
            prepared
        }
    "#;
    let panicked = catch_unwind(AssertUnwindSafe(|| {
        AgentRunner::from_source(source, AgentConfig::default())
            .expect("compile")
            .with_host(host)
            .run_with_context(VmValue::map(vec![]))
    }));
    assert!(panicked.is_err() || panicked.as_ref().is_ok_and(|result| result.is_err()));
    assert_eq!(durable.interrupted(), ["call-1"]);
    assert_eq!(log.snapshot(), ["started", "token", "interrupted"]);
}

struct FailResultDurable {
    inner: Arc<MemoryDurable>,
    attempts: Mutex<u64>,
}

impl FailResultDurable {
    fn new(inner: Arc<MemoryDurable>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            attempts: Mutex::new(0),
        })
    }

    fn attempts(&self) -> u64 {
        *self.attempts.lock().expect("attempts")
    }
}

impl DurableToolLifecycle for FailResultDurable {
    fn assert_active_run(&self, run_id: &str) -> Result<(), LifecycleError> {
        self.inner.assert_active_run(run_id)
    }

    fn prepare_parent(
        &self,
        run_id: &str,
        call_id: &str,
        tool_name: &str,
    ) -> Result<(), LifecycleError> {
        self.inner.prepare_parent(run_id, call_id, tool_name)
    }

    fn replay_result(
        &self,
        run_id: &str,
        call_id: &str,
        tool_name: &str,
    ) -> Result<Option<Value>, LifecycleError> {
        self.inner.replay_result(run_id, call_id, tool_name)
    }

    fn commit_started(&self, record: &DurableStarted) -> Result<(), LifecycleError> {
        self.inner.commit_started(record)
    }

    fn commit_result(&self, _call_id: &str, _result: &Value) -> Result<Value, LifecycleError> {
        *self.attempts.lock().expect("attempts") += 1;
        self.inner.log.push("result");
        Err(LifecycleError::ResultCommitFailed(
            "injected result failure".to_string(),
        ))
    }

    fn interrupt(&self, call_id: &str) -> Result<(), LifecycleError> {
        self.inner.interrupt(call_id)
    }
}

fn engine_with_durable(
    log: Arc<SequenceLog>,
    durable: Arc<dyn DurableToolLifecycle>,
) -> CapabilityLifecycle {
    CapabilityLifecycle::builder()
        .owner(owner())
        .registry_identity("registry-a")
        .workspace("/tmp/workspace-a")
        .limits(LifecycleLimits {
            max_tool_calls: 8,
            max_output_bytes: 4096,
            max_summary_bytes: 256,
        })
        .deadline_ms(10_000)
        .clock(Arc::clone(&ScriptedClock::new(1_000)) as Arc<dyn LifecycleClock>)
        .tokens(LoggingIssuer::new(log) as Arc<dyn TokenIssuer>)
        .durable(durable)
        .approval(Arc::new(AllowAll) as Arc<dyn ApprovalGate>)
        .generation(1)
        .build()
        .expect("lifecycle")
}

#[test]
fn failed_durable_result_commit_fences_retry_and_same_call_prepare() {
    let log = SequenceLog::new();
    let inner = MemoryDurable::new(Arc::clone(&log));
    let durable = FailResultDurable::new(Arc::clone(&inner));
    let lifecycle = engine_with_durable(
        Arc::clone(&log),
        Arc::clone(&durable) as Arc<dyn DurableToolLifecycle>,
    );
    let token = token_of(
        lifecycle
            .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
            .expect("prepare"),
    );
    let error = lifecycle
        .commit(&owner(), &token, json!({"ok": true, "content": "done"}))
        .expect_err("durable result commit must fail closed");
    assert_eq!(
        error,
        LifecycleError::ResultCommitFailed("injected result failure".to_string())
    );
    assert_eq!(durable.attempts(), 1);
    assert!(
        inner
            .replay_result("run-a", "call-1", "fixture_only_tool")
            .expect("replay lookup")
            .is_none()
    );

    let retry = lifecycle
        .commit(&owner(), &token, json!({"ok": true, "content": "retry"}))
        .expect_err("retry commit must not execute after eager close");
    assert_eq!(retry, LifecycleError::DuplicateClose);
    assert_eq!(durable.attempts(), 1);
    assert_eq!(
        lifecycle
            .authorize(&owner(), &token, CapabilityRisk::Read)
            .expect_err("closed token must not authorize effects"),
        LifecycleError::DuplicateClose
    );

    let error = lifecycle
        .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
        .expect_err("same-call prepare must not issue another token");
    assert_eq!(error, LifecycleError::UnresolvedCall);
    assert_eq!(log.snapshot(), ["started", "token", "result"]);
    assert_eq!(inner.started_records().len(), 1);
}

#[test]
fn terminal_token_states_fence_same_call_prepare_without_durable_replay() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));

    lifecycle
        .prepare(&owner(), metadata("open-call", "fixture_only_tool"))
        .expect("open token");
    assert_eq!(
        lifecycle
            .prepare(&owner(), metadata("open-call", "fixture_only_tool"))
            .expect_err("Open fences prepare"),
        LifecycleError::UnresolvedCall
    );

    let committed = token_of(
        lifecycle
            .prepare(&owner(), metadata("committed-call", "fixture_only_tool"))
            .expect("committed prepare"),
    );
    lifecycle
        .commit(&owner(), &committed, json!({"ok": true, "content": "done"}))
        .expect("successful commit has durable replay");
    assert_eq!(
        lifecycle
            .prepare(&owner(), metadata("committed-call", "fixture_only_tool"))
            .expect("Committed with durable replay must replay"),
        PrepareOutcome::Replay {
            result: json!({"ok": true, "content": "done"}),
        }
    );

    let interrupted = token_of(
        lifecycle
            .prepare(&owner(), metadata("interrupted-call", "fixture_only_tool"))
            .expect("interrupted prepare"),
    );
    lifecycle.recover_open_tokens().expect("recover");
    assert_eq!(
        lifecycle
            .commit(
                &owner(),
                &interrupted,
                json!({"ok": true, "content": "late"})
            )
            .expect_err("Interrupted rejects commit"),
        LifecycleError::Interrupted
    );
    assert_eq!(
        lifecycle
            .prepare(&owner(), metadata("interrupted-call", "fixture_only_tool"))
            .expect_err("Interrupted without durable replay fences prepare"),
        LifecycleError::UnresolvedCall
    );
    assert_eq!(durable.started_records().len(), 3);
}

#[test]
fn commit_rejects_invalid_canonical_results_without_closing_token() {
    let log = SequenceLog::new();
    let durable = MemoryDurable::new(Arc::clone(&log));
    let lifecycle = engine(Arc::clone(&log), Arc::clone(&durable));
    let token = token_of(
        lifecycle
            .prepare(&owner(), metadata("call-1", "fixture_only_tool"))
            .expect("prepare"),
    );
    let mut lease = lifecycle
        .lease(&token)
        .expect("open token must be leaseable");

    let invalid = [
        json!({}),
        json!({"ok": "true"}),
        json!({"ok": 1}),
        json!({"ok": true}),
        json!({"ok": true, "content": 1}),
        json!({"ok": true, "content": "x", "truncated": "yes"}),
        json!({"ok": true, "content": "x", "artifacts": "id"}),
        json!({"ok": true, "content": "x", "artifacts": [1]}),
        json!({"ok": true, "content": "x", "data": "nope"}),
        json!({"ok": false}),
        json!({"ok": false, "error": {}}),
        json!({"ok": false, "error": {"code": 1}}),
    ];
    for result in invalid {
        let error = lifecycle
            .commit(&owner(), &token, result.clone())
            .expect_err("invalid canonical result must not close");
        assert!(
            matches!(error, LifecycleError::InvalidMetadata(_)),
            "expected InvalidMetadata for {result:?}, got {error:?}"
        );
        lifecycle
            .authorize(&owner(), &token, CapabilityRisk::Read)
            .expect("token must remain Open/leased after invalid commit");
    }

    lifecycle
        .commit(
            &owner(),
            &token,
            json!({
                "ok": false,
                "content": "typed failure body",
                "error": {"code": "not_found", "message": "missing fixture"}
            }),
        )
        .expect("corrected canonical failure must commit");
    lease.disarm();
    assert_eq!(
        lifecycle
            .commit(&owner(), &token, json!({"ok": true, "content": "late"}))
            .expect_err("successful close is single-use"),
        LifecycleError::DuplicateClose
    );
}
