//! A4 durable approval bridge suites.
//!
//! These tests drive the native [`ApprovalBridge`] over the production A2
//! storage program (`rss/storage/main.rss`) with a real SQLite file, verifying
//! the durable approval contract:
//!   - pending approvals are persisted durably;
//!   - an approval resumes the run exactly once (a second resolve never
//!     resumes again);
//!   - a denied/expired approval produces a typed terminal;
//!   - native hard-deny cannot be relaxed by any RSS approval mode.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rustscript_agent::{
    AgentConfig, ApprovalBridge, ApprovalDecision, NativeDenyPolicy, PendingApproval, Resolution,
    RiskClass,
};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

const STORAGE_FILES: &[&str] = &[
    "main.rss",
    "schema.rss",
    "sessions.rss",
    "messages.rss",
    "runs.rss",
    "events.rss",
    "approvals.rss",
    "compactions.rss",
    "jobs.rss",
    "admission.rss",
    "load.rss",
    "existence.rss",
    "gateway.rss",
];

fn storage_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/storage")
}

fn temporary_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the Unix epoch")
        .as_nanos();
    let root = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/mnt/TEMP/rustscript/approval-bridge-tests"))
        .join(format!("{label}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root).expect("temporary root should be created");
    root
}

/// A minimal storage runner wrapper that mirrors the gateway storage command
/// envelope (no direct SQL — it composes the RSS storage program).
struct StorageHarness {
    runner: rustscript_agent::AgentRunner,
    db_name: String,
}

impl StorageHarness {
    fn open(root: &std::path::Path, db_name: &str) -> Self {
        // Verify the storage modules are present (compile guard).
        for file in STORAGE_FILES {
            assert!(
                storage_root().join(file).exists(),
                "missing storage module {file}"
            );
        }
        let runner = rustscript_agent::AgentRunner::from_file(
            storage_root().join("main.rss"),
            AgentConfig::default().with_sqlite_root(root),
        )
        .expect("storage program should compile");
        Self {
            runner,
            db_name: db_name.to_string(),
        }
    }

    fn command(&self, op: &str, payload: JsonValue, now_ms: i64) -> JsonValue {
        let input = Value::map(vec![
            (Value::string("op"), Value::string(op)),
            (Value::string("request_id"), Value::string("req")),
            (
                Value::string("db_path"),
                Value::string(self.db_name.clone()),
            ),
            (Value::string("db_mode"), Value::string("read_write_create")),
            (Value::string("busy_timeout_ms"), Value::Int(1_000)),
            (Value::string("max_rows"), Value::Int(128)),
            (Value::string("max_bytes"), Value::Int(65_536)),
            (Value::string("max_events"), Value::Int(128)),
            (Value::string("max_messages"), Value::Int(128)),
            (Value::string("now_ms"), Value::Int(now_ms)),
            (
                Value::string("payload_json"),
                Value::string(payload.to_string()),
            ),
        ]);
        let result = self
            .runner
            .run_with_context(input)
            .unwrap_or_else(|e| panic!("storage op {op}: {e:?}"));
        let Value::Map(map) = result else {
            panic!("storage op {op}: expected map");
        };
        vm_value_to_json(&Value::Map(map))
    }

    fn migrate(&self) {
        let out = self.command("migrate", json!({}), 1);
        assert_eq!(out["ok"], json!(true), "{out}");
    }

    fn create_session(&self, session_id: &str, now_ms: i64) {
        let out = self.command(
            "session.create",
            json!({
                "id": session_id,
                "profile": "default",
                "platform": "test",
                "account_id": "account-1",
                "chat_id": "chat-1",
                "thread_id": "",
                "user_id": "user-1",
                "generation": 1,
                "system_prompt": "",
                "model": "test-model",
                "provider": "test-provider",
                "toolset_hash": "test-tools",
                "metadata_json": "{}",
                "title": "",
                "end_reason": "",
                "now_ms": now_ms,
            }),
            now_ms,
        );
        assert_eq!(out["ok"], json!(true), "{out}");
    }

    fn create_run(&self, run_id: &str, session_id: &str, now_ms: i64) {
        let out = self.command(
            "run.create",
            json!({
                "id": run_id,
                "session_id": session_id,
                "parent_run_id": "",
                "input_json": "{}",
                "provider": "test-provider",
                "model": "test-model",
                "script_hash": "test-script",
                "idempotency_scope": "api:chat",
                "idempotency_key": run_id,
                "now_ms": now_ms,
            }),
            now_ms,
        );
        assert_eq!(out["ok"], json!(true), "{out}");
    }

    /// Moves a freshly created run (status `queued`) to `waiting_approval`
    /// through the valid `queued -> running -> waiting_approval` path.
    fn admit_to_waiting_approval(&self, run_id: &str, now_ms: i64) {
        self.transition(run_id, "queued", "running", now_ms);
        self.transition(run_id, "running", "waiting_approval", now_ms + 1);
    }

    fn transition(&self, run_id: &str, from: &str, to: &str, now_ms: i64) {
        let out = self.command(
            "run.transition",
            json!({
                "run_id": run_id,
                "from_status": from,
                "to_status": to,
                "error_code": "",
                "error_message": "",
                "recovery_reason": "",
                "now_ms": now_ms,
            }),
            now_ms,
        );
        assert_eq!(out["ok"], json!(true), "{out}");
    }
}

fn vm_value_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Int(v) => json!(v),
        Value::Float(v) => serde_json::Number::from_f64(*v)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Value::Bool(v) => json!(v),
        Value::String(v) => JsonValue::String(v.to_string()),
        Value::Bytes(v) => JsonValue::String(String::from_utf8_lossy(v).into_owned()),
        Value::Array(v) => JsonValue::Array(v.iter().map(vm_value_to_json).collect()),
        Value::Map(e) => JsonValue::Object(
            e.iter()
                .map(|(k, v)| (vm_key_to_string(k), vm_value_to_json(v)))
                .collect(),
        ),
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn vm_key_to_string(value: &Value) -> String {
    match value {
        Value::String(v) => v.to_string(),
        other => vm_value_to_json(other).to_string(),
    }
}

// --------------------------------------------------------------------------
// Native decision: hard-deny overrides every RSS mode.
// --------------------------------------------------------------------------

#[test]
fn native_hard_deny_overrides_every_approval_mode() {
    let root = temporary_root("native-deny");
    let db = root.join("state.db");
    let storage = StorageHarness::open(&root, "state.db");
    storage.migrate();

    let bridge = ApprovalBridge::open(
        &root,
        &db,
        AgentConfig::default(),
        NativeDenyPolicy::new().deny_tool("terminal.run"),
    )
    .expect("bridge should open");

    for action in ["approve", "pending", "deny"] {
        let decision = bridge.decide("terminal.run", RiskClass::Execute, action);
        match decision {
            ApprovalDecision::Denied { native: true, .. } => {}
            other => panic!("expected native deny, got {other:?}"),
        }
    }
    // A non-denied tool is not affected.
    let ok = bridge.decide("file.read", RiskClass::Read, "approve");
    assert_eq!(ok, ApprovalDecision::Approve);
    fs::remove_dir_all(root).ok();
}

#[test]
fn native_deny_by_risk_class_is_authoritative() {
    let root = temporary_root("native-deny-risk");
    let db = root.join("state.db");
    let storage = StorageHarness::open(&root, "state.db");
    storage.migrate();

    let bridge = ApprovalBridge::open(
        &root,
        &db,
        AgentConfig::default(),
        NativeDenyPolicy::new().deny_risk(RiskClass::Execute),
    )
    .expect("bridge should open");

    // Even "all" mode cannot widen a native execute deny.
    let decision = bridge.decide("anything", RiskClass::Execute, "approve");
    match decision {
        ApprovalDecision::Denied { native: true, .. } => {}
        other => panic!("expected native deny, got {other:?}"),
    }
    fs::remove_dir_all(root).ok();
}

// --------------------------------------------------------------------------
// Durable pending + exactly-once resume.
// --------------------------------------------------------------------------

#[test]
fn pending_approval_resumes_exactly_once_after_approval() {
    let root = temporary_root("exactly-once");
    let db = root.join("state.db");
    let storage = StorageHarness::open(&root, "state.db");
    storage.migrate();
    storage.create_session("s1", 10);
    storage.create_run("r1", "s1", 20);
    storage.admit_to_waiting_approval("r1", 25);

    let bridge = ApprovalBridge::open(&root, &db, AgentConfig::default(), NativeDenyPolicy::new())
        .expect("bridge should open");

    let approval_id = bridge
        .request_pending(&PendingApproval {
            run_id: "r1".into(),
            session_id: "s1".into(),
            tool_call_id: "tool-1".into(),
            tool_name: "file.write".into(),
            arguments_json: "{}".into(),
            risk: RiskClass::Write,
            requested_at_ms: 40,
            expires_at_ms: 0,
        })
        .expect("pending approval should persist");

    // First approval resumes exactly once.
    let first = bridge
        .resolve(&approval_id, true, "reviewer", 50)
        .expect("resolve should succeed");
    assert_eq!(
        first,
        Resolution::Resumed {
            approval_id: approval_id.clone()
        }
    );

    // A second resolve must NOT resume again (exactly-once).
    let second = bridge
        .resolve(&approval_id, true, "reviewer", 60)
        .expect("second resolve should succeed");
    assert_eq!(second, Resolution::AlreadyResolved);

    fs::remove_dir_all(root).ok();
}

#[test]
fn denied_approval_produces_typed_terminal_and_never_resumes() {
    let root = temporary_root("denied-terminal");
    let db = root.join("state.db");
    let storage = StorageHarness::open(&root, "state.db");
    storage.migrate();
    storage.create_session("s1", 10);
    storage.create_run("r1", "s1", 20);
    storage.admit_to_waiting_approval("r1", 25);

    let bridge = ApprovalBridge::open(&root, &db, AgentConfig::default(), NativeDenyPolicy::new())
        .expect("bridge should open");

    let approval_id = bridge
        .request_pending(&PendingApproval {
            run_id: "r1".into(),
            session_id: "s1".into(),
            tool_call_id: "tool-1".into(),
            tool_name: "terminal.run".into(),
            arguments_json: "{}".into(),
            risk: RiskClass::Execute,
            requested_at_ms: 40,
            expires_at_ms: 0,
        })
        .expect("pending approval should persist");

    let denied = bridge
        .resolve(&approval_id, false, "reviewer", 50)
        .expect("deny resolve should succeed");
    match denied {
        Resolution::Terminal {
            approval_id: id,
            reason,
        } => {
            assert_eq!(id, approval_id);
            assert_eq!(reason, "approval denied");
        }
        other => panic!("expected terminal on deny, got {other:?}"),
    }

    // A later approve must not resume (already terminal).
    let later = bridge
        .resolve(&approval_id, true, "reviewer", 60)
        .expect("later resolve should not fail");
    assert_eq!(later, Resolution::AlreadyResolved);
    fs::remove_dir_all(root).ok();
}

#[test]
fn expired_pending_approvals_are_swept_to_terminal() {
    let root = temporary_root("expired");
    let db = root.join("state.db");
    let storage = StorageHarness::open(&root, "state.db");
    storage.migrate();
    storage.create_session("s1", 10);
    storage.create_run("r1", "s1", 20);
    storage.admit_to_waiting_approval("r1", 25);

    let bridge = ApprovalBridge::open(&root, &db, AgentConfig::default(), NativeDenyPolicy::new())
        .expect("bridge should open");

    let approval_id = bridge
        .request_pending(&PendingApproval {
            run_id: "r1".into(),
            session_id: "s1".into(),
            tool_call_id: "tool-1".into(),
            tool_name: "file.write".into(),
            arguments_json: "{}".into(),
            risk: RiskClass::Write,
            requested_at_ms: 40,
            expires_at_ms: 1000,
        })
        .expect("pending approval should persist");

    // Expire everything at or before now (now_ms well past the 1000 expiry).
    let expired = bridge.expire(5000).expect("expire sweep should run");
    assert!(expired >= 1, "expected at least one pending expired");

    // Resolving the expired approval must not resume.
    let after = bridge
        .resolve(&approval_id, true, "reviewer", 6000)
        .expect("resolve after expiry should succeed");
    assert_eq!(after, Resolution::AlreadyResolved);
    fs::remove_dir_all(root).ok();
}

#[test]
fn request_pending_for_unknown_run_is_a_typed_failure() {
    let root = temporary_root("orphan");
    let db = root.join("state.db");
    let storage = StorageHarness::open(&root, "state.db");
    storage.migrate();
    storage.create_session("s1", 10);

    let bridge = ApprovalBridge::open(&root, &db, AgentConfig::default(), NativeDenyPolicy::new())
        .expect("bridge should open");

    let err = bridge
        .request_pending(&PendingApproval {
            run_id: "run-ghost".into(),
            session_id: "s1".into(),
            tool_call_id: "tool-1".into(),
            tool_name: "file.write".into(),
            arguments_json: "{}".into(),
            risk: RiskClass::Write,
            requested_at_ms: 40,
            expires_at_ms: 0,
        })
        .expect_err("unknown run must be a typed approval failure");
    assert_eq!(err.code, "run_not_found");
    fs::remove_dir_all(root).ok();
}
