//! A4 focused harness and durable approval suites.
//!
//! These integration tests drive the production RSS harness modules
//! (`rss/harness/registry.rss`, `file.rss`, `patch.rss`, `terminal.rss`,
//! `approval.rss`) through the real `AgentRunner` with a bounded generic
//! `IoPolicy`, and the native `approval_bridge` through the production A2
//! storage program (`rss/storage/main.rss`).
//!
//! The A4 contract: model tool schemas map to *bounded generic capabilities*
//! (file/patch/terminal via generic `io::*` with native roots, write gate,
//! and byte limits; approvals via the durable A2 storage). Native hard-deny is
//! a hard upper bound that RSS approval policy can only narrow, never widen.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rustscript_agent::{AgentConfig, AgentRunner, RunError};
use rustscript_vm::{InvocationError, IoPolicy, Value};
use serde_json::{Value as JsonValue, json};

fn harness_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/harness")
}

fn temporary_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after the Unix epoch")
        .as_nanos();
    let root = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/mnt/TEMP/rustscript/harness-tests"))
        .join(format!("{label}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root).expect("temporary harness root should be created");
    root
}

fn io_config(root: &Path) -> AgentConfig {
    AgentConfig::default().with_io_policy(IoPolicy {
        allowed_roots: vec![root.to_string_lossy().into_owned()],
        allow_write: true,
        allow_process: true,
        max_read_bytes: 64 * 1024,
        max_write_bytes: 64 * 1024,
    })
}

fn harness_runner(name: &str, config: AgentConfig) -> AgentRunner {
    AgentRunner::from_file(harness_root().join(name), config)
        .unwrap_or_else(|e| panic!("compile {name}: {e}"))
}

fn run_module(runner: &AgentRunner, context: Value, label: &str) -> JsonValue {
    let result = runner
        .run_with_context(context)
        .unwrap_or_else(|e| panic!("{label}: {e:?}"));
    let Value::Map(map) = result else {
        panic!("{label}: expected map result");
    };
    vm_value_to_json(&Value::Map(map))
}

/// Asserts the run fails with a typed `InvocationError::Capability` (the
/// native hard boundary), returning the error message.
fn run_module_capability_error(runner: &AgentRunner, context: Value, label: &str) -> String {
    match runner.run_with_context(context) {
        Err(RunError::Invocation(InvocationError::Capability(err))) => err.message().to_string(),
        other => panic!("{label}: expected typed capability failure, got {other:?}"),
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
                .map(|(k, v)| (vm_map_key_to_string(k), vm_value_to_json(v)))
                .collect(),
        ),
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn vm_map_key_to_string(value: &Value) -> String {
    match value {
        Value::String(v) => v.to_string(),
        other => vm_value_to_json(other).to_string(),
    }
}

fn str(value: &str) -> Value {
    Value::string(value)
}

fn owned(value: String) -> Value {
    Value::string(value)
}

// --------------------------------------------------------------------------
// Registry: tool schema -> bounded generic capability + risk class.
// --------------------------------------------------------------------------

#[test]
fn registry_maps_file_tool_to_bounded_io_capability() {
    let root = temporary_root("registry-file");
    let runner = harness_runner("registry.rss", io_config(&root));
    let out = run_module(
        &runner,
        Value::map(vec![
            (str("op"), str("describe")),
            (str("tool_name"), str("file.read")),
        ]),
        "registry file.read",
    );
    assert_eq!(out["ok"], json!(true), "{out}");
    assert_eq!(out["descriptor"]["name"], json!("file.read"));
    assert_eq!(out["descriptor"]["capability"], json!("io.file"));
    assert_eq!(out["descriptor"]["risk_class"], json!("read"));
    assert!(out["descriptor"]["schema"].is_object());
    fs::remove_dir_all(root).ok();
}

#[test]
fn registry_maps_terminal_tool_to_bounded_process_capability() {
    let root = temporary_root("registry-terminal");
    let runner = harness_runner("registry.rss", io_config(&root));
    let out = run_module(
        &runner,
        Value::map(vec![
            (str("op"), str("describe")),
            (str("tool_name"), str("terminal.run")),
        ]),
        "registry terminal.run",
    );
    assert_eq!(out["ok"], json!(true), "{out}");
    assert_eq!(out["descriptor"]["capability"], json!("io.process"));
    assert_eq!(out["descriptor"]["risk_class"], json!("execute"));
    fs::remove_dir_all(root).ok();
}

#[test]
fn registry_rejects_unknown_tool_as_typed_error() {
    let root = temporary_root("registry-unknown");
    let runner = harness_runner("registry.rss", io_config(&root));
    let out = run_module(
        &runner,
        Value::map(vec![
            (str("op"), str("describe")),
            (str("tool_name"), str("does.not.exist")),
        ]),
        "registry unknown",
    );
    assert_eq!(out["ok"], json!(false));
    assert_eq!(out["code"], json!("unknown_tool"));
    fs::remove_dir_all(root).ok();
}

// --------------------------------------------------------------------------
// File: bounded read/write via generic io::*, native root/symlink safety.
// --------------------------------------------------------------------------

#[test]
fn file_write_then_read_within_root_round_trips() {
    let root = temporary_root("file-rw");
    let target = root.join("a.txt");
    let runner = harness_runner("file.rss", io_config(&root));
    let write = run_module(
        &runner,
        Value::map(vec![
            (str("op"), str("write")),
            (str("path"), owned(target.to_string_lossy().into_owned())),
            (str("content"), str("hello harness")),
        ]),
        "file write",
    );
    assert_eq!(write["ok"], json!(true), "{write}");
    let read = run_module(
        &runner,
        Value::map(vec![
            (str("op"), str("read")),
            (str("path"), owned(target.to_string_lossy().into_owned())),
        ]),
        "file read",
    );
    assert_eq!(read["ok"], json!(true), "{read}");
    assert_eq!(read["data"]["text"], json!("hello harness"));
    fs::remove_dir_all(root).ok();
}

#[test]
fn file_read_outside_root_is_denied_by_native_policy() {
    let root = temporary_root("file-outside");
    let outside = std::env::temp_dir().join(format!(
        "harness-outside-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::write(&outside, "secret").expect("seed outside file");
    let runner = harness_runner("file.rss", io_config(&root));
    // The native IoPolicy root check rejects the path with a typed capability
    // failure; the run terminates (no partial read, no fabricated success).
    let msg = run_module_capability_error(
        &runner,
        Value::map(vec![
            (str("op"), str("read")),
            (str("path"), owned(outside.to_string_lossy().into_owned())),
        ]),
        "file read outside root",
    );
    assert!(
        msg.contains("outside the allowed roots"),
        "expected native root-denial message, got: {msg}"
    );
    fs::remove_dir_all(root).ok();
    fs::remove_file(outside).ok();
}

// --------------------------------------------------------------------------
// Patch: atomic read -> apply -> write under the same native root.
// --------------------------------------------------------------------------

#[test]
fn patch_applies_bounded_replacement_and_round_trips() {
    let root = temporary_root("patch");
    let target = root.join("doc.txt");
    fs::write(&target, "the quick brown fox").expect("seed patch target");
    let runner = harness_runner("patch.rss", io_config(&root));
    let out = run_module(
        &runner,
        Value::map(vec![
            (str("op"), str("apply")),
            (str("path"), owned(target.to_string_lossy().into_owned())),
            (str("from"), str("quick brown")),
            (str("to"), str("slow green")),
        ]),
        "patch apply",
    );
    assert_eq!(out["ok"], json!(true), "{out}");
    let final_text = fs::read_to_string(&target).expect("patched file");
    assert_eq!(final_text, "the slow green fox");
    fs::remove_dir_all(root).ok();
}

#[test]
fn patch_without_matching_context_is_typed_failure_and_file_unchanged() {
    let root = temporary_root("patch-miss");
    let target = root.join("doc.txt");
    fs::write(&target, "original body").expect("seed patch target");
    let runner = harness_runner("patch.rss", io_config(&root));
    let out = run_module(
        &runner,
        Value::map(vec![
            (str("op"), str("apply")),
            (str("path"), owned(target.to_string_lossy().into_owned())),
            (str("from"), str("missing context")),
            (str("to"), str("n/a")),
        ]),
        "patch miss",
    );
    assert_eq!(out["ok"], json!(false), "{out}");
    assert_eq!(out["code"], json!("context_not_found"));
    assert_eq!(fs::read_to_string(&target).unwrap(), "original body");
    fs::remove_dir_all(root).ok();
}

// --------------------------------------------------------------------------
// Approval policy: auto/manual/never/all modes + native hard-deny.
// --------------------------------------------------------------------------

#[test]
fn approval_never_denies_execute_and_read() {
    let root = temporary_root("approval-never");
    let runner = harness_runner("approval.rss", io_config(&root));
    for (tool, risk) in [("terminal.run", "execute"), ("file.read", "read")] {
        let out = run_module(
            &runner,
            Value::map(vec![
                (str("op"), str("decide")),
                (str("tool_name"), str(tool)),
                (str("risk_class"), str(risk)),
                (str("approval_mode"), str("never")),
            ]),
            "approval never",
        );
        assert_eq!(out["ok"], json!(true), "{out}");
        assert_eq!(out["decision"]["action"], json!("deny"));
    }
    fs::remove_dir_all(root).ok();
}

#[test]
fn approval_all_approves_everything() {
    let root = temporary_root("approval-all");
    let runner = harness_runner("approval.rss", io_config(&root));
    for (tool, risk) in [
        ("terminal.run", "execute"),
        ("file.write", "write"),
        ("patch.apply", "write"),
    ] {
        let out = run_module(
            &runner,
            Value::map(vec![
                (str("op"), str("decide")),
                (str("tool_name"), str(tool)),
                (str("risk_class"), str(risk)),
                (str("approval_mode"), str("all")),
            ]),
            "approval all",
        );
        assert_eq!(out["ok"], json!(true), "{out}");
        assert_eq!(out["decision"]["action"], json!("approve"));
    }
    fs::remove_dir_all(root).ok();
}

#[test]
fn approval_manual_requires_pending_for_any_risk() {
    let root = temporary_root("approval-manual");
    let runner = harness_runner("approval.rss", io_config(&root));
    for risk in ["read", "write", "execute", "privileged"] {
        let out = run_module(
            &runner,
            Value::map(vec![
                (str("op"), str("decide")),
                (str("tool_name"), str("file.read")),
                (str("risk_class"), str(risk)),
                (str("approval_mode"), str("manual")),
            ]),
            "approval manual",
        );
        assert_eq!(out["ok"], json!(true), "{out}");
        assert_eq!(out["decision"]["action"], json!("pending"));
    }
    fs::remove_dir_all(root).ok();
}

#[test]
fn approval_auto_approves_read_but_requires_pending_for_execute() {
    let root = temporary_root("approval-auto");
    let runner = harness_runner("approval.rss", io_config(&root));
    let read = run_module(
        &runner,
        Value::map(vec![
            (str("op"), str("decide")),
            (str("tool_name"), str("file.read")),
            (str("risk_class"), str("read")),
            (str("approval_mode"), str("auto")),
        ]),
        "approval auto read",
    );
    assert_eq!(read["decision"]["action"], json!("approve"), "{read}");
    let exec = run_module(
        &runner,
        Value::map(vec![
            (str("op"), str("decide")),
            (str("tool_name"), str("terminal.run")),
            (str("risk_class"), str("execute")),
            (str("approval_mode"), str("auto")),
        ]),
        "approval auto execute",
    );
    assert_eq!(exec["decision"]["action"], json!("pending"), "{exec}");
    fs::remove_dir_all(root).ok();
}

#[test]
fn approval_native_hard_deny_cannot_be_relaxed_by_mode() {
    let root = temporary_root("approval-harddeny");
    let runner = harness_runner("approval.rss", io_config(&root));
    // Native hard-deny input (tool-level deny list) overrides every mode,
    // including "all" and "manual".
    for mode in ["all", "manual", "auto", "never"] {
        let out = run_module(
            &runner,
            Value::map(vec![
                (str("op"), str("decide")),
                (str("tool_name"), str("terminal.run")),
                (str("risk_class"), str("execute")),
                (str("approval_mode"), str(mode)),
                (str("native_hard_deny"), Value::Bool(true)),
            ]),
            "approval hard deny",
        );
        assert_eq!(out["ok"], json!(true), "{out}");
        assert_eq!(
            out["decision"]["action"],
            json!("deny"),
            "native hard-deny must not be widened by mode {mode}: {out}"
        );
    }
    fs::remove_dir_all(root).ok();
}

// --------------------------------------------------------------------------
// Terminal: bounded foreground terminal policy. The generic process
// capability (`io::popen`) at the pinned core has NO per-invocation timeout
// and NO argv-array form; the policy reports those boundaries as typed
// capability_unavailable rather than fabricating bounded execution.
// --------------------------------------------------------------------------

#[test]
fn terminal_without_timeout_is_blocked_with_typed_unavailable() {
    let root = temporary_root("terminal-blocked");
    let runner = harness_runner("terminal.rss", io_config(&root));
    // A timeout-less foreground command cannot be bounded by the generic
    // process capability (CORE_BLOCKER): the policy returns a typed
    // capability_unavailable decision, never a fabricated success.
    let out = run_module(
        &runner,
        Value::map(vec![
            (str("op"), str("run")),
            (str("command"), str("echo hi")),
        ]),
        "terminal no-timeout",
    );
    assert_eq!(out["ok"], json!(false), "{out}");
    assert_eq!(out["code"], json!("capability_unavailable"));
    assert_eq!(out["blocker"], json!("process_timeout_unavailable"));
    fs::remove_dir_all(root).ok();
}
