//! Executable driver for the A3 core-blocker repro set.
//!
//! The repro sources in `tests/fixtures/core-repros/` exercise the pd-vm
//! behaviors that blocked the A3 provider adapters before core revision
//! `fd4b570d08d7cc90cc29e3b05df59c9e9bf3b88e` (B1–B4 plus the residual
//! parameter-liveness fix):
//!
//! - `root_splice.rss` (+ `chain_m1.rss` accessor module): passing a
//!   cross-module-accessor ARRAY result into a script function used to
//!   corrupt the callee's prototype schema at runtime
//!   (`TypeMismatch("callable return schema")` / `TypeMismatch("string")`).
//!   B1 (callable schema identity across module merging) fixed it.
//! - `root_splice2.rss`: the identical call with a literal `[]` argument —
//!   control that always passed.
//! - `hop4_m2.rss` / `hop4_root.rss`: a function with two map parameters
//!   that string-reads its FIRST map parameter and passes the second onward
//!   used to fail; `hop13_m2.rss` / `hop13_root.rss` (reading the SECOND map
//!   parameter) was the documented workaround. B1 fixed both layouts.
//! - `json_enc_e.rss`, `letif_a.rss`, `tailif_m2.rss` (+ `tailif_root.rss`):
//!   annotated lets with unprovable initializers inside tail-position
//!   expression-if branches were rejected by strict typing. B2 (branch-aware
//!   expression-block type collection) fixed them.
//! - `closure_assign_root.rss`: the frontend availability pass used to
//!   reject closures that by-value-use a captured local
//!   (`local 'state' was moved earlier; use 'state.copy()' ...`). B3 made
//!   MUTATION of a captured mutable local select `BorrowMut` (shared capture
//!   cells), which is what the SSE delta-aggregation pattern needs; a pure
//!   by-value use of a movable value remains a move, so this probe stays a
//!   NEGATIVE control (it must still be rejected).
//! - `closure_read_root.rss`: the `.copy()` capture control — always passed.
//!
//! The residual slot-aliasing defect reported at d8cf291 (plan §11a) is
//! fixed by `fd4b570` (`fix(compiler): keep parameters live for the whole
//! body`): the liveness allocator now seeds parameter slots into the body
//! live-out and re-marks them after every statement, so a local defined
//! after body entry can no longer be colored onto a parameter slot. The
//! committed probe pair `param_aliasing_root.rss` /
//! `param_aliasing_ctrl_root.rss` guards the fix: the identical parse
//! chain now passes from BOTH the two-parameter caller (control) and the
//! five-parameter caller (the former `type mismatch: expected string`
//! trigger), both run by default.
//!
//! This driver runs by default as the agent-side regression guard for the
//! B1–B4 consume (see `plans/2026-08-14_a3-rustscript-core-unblock.md`).
//! The native core tests for the same behaviors live in the core repository.
//!
//! ```bash
//! cargo test --test core_repro_driver
//! ```

use std::path::PathBuf;

use rustscript_agent::{AgentConfig, AgentRunner};
use rustscript_vm::Value;

fn repro(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/core-repros")
        .join(name)
}

fn a6_repro(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/a6-core-repros")
        .join(name)
}

fn run_repro(name: &str) -> Result<Value, String> {
    let config = AgentConfig::for_hosts(["127.0.0.1"]);
    let runner = AgentRunner::from_file(repro(name), config).map_err(|error| error.to_string())?;
    let context = Value::map(vec![
        (
            Value::string("request"),
            Value::map(vec![
                (
                    Value::string("tools"),
                    Value::Array(std::sync::Arc::new(vec![Value::map(vec![
                        (Value::string("name"), Value::string("read_file")),
                        (Value::string("description"), Value::string("read")),
                        (
                            Value::string("schema_json"),
                            Value::string("{\"type\":\"object\"}"),
                        ),
                    ])])),
                ),
                (Value::string("model"), Value::string("m")),
                (
                    Value::string("messages"),
                    Value::Array(std::sync::Arc::new(vec![])),
                ),
            ]),
        ),
        (
            Value::string("profile"),
            Value::map(vec![
                (
                    Value::string("base_url"),
                    Value::string("http://127.0.0.1:1"),
                ),
                (Value::string("api_key"), Value::string("k")),
                (Value::string("provider"), Value::string("p")),
            ]),
        ),
        (Value::string("model"), Value::string("m")),
    ]);
    runner
        .run_with_context(context)
        .map_err(|error| error.to_string())
}

/// B1: a cross-module accessor array result passed to a script function now
/// keeps the callee's schema intact (was `TypeMismatch("string")`).
#[test]
fn root_splice_cross_module_array_preserves_callee_schema() {
    let result = run_repro("root_splice.rss").expect("root_splice must run");
    assert!(
        format!("{result:?}").contains("kind"),
        "expected the probe result, got: {result:?}"
    );
}

/// Control: the identical call with a literal array argument.
#[test]
fn root_splice2_literal_array_control_passes() {
    let result = run_repro("root_splice2.rss").expect("root_splice2 must pass");
    assert!(format!("{result:?}").contains("kind"));
}

/// B1: the two-map function reading its FIRST map parameter now passes (the
/// former `hop4` corruption trigger).
#[test]
fn hop4_two_map_first_read_passes() {
    let result = run_repro("hop4_root.rss").expect("hop4 must pass");
    assert!(format!("{result:?}").contains("kind"));
}

/// Control: the same layout reading the SECOND map parameter.
#[test]
fn hop13_two_map_second_read_passes() {
    let result = run_repro("hop13_root.rss").expect("hop13 must pass");
    assert!(format!("{result:?}").contains("kind"));
}

/// B2: annotated let with json::encode initializer inside an expression-if
/// branch now compiles and runs.
#[test]
fn json_enc_e_annotated_let_in_expr_if_branch_compiles() {
    let result = run_repro("json_enc_e.rss").expect("json_enc_e must compile/run");
    assert!(
        format!("{result:?}").contains("text"),
        "expected the branch value, got: {result:?}"
    );
}

/// B2: annotated let with literal initializer inside an expression-if branch
/// now compiles and runs.
#[test]
fn letif_a_literal_let_in_expr_if_branch_compiles() {
    let result = run_repro("letif_a.rss").expect("letif_a must compile/run");
    assert!(
        format!("{result:?}").contains("literal"),
        "expected the branch value, got: {result:?}"
    );
}

/// B2: annotated let inside a TAIL expression-if branch now compiles.
#[test]
fn tailif_m2_annotated_let_in_tail_expr_if_compiles() {
    let result = run_repro("tailif_root.rss").expect("tailif must compile/run");
    assert!(format!("{result:?}").contains("kind"));
}

/// B3 negative control: a closure that by-value-uses a captured movable
/// local still forces a move, so the later external use must still be
/// rejected at compile time with the `state.copy()` remedy. B3 shares
/// MUTATION captures (`BorrowMut` cells); pure by-value reads keep their
/// move semantics.
#[test]
fn closure_assign_by_value_capture_still_rejects_external_use() {
    let error =
        run_repro("closure_assign_root.rss").expect_err("closure_assign must fail to compile/run");
    assert!(
        error.contains("was moved earlier") && error.contains("state.copy()"),
        "expected the capture-move compile rejection mentioning 'state.copy()', got: {error}"
    );
}

/// Control for the closure semantics: reading the captured local through
/// `state.copy()` leaves the local usable outside, so the probe runs.
#[test]
fn closure_read_captured_local_control_passes() {
    let result = run_repro("closure_read_root.rss").expect("closure_read must pass");
    assert!(format!("{result:?}").contains("ok"));
}

/// fd4b570 (plan §11a fix): the five-parameter caller calling the shared
/// parse chain through an expression-if now passes the VM callable-schema
/// check. Before the fix (d8cf291) the local-slot colorer could alias a
/// parameter slot with a local not live at body entry and the call failed
/// with `type mismatch: expected string` although every value was
/// correctly typed; the identical chain from a two-parameter caller
/// (`param_aliasing_ctrl_root.rss`) always passed. Both probes run by
/// default as the regression guard for the fd4b570 parameter-liveness fix.
#[test]
fn param_aliasing_five_param_caller_passes_vm_schema_check() {
    let result = run_repro("param_aliasing_root.rss").expect("param_aliasing must pass");
    assert!(
        format!("{result:?}").contains("ok"),
        "expected the parsed response, got: {result:?}"
    );
}

/// Control for the fd4b570 repro: the identical parse chain and canned
/// body called from a two-parameter caller.
#[test]
fn param_aliasing_two_param_caller_control_passes() {
    let result = run_repro("param_aliasing_ctrl_root.rss").expect("control must pass");
    assert!(
        format!("{result:?}").contains("ok"),
        "expected the control result, got: {result:?}"
    );
}

/// A6 narrowed CORE_BLOCKER: the RustScript LANGUAGE (synchronous,
/// single-threaded) and the restricted inline registry expose no
/// script-internal generic task surface, so a policy script cannot itself
/// call `task::spawn`. The fixture is scoped to that ONE actual surface
/// (`task::spawn` only — no await_all/await/cancel is claimed), and it is
/// wired into CI here so the narrowing stays honest.
#[test]
fn a6_no_task_script_cannot_call_task_spawn() {
    let config = AgentConfig::default();
    let error = AgentRunner::from_file(a6_repro("no_task_child_capability.rss"), config)
        .expect_err("a policy script must not be able to call task::spawn");
    assert!(
        error.to_string().contains("task::spawn"),
        "expected the task::spawn unknown-namespace rejection, got: {error}"
    );
}
