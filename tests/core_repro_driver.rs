//! Executable driver for the minimal core-blocker repro set.
//!
//! The repro sources in `tests/fixtures/core-repros/` exercise the pd-vm
//! callable-schema corruption documented in
//! `plans/2026-08-13_a3-provider-core-blocker.md`:
//!
//! - `root_splice.rss` (+ `chain_m1.rss` accessor module): passing a
//!   cross-module-accessor ARRAY result into a script function corrupts the
//!   callee's prototype schema at runtime (`TypeMismatch("callable return
//!   schema")` / `TypeMismatch("string")`).
//! - `root_splice2.rss`: the same call with a literal `[]` argument passes —
//!   control isolating the trigger to the cross-module array value.
//! - `hop4_m2.rss` / `hop4_root.rss`: a function with two map parameters that
//!   string-reads its FIRST map parameter and passes the second onward fails.
//! - `hop13_m2.rss` / `hop13_root.rss`: the same layout reading the SECOND map
//!   parameter instead passes — the documented workaround.
//! - `json_enc_e.rss`, `letif_a.rss`, `tailif_m2.rss` (+ `tailif_root.rss`):
//!   compile-time strict-typing limits (annotated lets with unprovable
//!   initializers inside tail-position expression-if branches).
//! - `closure_assign_root.rss` (+ `closure_read_root.rss` control): the
//!   frontend availability pass rejects closures that by-value-use a captured
//!   local (`local 'x' was moved earlier; use 'x.copy()' ...`), so the SSE
//!   delta-aggregation pattern (accumulate into a shared accumulator from an
//!   `http::client::sse` callback) is unexpressible even in a root module.
//!
//! This driver is `#[ignore]`d by default: it documents and re-verifies the
//! core blocker on demand. Run with:
//!
//! ```bash
//! cargo test --test core_repro_driver -- --ignored --nocapture
//! ```
//!
//! It must NOT be un-ignored until the core emits correct callable schemas for
//! every script prototype in non-root modules.

use std::path::PathBuf;

use rustscript_agent::{AgentConfig, AgentRunner};
use rustscript_vm::Value;

fn repro(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/core-repros")
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

/// The core blocker: a cross-module accessor array result passed to a script
/// function fails the runtime callable-schema guard.
#[ignore = "core callable-schema corruption repro (see plans/2026-08-13_a3-provider-core-blocker.md)"]
#[test]
fn root_splice_cross_module_array_corrupts_callee_schema() {
    let error = run_repro("root_splice.rss").expect_err("root_splice must fail");
    assert!(
        error.contains("type mismatch") || error.contains("TypeMismatch"),
        "expected a typed VM schema failure, got: {error}"
    );
}

/// Control: the identical call with a literal array argument succeeds.
#[ignore = "core callable-schema corruption repro (see plans/2026-08-13_a3-provider-core-blocker.md)"]
#[test]
fn root_splice2_literal_array_control_passes() {
    let result = run_repro("root_splice2.rss").expect("root_splice2 must pass");
    assert!(format!("{result:?}").contains("kind"));
}

/// Two-map function reading its FIRST map parameter fails.
#[ignore = "core callable-schema corruption repro (see plans/2026-08-13_a3-provider-core-blocker.md)"]
#[test]
fn hop4_two_map_first_read_fails() {
    let error = run_repro("hop4_root.rss").expect_err("hop4 must fail");
    assert!(
        error.contains("type mismatch") || error.contains("TypeMismatch"),
        "expected a typed VM schema failure, got: {error}"
    );
}

/// Control: the same layout reading the SECOND map parameter passes.
#[ignore = "core callable-schema corruption repro (see plans/2026-08-13_a3-provider-core-blocker.md)"]
#[test]
fn hop13_two_map_second_read_passes() {
    let result = run_repro("hop13_root.rss").expect("hop13 must pass");
    assert!(format!("{result:?}").contains("kind"));
}

/// Compile-time limit: annotated let with json::encode initializer inside an
/// expression-if branch is rejected by strict typing.
#[ignore = "core compile-time limit repro (see plans/2026-08-13_a3-provider-core-blocker.md)"]
#[test]
fn json_enc_e_annotated_let_in_expr_if_branch_is_rejected() {
    let error = run_repro("json_enc_e.rss").expect_err("json_enc_e must fail to compile/run");
    assert!(
        error.contains("concrete compile-time type"),
        "expected a compile rejection, got: {error}"
    );
}

/// Compile-time limit: annotated let with literal initializer inside an
/// expression-if branch is rejected by strict typing.
#[ignore = "core compile-time limit repro (see plans/2026-08-13_a3-provider-core-blocker.md)"]
#[test]
fn letif_a_literal_let_in_expr_if_branch_is_rejected() {
    let error = run_repro("letif_a.rss").expect_err("letif_a must fail to compile/run");
    assert!(
        error.contains("concrete compile-time type"),
        "expected a compile rejection, got: {error}"
    );
}

/// Compile-time limit: annotated let inside a TAIL expression-if branch is
/// rejected by strict typing.
#[ignore = "core compile-time limit repro (see plans/2026-08-13_a3-provider-core-blocker.md)"]
#[test]
fn tailif_m2_annotated_let_in_tail_expr_if_is_rejected() {
    let error = run_repro("tailif_root.rss").expect_err("tailif must fail to compile/run");
    assert!(
        error.contains("concrete compile-time type"),
        "expected a compile rejection, got: {error}"
    );
}

/// The SSE stream blocker, isolated: a closure that by-value-uses a captured
/// local (a move in RustScript's move semantics; closure bodies are single
/// expressions, so the accumulator read is the expressible form of the
/// aggregation pattern) forces the availability pass to move that local, so
/// any later use outside the closure is rejected at compile time with
/// `local '<name>' was moved earlier; use '<name>.copy()' ...`. This is the
/// aggregation pattern `http::client::sse` needs (a callback accumulating
/// deltas into a shared accumulator) and it fails identically in a minimal
/// root module.
#[ignore = "core compile-time limit repro (see plans/2026-08-13_a3-provider-core-blocker.md)"]
#[test]
fn closure_assign_captured_local_then_external_use_is_rejected() {
    let error =
        run_repro("closure_assign_root.rss").expect_err("closure_assign must fail to compile/run");
    assert!(
        error.contains("was moved earlier") && error.contains("state.copy()"),
        "expected the capture-move compile rejection mentioning 'state.copy()', got: {error}"
    );
}

/// Control for the closure blocker: the identical closure shape reading the
/// captured local through `state.copy()` (the exact remedy the error message
/// suggests) leaves the local usable outside, so the probe compiles and runs
/// — the by-value capture is the trigger.
#[ignore = "core compile-time limit repro control (see plans/2026-08-13_a3-provider-core-blocker.md)"]
#[test]
fn closure_read_captured_local_control_passes() {
    let result = run_repro("closure_read_root.rss").expect("closure_read must pass");
    assert!(format!("{result:?}").contains("ok"));
}
