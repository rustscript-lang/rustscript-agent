# A3 RustScript Core Unblock Implementation Plan

> **For Hermes:** Execute task-by-task with strict RED-GREEN-REFACTOR discipline. Keep each blocker in a separate commit and review boundary. Do not weaken VM schema guards or rewrite provider fixtures to hide a core failure.

**Date:** 2026-08-14

**Status:** B1–B4 implemented, reviewed, and published in the core repository; the residual slot-aliasing defect (plan §11a) is fixed by core revision `fd4b570d08d7cc90cc29e3b05df59c9e9bf3b88e`, which the agent pins and consumes. All Definition-of-done items are met.

**Implementation base:** `rustscript-lang/rustscript@fd4b570d08d7cc90cc29e3b05df59c9e9bf3b88e` (B1 `fe890a0`, B2 `e2b50cb`, B3 `b9b66d8`, B4 `d8cf291`, residual fix `fd4b570`, on top of `06b37fd…` `origin/plan/callable-stream-integration`)

**Consumer baseline:** `rustscript-agent@946e30708b1312725ebeab0e0018c39db416518c`, with `pd-vm` pinned by HTTPS Git URL and full revision `fd4b570d08d7cc90cc29e3b05df59c9e9bf3b88e`

**Goal:** Remove the four RustScript core constraints that prevent A3 provider adapters from using correct cross-module callable contracts, typed locals in tail expression-if branches, shared mutable closure captures for SSE aggregation, and structured JSON construction from runtime maps.

**Architecture:** Preserve strict compile-time typing and runtime callable validation. Repair metadata at the compiler/linker source, make expression-block type collection branch-aware, align availability capture effects with the runtime `BorrowMut` capture model, and admit runtime maps at `json::encode` only under the runtime encoder's existing string-key and recursively encodable-value checks.

**Tech stack:** Rust 2024, RustScript parser/IR/linker/type inference/lifetime/codegen, interpreter callable environments, `serde_json`, VMBC/no-std compatibility, and `rustscript-agent` provider integration tests.

---

## 1. Scope and evidence

### 1.1 Core blocker matrix

| ID | Current failure | Required core result | Primary core ownership |
|---|---|---|---|
| B1 | Valid calls from merged module graphs fail with `TypeMismatch("callable argument schema")`, `TypeMismatch("callable return schema")`, or `TypeMismatch("string")` | Every `CallScript`/callable target retains the declared parameter order and result `TypeSchema::Callable` after module registration, index remapping, specialization, and VMBC round-trip | `src/compiler/linker.rs`, `src/compiler/codegen.rs`; VM guard remains unchanged |
| B2 | An annotated `let` inside a block used by a tail-position expression-if is reported as lacking a concrete compile-time type | Branch-local declarations are collected with the branch's refined state and are visible to strict slot validation without leaking beyond the block | `src/compiler/typing/collect.rs`, `src/compiler/typing/context.rs`, `src/compiler/typing/validate.rs`, `src/compiler/pipeline.rs` only if source-site traversal is incomplete |
| B3 | An SSE accumulator captured by a closure cannot be mutated and then read outside the closure; availability reports `E_LOCAL_MOVED` | Assignment to a captured mutable local selects `BorrowMut`, shares one capture cell with the outer local, and leaves later outer reads legal; pure by-value reads keep existing move semantics | `src/compiler/lifetime/availability.rs`, `src/compiler/lifetime/availability/captures.rs`, existing capture-cell paths in `src/vm/mod.rs` |
| B4 | Strict validation rejects `TypeSchema::Map(_)` at `json::encode`, forcing marker-based JSON splicing | String-key runtime maps can be encoded recursively; non-string keys and unsupported nested values fail through precise runtime errors | `src/compiler/typing/validate.rs`, existing runtime behavior in `src/builtins/runtime/json.rs` |

### 1.2 Correction to the JSON statement

Struct-shaped JSON encoding is already supported and must remain green. The existing core test `json encode decode builtins are supported` encodes a nested struct successfully. The missing capability is **generic/runtime map encoding at the compile-time boundary**, not struct encoding.

B4 must therefore:

- retain struct/object encoding behavior;
- allow `map` and nested map values to reach the existing runtime encoder;
- keep `json_encode map keys must be strings` for non-string keys;
- keep bytes, callable, NaN, and infinity failures precise;
- avoid any guarantee about serialized object key order; tests compare parsed JSON objects.

### 1.3 Consumer evidence

Minimal sources currently live in:

- `rustscript-agent/tests/fixtures/core-repros/root_splice.rss`
- `rustscript-agent/tests/fixtures/core-repros/root_splice2.rss`
- `rustscript-agent/tests/fixtures/core-repros/hop4_root.rss`
- `rustscript-agent/tests/fixtures/core-repros/hop4_m2.rss`
- `rustscript-agent/tests/fixtures/core-repros/hop13_root.rss`
- `rustscript-agent/tests/fixtures/core-repros/hop13_m2.rss`
- `rustscript-agent/tests/fixtures/core-repros/letif_a.rss`
- `rustscript-agent/tests/fixtures/core-repros/json_enc_e.rss`
- `rustscript-agent/tests/fixtures/core-repros/tailif_root.rss`
- `rustscript-agent/tests/fixtures/core-repros/tailif_m2.rss`
- `rustscript-agent/tests/fixtures/core-repros/closure_assign_root.rss`
- `rustscript-agent/tests/fixtures/core-repros/closure_read_root.rss`
- shared accessor module `rustscript-agent/tests/fixtures/core-repros/chain_m1.rss`

`rustscript-agent/tests/core_repro_driver.rs` currently verifies five failing behaviors and four controls. Copy the behavior into native core tests; do not make core tests depend on the agent repository.

---

## 2. Non-goals and invariants

- Do not remove or bypass `src/vm/mod.rs::enter_script_frame` argument-schema checks.
- Do not change a mismatching declared schema to `Unknown` as a compatibility escape.
- Do not globally disable strict RustScript type resolution.
- Do not make every closure capture a copy or shared borrow.
- Do not make a pure by-value use of a movable value reusable after capture; `.copy()` and explicit borrow behavior remain meaningful.
- Do not accept callable values, bytes, NaN, infinity, or non-string map keys in JSON.
- Do not change VM opcodes, opcode numbers, callable wire format, or VMBC version unless a RED round-trip test proves metadata cannot be represented by the existing format. `TypeSchema::Callable` and capture modes are already serialized.
- Do not implement agent tool harness, approval policy, parallel tasks, structured-task supervision, or subagents.
- Do not implement the OpenAI Responses or Anthropic adapters in the core repository.
- Do not use provider source rewrites, private builtins, or fixture weakening as substitutes for core fixes.

---

## 3. Workspace and branch setup

All implementation work, target output, temporary files, and logs must remain below `/mnt/TEMP/rustscript/`.

```bash
cd /mnt/TEMP/rustscript/agent-roadmap/rustscript
git status --short --branch
test "$(git rev-parse HEAD)" = "06b37fd155be2b81ba4b41dbb6514e7b283f4f10"

git worktree add \
  /mnt/TEMP/rustscript/a3-core-unblock \
  -b fix/a3-core-unblock \
  06b37fd155be2b81ba4b41dbb6514e7b283f4f10

export CARGO_TARGET_DIR=/mnt/TEMP/rustscript/a3-core-target
export TMPDIR=/mnt/TEMP/rustscript/a3-core-tmp
mkdir -p "$CARGO_TARGET_DIR" "$TMPDIR"
cd /mnt/TEMP/rustscript/a3-core-unblock
```

Baseline gates:

```bash
cargo fmt --all -- --check
cargo test --locked --test compiler_tests
cargo test --locked --test vm_tests call_script
cargo test --locked --test wire_tests callable
cargo test --locked -p pd-vm-nostd
```

Record the baseline counts before changing production code. A baseline failure must be classified before implementation begins.

---

## 4. Task 0 — Port the A3 repros into native core tests

**Objective:** Establish deterministic RED tests in the core repository and distinguish compile metadata defects from runtime guard defects.

**Files:**

- Modify: `tests/compiler/module_import_tests.rs`
- Modify: `tests/compiler/compiler_rustscript_tests.rs`
- Modify: `tests/vm/call_script_tests.rs` only when a runtime-only assertion is needed
- Optional fixture directory: `tests/fixtures/a3_core/` if inline module overrides become unreadable

### Step 1: Add a module-test helper

Reuse `CompileSourceFileOptions::with_module_override_source` and the existing temporary-module helpers. The test helper must:

1. compile a root source and one or more `self::...` module overrides;
2. expose `compiled.program.callable_prototypes` and decoded `CallScript` targets;
3. optionally execute the program through `Vm`;
4. clean its temporary root on every success/error path.

Prefer inline source overrides for two-file cases. Use fixture files only for the full multi-hop graph.

### Step 2: Add B1 RED tests

Add these focused tests:

- `module_callable_schema_preserves_cross_module_array_argument`
  - port `root_splice.rss` plus `chain_m1.rss`;
  - assert the target callable schema is `fn(string, array) -> string` before execution;
  - execute and expect `{ kind: "ok" }`.
- `module_callable_schema_literal_array_control`
  - port `root_splice2.rss`;
  - retain as a green control.
- `module_callable_schema_preserves_first_map_parameter`
  - port the `hop4` behavior;
  - assert all declared map parameters remain in source order;
  - execute successfully.
- `module_callable_schema_second_parameter_control`
  - port the `hop13` behavior and retain it as a control.
- `callable_schema_survives_vmbc_round_trip_for_merged_modules`
  - encode/decode the compiled program;
  - compare every script prototype's schema before and after the round-trip;
  - execute the decoded program.

Expected RED on the base revision: metadata assertion and/or execution fails with the existing type-mismatch signatures. If prototype metadata is already correct before VM entry, add a narrow runtime trace assertion to identify the wrong prototype ID used by the call site.

### Step 3: Add B2 RED tests

In `tests/compiler/compiler_rustscript_tests.rs`, add:

- `tail_expression_if_collects_annotated_literal_local`
- `tail_expression_if_collects_json_encode_local`
- `tail_expression_if_collects_module_call_local`
- `non_tail_expression_if_annotated_local_control`
- `tail_expression_if_unannotated_local_control`

Each positive case must compile and execute. The tests must also check the final value, so a parser-only acceptance that lowers incorrectly cannot pass.

Expected RED: `CompileError::StrictTypingRequired` with `does not resolve to a concrete compile-time type in RustScript`.

### Step 4: Add B3 RED tests

Add a real mutation case rather than the current read-only approximation:

```rss
pub fn run() -> string {
    let mut state: string = "";
    let sink = |delta| {
        state = state + delta;
        { action: "continue" }
    };
    let _ = sink("a");
    let _ = sink("b");
    state
}
```

Tests:

- `closure_mut_capture_updates_outer_local`
- `closure_mut_capture_survives_multiple_calls`
- `closure_mut_capture_is_visible_after_callback_returns`
- `closure_by_value_move_still_rejects_later_outer_use`
- `closure_copy_capture_keeps_source_reusable`
- `closure_shared_capture_vmbc_round_trip`

Expected RED: availability rejects the mutation case with `E_LOCAL_MOVED`, or execution does not expose the updated cell to the outer local. The pure by-value negative control must remain green as a rejection test.

### Step 5: Add B4 RED tests

Add:

- `json_encode_accepts_string_key_runtime_map`
- `json_encode_accepts_nested_runtime_maps_and_arrays`
- `json_encode_preserves_struct_support`
- `json_encode_runtime_map_rejects_non_string_key`
- `json_encode_runtime_map_rejects_nested_bytes`
- `json_encode_runtime_map_rejects_nested_callable`

For success cases, decode the generated text and compare semantic JSON. Do not compare object key order.

Expected RED: map success cases fail at compile time with `requires object/struct-shaped data`. Negative runtime cases may already pass as rejection controls.

### Step 6: Run all RED groups separately

```bash
cargo test --locked --test compiler_tests module_callable_schema -- --nocapture
cargo test --locked --test compiler_tests tail_expression_if -- --nocapture
cargo test --locked --test compiler_tests closure_mut_capture -- --nocapture
cargo test --locked --test compiler_tests json_encode_ -- --nocapture
```

Every command must select at least one test. Preserve the exact failure signature in the commit message or review notes.

**Commit boundary:** tests only.

```bash
git add tests/compiler/ tests/vm/
git commit -m "test(a3): reproduce provider core blockers"
```

---

## 5. Task 1 — Repair callable schema identity across module merging

**Objective:** Ensure source-declared callable schemas survive module registration, function/local index remapping, specialization, code generation, VMBC, and VM entry.

**Files:**

- Modify as proved by RED localization: `src/compiler/linker.rs`
- Modify as proved by RED localization: `src/compiler/codegen.rs`
- Test: `tests/compiler/module_import_tests.rs`
- Test: `tests/compiler/compiler_common_tests.rs`
- Test: `tests/vm/call_script_tests.rs`
- Test: `tests/wire/wire_tests.rs` or the existing callable VMBC module

### Step 1: Inspect the compile-time chain

For every failing call, record:

1. source `FunctionDecl.index`, `arg_schemas`, `return_schema`, and `type_params`;
2. merged flat index from `linker::register_unit_functions`;
3. remapped `Expr::Call`/`Expr::ModuleCall` target from `remap_expr_indices`;
4. prototype ID and schema produced by `codegen::prepare_named_callables`;
5. specialized prototype selected by `ensure_direct_specialized_prototype` when type args exist;
6. prototype ID encoded in the `CallScript` operand;
7. VM entry prototype and operand value types.

The first point where expected metadata diverges owns the fix.

### Step 2: Fix linker metadata if the flat declaration is wrong

In `src/compiler/linker.rs`, ensure both host and script branches of `register_unit_functions` copy and preserve:

- `args` and source order;
- `arg_schemas` and source order;
- `return_schema`;
- `type_params`;
- symbol-to-flat-index identity;
- `function_sources` for diagnostics.

Do not derive schema fields from argument values or from another declaration that happens to share an index.

Add an invariant after merge in test builds: every merged implementation index has exactly one declaration with matching arity.

### Step 3: Fix codegen identity if declarations are correct but prototypes are wrong

In `src/compiler/codegen.rs`:

- make `prepare_named_callables` construct the base `TypeSchema::Callable` from the declaration mapped to the exact merged function index;
- keep `instantiated_callable_schema` a pure substitution of that declaration;
- keep `ensure_direct_specialized_prototype` keyed by `(function index, complete type args)`;
- ensure `CallScript` uses the intended base/specialized prototype ID;
- ensure hidden callable slots and direct-only call paths share the same schema source.

Do not mutate a shared base prototype according to one call site's inferred values.

### Step 4: Keep VM validation intact

`src/vm/mod.rs::enter_script_frame` remains the runtime backstop. Only improve its diagnostic payload if the RED test cannot identify expected vs actual schema without it. Any diagnostic change must preserve the existing `VmError` category.

### Step 5: Prove GREEN and regression coverage

```bash
cargo test --locked --test compiler_tests module_callable_schema -- --nocapture
cargo test --locked --test compiler_tests direct_script_call_generic -- --nocapture
cargo test --locked --test compiler_tests module_import -- --nocapture
cargo test --locked --test vm_tests call_script -- --nocapture
cargo test --locked --test wire_tests callable -- --nocapture
```

Acceptance:

- root and non-root layouts produce identical callable schemas;
- first/second parameter order does not affect behavior;
- accessor-returned and literal arrays behave identically;
- generic specializations still reject wrong argument types;
- VMBC round-trip preserves callable schemas;
- no schema is weakened to `Unknown` to make execution pass.

**Commit boundary:** B1 only.

```bash
git add src/compiler/linker.rs src/compiler/codegen.rs src/vm/mod.rs \
        tests/compiler/ tests/vm/ tests/wire/
git commit -m "fix(compiler): preserve callable schemas across modules"
```

---

## 6. Task 2 — Make tail expression-if block typing branch-aware

**Objective:** Record typed locals declared inside `Expr::Block` branches and validate each trailing expression under the state produced by that branch.

**Files:**

- Modify: `src/compiler/typing/collect.rs`
- Modify: `src/compiler/typing/context.rs`
- Modify if validation traversal diverges: `src/compiler/typing/validate.rs`
- Modify only if source-site collection omits expression blocks: `src/compiler/pipeline.rs`
- Test: `tests/compiler/compiler_rustscript_tests.rs`
- Test: `tests/compiler/diagnostics_tests.rs`

### Step 1: Preserve parser behavior

`parser::parse_if_expr_branch` already wraps branch statements and the trailing value in `Expr::Block`. Do not add a second AST form or lower branch statements into outer scope.

Add a parser/IR assertion only if needed to prove:

```text
Expr::IfElse
  then_expr = Expr::Block { stmts: [...], expr: ... }
  else_expr = Expr::Block { stmts: [...], expr: ... }
```

### Step 2: Repair collection state

In `typing/collect.rs`:

- derive `then_state` and `else_state` with `refine_state_for_condition`;
- recurse into each branch using its own state;
- for `Expr::Block`, apply statements before collecting the trailing expression;
- record `local_types`, `local_schemas`, labels, optional slots, and callable slots for branch-local declarations;
- do not merge branch-only bindings into outer state.

### Step 3: Align schema/type inference

In `typing/context.rs`, make `Expr::IfElse` inference:

- evaluate branch schemas/types under refined branch states;
- let each `Expr::Block` apply its local statements before inferring the trailing expression;
- merge only branch result types/schemas;
- preserve the existing incompatible-branch diagnostic.

Avoid cache entries keyed only by expression identity when the state differs between branches.

### Step 4: Align strict validation and diagnostics

In `typing/validate.rs`, validate each branch under the same refined state used by inference.

In `pipeline.rs`, change `collect_strict_slot_sites` or expression-source traversal only if branch-local slots are correctly inferred but diagnostics cannot find their source. Keep `E_STRICT_UNKNOWN_TYPE` for genuinely unresolved bindings.

### Step 5: Prove GREEN

```bash
cargo test --locked --test compiler_tests tail_expression_if -- --nocapture
cargo test --locked --test compiler_tests if_else -- --nocapture
cargo test --locked --test compiler_tests strict -- --nocapture
cargo test --locked --test compiler_tests diagnostics -- --nocapture
```

Acceptance:

- literal, `json::encode`, and module-call initializers compile in tail branches;
- typed and untyped controls execute to the same value;
- block-local names remain unavailable outside their branch;
- incompatible branch results still fail;
- genuinely unknown declarations still produce `E_STRICT_UNKNOWN_TYPE` with source path and line.

**Commit boundary:** B2 only.

```bash
git add src/compiler/typing/ src/compiler/pipeline.rs tests/compiler/
git commit -m "fix(typing): collect tail expression branch locals"
```

---

## 7. Task 3 — Align closure mutation availability with shared capture cells

**Objective:** Make the availability pass agree with the runtime capture-mode calculation for mutation captures.

**Files:**

- Modify: `src/compiler/lifetime/availability.rs`
- Modify: `src/compiler/lifetime/availability/captures.rs`
- Modify only if a runtime cell defect is proved: `src/vm/mod.rs`
- Test: `tests/compiler/compiler_rustscript_tests.rs`
- Test: `tests/vm/call_script_tests.rs`
- Test: `tests/wire/wire_tests.rs`

### Step 1: Define the semantic split

Required modes:

- `Copy`: explicit `.copy()` or copyable values where current rules allow copying;
- `Borrow`: explicit shared read capture;
- `BorrowMut`: assignment/mutation of a captured mutable binding;
- `Move`: pure by-value use of a movable binding when no copy/borrow was requested.

A mutation capture must not also be marked moved merely because its RHS reads the same captured slot.

### Step 2: Reuse one capture-mode classifier

The public codegen wrappers in `availability.rs` already use `runtime_*_capture_mode_for_slot`, where assignment under `Copy` context upgrades to `BorrowMut`. The availability effect path currently computes move-oriented modes separately.

Refactor so availability and codegen consume one classifier result for each `(closure/function, captured slot)`. Keep any stricter body-use checks separate from source-binding mode selection.

`apply_capture_binding_effect` must:

- mark the source moved only for `CaptureBindingMode::Move`;
- leave source availability intact for `Borrow` and `BorrowMut`;
- preserve collection alias and partial-move checks;
- reject `BorrowMut` from an immutable source with the existing mutability diagnostic.

### Step 3: Verify existing runtime shared-cell behavior

The VM already creates/reuses `capture_cells` for `Borrow` and `BorrowMut`, and loads captured/outer values through those cells. Add tests proving:

- closure assignment updates the cell;
- later outer reads load the cell value;
- repeated closure calls reuse the same cell;
- two closures borrowing the same outer mutable local observe one value;
- reset/drop releases cells without leaking state to another invocation.

Modify `src/vm/mod.rs` only if these tests expose an actual cell synchronization defect.

### Step 4: Preserve negative ownership tests

Keep these failures:

- pure by-value capture followed by outer use;
- mutation capture from immutable binding;
- use after a true move inside the closure;
- partial-field move before capture;
- conflicting mutable capture aliases if current ownership policy rejects them.

### Step 5: Prove GREEN and serialization parity

```bash
cargo test --locked --test compiler_tests closure_mut_capture -- --nocapture
cargo test --locked --test compiler_tests closure_capture -- --nocapture
cargo test --locked --test vm_tests capture -- --nocapture
cargo test --locked --test wire_tests capture -- --nocapture
cargo test --locked -p pd-vm-nostd capture -- --nocapture
```

Acceptance:

- SSE accumulator pattern compiles and returns the accumulated value;
- `CaptureBindingMode::BorrowMut` is visible on the callable prototype;
- VMBC round-trip preserves `BorrowMut`;
- pure by-value move semantics remain enforced.

**Commit boundary:** B3 only.

```bash
git add src/compiler/lifetime/ src/vm/mod.rs tests/compiler/ tests/vm/ tests/wire/ pd-vm-nostd/
git commit -m "fix(ownership): share mutable closure captures"
```

---

## 8. Task 4 — Admit runtime maps at `json::encode`

**Objective:** Remove the compile-time map-only prohibition while retaining recursive runtime validation.

**Files:**

- Modify: `src/compiler/typing/validate.rs`
- Modify only for better path diagnostics: `src/builtins/runtime/json.rs`
- Test: `tests/compiler/compiler_rustscript_tests.rs`
- Test: `tests/builtins/stdlib_tests.rs` or the existing JSON runtime test module

### Step 1: Change the schema policy

In `validate_json_schema`:

- keep `Object` and resolved `Named` recursion unchanged;
- allow `TypeSchema::Map(inner)`;
- if `inner` is concrete, reject statically unsupported value schemas such as bytes/callable;
- if `inner` is `Unknown`, allow compilation and defer recursive checks to runtime;
- keep top-level optional handling consistent with the existing API contract.

Map key types are not represented in `TypeSchema::Map`, so key legality cannot be proved statically.

### Step 2: Preserve runtime enforcement

`src/builtins/runtime/json.rs::vm_to_json_value` already:

- accepts string-key maps;
- rejects non-string keys;
- recurses through arrays/maps;
- rejects bytes and callable values;
- rejects NaN/infinity.

Retain this behavior. Improve errors with a JSON path only if tests require identifying a nested failure. Do not stringify non-string keys.

### Step 3: Add structured provider-shape coverage

Test a runtime map shaped like a provider request:

```rss
let request: map = {
    "model": "test-model",
    "stream": false,
    "messages": [
        { "role": "user", "content": [{ "type": "text", "text": "hello" }] }
    ],
    "tools": [
        { "type": "function", "function": { "name": "read_file", "parameters": { "type": "object" } } }
    ]
};
json::encode(request)
```

Parse the result and compare semantic fields. This is the capability needed to remove marker-based splicing from the agent adapter later.

### Step 4: Prove GREEN

```bash
cargo test --locked --test compiler_tests json_encode_ -- --nocapture
cargo test --locked --test builtins_tests json -- --nocapture
cargo test --locked --test compiler_tests rustscript_builtin_runtime_cases_work -- --nocapture
```

Acceptance:

- existing nested struct encode/decode remains green;
- runtime string-key maps and nested maps encode successfully;
- non-string keys fail with `json_encode map keys must be strings`;
- unsupported nested values fail without panic;
- JSON equality tests do not depend on object key order.

**Commit boundary:** B4 only.

```bash
git add src/compiler/typing/validate.rs src/builtins/runtime/json.rs \
        tests/compiler/ tests/builtins/
git commit -m "feat(json): encode runtime string-key maps"
```

---

## 9. Task 5 — Core integration and regression gates

**Objective:** Verify all four fixes together across compiler, VM, wire format, JIT/AOT-enabled workspace targets, and no-std.

### Focused gates

```bash
cargo fmt --all -- --check
cargo test --locked --test compiler_tests module_callable_schema -- --nocapture
cargo test --locked --test compiler_tests tail_expression_if -- --nocapture
cargo test --locked --test compiler_tests closure_mut_capture -- --nocapture
cargo test --locked --test compiler_tests json_encode_ -- --nocapture
cargo test --locked --test vm_tests call_script -- --nocapture
cargo test --locked --test wire_tests callable -- --nocapture
cargo test --locked --test wire_tests capture -- --nocapture
```

### Backend and workspace gates

```bash
cargo test --locked -p pd-vm-nostd
cargo test --locked -p pd-vm-wasm
cargo test --locked --workspace --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
git diff --check
```

If a filter selects zero tests, stop and correct the target/filter before continuing.

### Integration acceptance

- all new RED tests are GREEN;
- all original workspace tests remain GREEN;
- no ignored core regression test is added;
- no VM schema guard is removed;
- no `TypeSchema::Unknown` substitution hides B1;
- no ownership test is weakened;
- no local path dependency or generated artifact appears in the diff.

**Commit boundary:** integration-only fixes, if required. Do not squash the four blocker commits before review.

---

## 10. Task 6 — Publish a consumable core revision and update the agent

**Objective:** Make the result reproducible from the agent repository without relying on a local checkout state.

### Step 1: Publish core history

Push the core branch so every commit is reachable from an advertised remote ref. Open/update the core PR and run CI. Record the final reviewed 40-character commit ID.

The consumable revision must include:

- callable streaming and `http-client` support from the `06b37fd...` base;
- B1–B4 commits;
- all integration fixes;
- no local-only patches.

### Step 2: Update the agent pin

In `/home/wow/rustscript/rustscript-agent`:

- modify `Cargo.toml` `rustscript-vm.rev`;
- update `Cargo.lock`;
- update `tests/dependency_pin_tests.rs::PIN`;
- update the revision references in A3 plans;
- verify the lock source contains the exact new commit.

Do not restore `path = "../rustscript"`.

### Step 3: Re-run native agent gates

Executed on 2026-08-14 against the pinned `d8cf291…` revision (results recorded in `/mnt/TEMP/rustscript/agent-a3-core-tmp/`) and re-executed on 2026-08-15 against the final `fd4b570…` revision (results recorded in `/mnt/TEMP/rustscript/`):

```bash
cd /home/wow/rustscript/rustscript-agent
export CARGO_TARGET_DIR=/mnt/TEMP/rustscript/agent-target
export TMPDIR=/mnt/TEMP/rustscript/agent-a3-core-tmp
mkdir -p "$TMPDIR"

cargo test --locked --test dependency_pin_tests          # 2 passed (direct rustc and cargo)
cargo test --locked --test core_repro_driver             # 11 passed, 0 ignored
cargo test --locked --test provider_tests                # 12 passed, 4 ignored (stub-only)
cargo test --locked --workspace --all-features --all-targets
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
git diff --check
```

`core_repro_driver` was converted from "expect current failure" assertions to
positive behavior assertions and runs by default (8 positive B1–B3 probes, 1
preserved by-value-capture rejection control, 1 two-parameter control, plus
the five-parameter probe, which flipped from the ignored residual-defect
assertion to a positive assertion at `fd4b570…`). The B4 capability has no
dedicated probe (the adapter's marker-splice path is a documented follow-up;
see §11).

---

## 11. Provider-test unlock matrix

Core completion plus the §11a residual fix (`fd4b570…`) makes all eight
OpenAI Chat provider tests pass by default. The last four still require
agent adapter implementation (`not_implemented` stubs; retained ignores).

| Provider test | Core prerequisites | Additional agent prerequisite | Actual state after fd4b570 pin |
|---|---|---|---|
| `openai_chat_non_stream_text_usage_and_reasoning` | B1, B2 | none beyond current adapter | PASS (default run) |
| `openai_chat_non_stream_tool_calls` | B1, B2 | none beyond current adapter | PASS (default run) |
| `openai_chat_malformed_payload_is_typed` | B1, B2 | none beyond current adapter | PASS (default run) |
| `openai_chat_invalid_json_fails_as_typed_invocation_error` | B1, B2 | none beyond current adapter | PASS (default run) |
| `openai_chat_stream_text_and_usage` | B1, B3 | SSE callback path active (DONE: adapter implemented, `http::client::sse` exposed) | PASS (default run) |
| `openai_chat_stream_tool_call_chunk_aggregation` | B1, B3 | SSE callback path active (DONE) | PASS (default run) |
| `openai_chat_stream_cancellation_is_typed` | B1, B3 | cancellation reaches the stream driver (runner already cancels pending invocations) | PASS (default run) |
| `openai_chat_stream_eof_without_done_fails_closed` | B1, B3 | fail-closed EOF handling in the stream adapter (A3 review P2 guard; DONE) | PASS (default run) |
| `openai_responses_buffered_transcript_is_referenced` | B1, B2, B4 | replace `not_implemented` adapter stub | retained ignore (agent work) |
| `openai_responses_stream_transcript_matches_real_transport_and_is_referenced` | B1, B3, B4 | implement Responses stream adapter | retained ignore (agent work) |
| `anthropic_messages_buffered_transcript_is_referenced` | B1, B2, B4 | replace `not_implemented` adapter stub | retained ignore (agent work) |
| `anthropic_messages_stream_transcript_is_referenced` | B1, B3, B4 | implement Anthropic stream adapter | retained ignore (agent work) |

The eight OpenAI Chat suites run by default at `fd4b570…` (buffered,
stream aggregation, cancellation, and the EOF-without-`[DONE]` fail-closed
guard) and pass against the recorded wire fixtures. No schema guard is
bypassed and no fixture is weakened; the
`param_aliasing_*` repro pair independently guards the §11a fix through
`core_repro_driver`.

B4 also enables a follow-up agent change replacing marker-splice request
bodies with direct structured map encoding. That follow-up must preserve the
four currently green wire/error tests before marker code is removed.

---

## 11a. Residual core defect (fixed at fd4b570)

The B1 liveness fix (`fe890a0`, `src/compiler/lifetime/liveness.rs`) made
all parameters interfere with each other and with entry-live locals, but a
local that is not live at body entry could still be colored onto a
parameter slot. The caller frame then read the wrong slot while evaluating
call arguments and the VM's `enter_script_frame` schema check failed
(`type mismatch: expected string`, `TypeMismatch("callable argument
schema")`) although every value was correctly typed.

Evidence at `d8cf291…` (all probes compiled and run through the agent's own
runner; scratch bisect ladder preserved in `/mnt/TEMP/rustscript/`):

| probe | shape | result |
|---|---|---|
| `root_splice` / `hop4` (committed B1 repros) | cross-module accessor array / two-map first-read | PASS |
| 2-parameter caller → parse chain | `fn(body, ctx)` shapes, literal or decoded body | PASS |
| 3-parameter caller → parse chain (`(map, int, string)`) | `chat_parse_response_body` shape | PASS |
| 4–5-parameter caller → parse chain (all params used) | `chat_send_complete` 5-param shape | FAIL `type mismatch: expected string` |
| full dispatch chain with transport (HTTP) | mirror of `openai_chat.rss` | FAIL |
| identical chain with the transport removed | canned body | PASS |
| identical chain with the sibling `complete_dispatch` function removed | same functions otherwise | PASS |

The corruption was graph-layout-dependent, not per-function: identical
functions passed or failed depending on a sibling function's presence, and
compiled `CallablePrototype` metadata stayed internally consistent
(`parameter_slots` non-contiguous, e.g. `[1,4,5,6,0]` for the five-parameter
caller, but matching the schema arity), so the defect lived in the colored
frame's slot references, not in prototype metadata. Adapter restructuring
could not reliably avoid it (verified: a fully 2-parameter restructure of
the dispatch chain still failed when the sibling dispatch function and the
transport call were present).

**Core fix (`fd4b570`, `fix(compiler): keep parameters live for the whole
body`):** the liveness allocator now seeds the function's parameter slots
into the body live-out before collecting interference constraints and
re-marks them after every statement in the backward sweep, so every
parameter stays live for the whole body no matter what the body does to it.
Body statements can still define a parameter slot (an `Assign` may target a
parameter, and the liveness rewriter may `Drop` one after its last use), so
the rule is a conservative safety invariant, not a claim that the body
never defines a parameter slot. Non-parameter locals keep sharing physical
slots exactly as before. `fd4b570` is the direct child of `d8cf291` on
`origin/fix/a3-core-unblock` and is verified reachable on the canonical
HTTPS remote.

**Consumer verification at `fd4b570…`:** the committed probe pair now runs
by default as positive assertions:

- `tests/fixtures/core-repros/param_aliasing_m2.rss` +
  `param_aliasing_root.rss` — five-parameter caller → parse chain; PASSES
  (`param_aliasing_five_param_caller_passes_vm_schema_check`).
- `tests/fixtures/core-repros/param_aliasing_ctrl_m2.rss` +
  `param_aliasing_ctrl_root.rss` + shared `param_aliasing_parse.rss` —
  two-parameter caller, identical parse chain; PASSES
  (`param_aliasing_two_param_caller_control_passes`).

The eight OpenAI Chat provider suites (buffered, stream aggregation,
cancellation, and the EOF-without-`[DONE]` fail-closed guard) run by
default and pass at the pinned revision; the VM schema
guard is unchanged and no fixture was weakened.

Focused consumer commands:

```bash
cargo test --locked --test core_repro_driver param_aliasing
cargo test --locked --test provider_tests openai_chat_
```

---

## 12. Review boundaries

Perform one read-only review after each blocker commit:

1. **B1 review:** schema identity, module index remapping, specialization cache keys, VM guard retained.
2. **B2 review:** branch-local state isolation, strict diagnostics retained, no scope leakage.
3. **B3 review:** capture classifier parity, mutation uses `BorrowMut`, pure by-value move rejection retained, cell lifecycle.
4. **B4 review:** string-key map success, unsupported nested value errors, struct regression, no key stringification.
5. **Integration review:** cross-blocker interactions and consumer revision reproducibility.

Reviewers must inspect diffs and tests. They must not change code during the read-only review.

---

## 13. Rollback strategy

Each blocker is an independent commit:

- revert B4 if map admission broadens JSON behavior incorrectly without affecting B1–B3;
- revert B3 if shared capture lifetime behavior regresses without affecting schema/type fixes;
- revert B2 if branch inference leaks locals without affecting runtime schema/capture behavior;
- revert B1 only with the agent pin returned to the previous core revision, because it is the primary provider execution unblock.

Never roll back by replacing the Git dependency with a local path or by removing runtime validation.

---

## 14. Definition of done

The core plan is complete when all of the following are true:

1. B1 native root/non-root, parameter-order, accessor/literal, specialization, VMBC, and runtime tests pass. **DONE** — `fe890a0` (plus `module_callable_schema_*` tests in the core repo); the agent's committed B1 repros (`root_splice`, `hop4`) now pass at `fd4b570…`.
2. B2 tail expression-if typed-local tests pass while unknown-type and scope errors remain enforced. **DONE** — `e2b50cb`; agent repros `json_enc_e`, `letif_a`, `tailif` compile and run.
3. B3 mutable capture tests pass through multiple calls and VMBC while pure move controls remain rejected. **DONE** — `b9b66d8`; agent `closure_assign` remains rejected (preserved move semantics), `closure_read` control passes, and the SSE accumulator closure in `openai_chat.rss` compiles and runs end-to-end at `fd4b570…`.
4. B4 runtime map encode tests pass; struct tests remain green; invalid keys/values return typed errors. **DONE** — `d8cf291`; the marker-splice replacement follow-up in the agent is deferred (see §11).
5. Full workspace, no-std, wasm, fmt, Clippy, and diff gates pass. **DONE** — core gates green at `fd4b570…`; agent workspace/fmt/Clippy/diff gates green at the pinned revision.
6. The final core commit is reachable from a remote ref. **DONE** — `fd4b570d08d7cc90cc29e3b05df59c9e9bf3b88e` verified via `git ls-remote` on `rustscript-lang/rustscript` (branch `fix/a3-core-unblock`).
7. The agent pins that exact full revision through HTTPS Git and `Cargo.lock`. **DONE** — `Cargo.toml` `rev = "fd4b570d08d7cc90cc29e3b05df59c9e9bf3b88e"`; `Cargo.lock` carries the canonical `git+https://…rustscript.git?rev=fd4b570…#fd4b570…` source for both `pd-vm` and `pd-host-function`; no path dependency; `dependency_pin_tests` green (direct rustc and cargo, including the lock-source guard for both crates).
8. Agent core repros are converted to positive tests and run by default. **DONE** — `core_repro_driver` runs by default (11 passed, 0 ignored), including the five-parameter probe converted from the residual-defect failure assertion to a positive assertion at `fd4b570…`.
9. The eight directly core-blocked OpenAI Chat tests pass or have a newly demonstrated agent-side failure with the core failure absent. **MET** — at `fd4b570…` the eight suites (buffered, stream aggregation, cancellation, and the EOF-without-`[DONE]` fail-closed guard) run by default and pass against the recorded wire fixtures; the §11a defect is fixed in core and guarded by the committed `param_aliasing_*` probe pair.
10. The four Responses/Anthropic tests are tracked as agent adapter work rather than reported as unresolved core defects. **DONE** — placeholder ignores retained with stub-only reasons; no adapter is claimed.
11. No A4/A6 capability is claimed by this plan. **DONE** — unchanged.
