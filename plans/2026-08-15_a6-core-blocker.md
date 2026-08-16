# A6 Native Supervisor Wiring — Status and the Narrowed Remaining Core Gap

**Date:** 2026-08-16 (wiring delivered; blocker narrowed)
**Branch:** `feat/agent-a6-wiring`
**Base / integration HEAD:** `f352f69a61b479c43da2344347802facc0d72026`
**Core pinned:** `rustscript-lang/rustscript@fd4b570d08d7cc90cc29e3b05df59c9e9bf3b88e`
(pd-vm, per Cargo.toml)

## 1. What is delivered (native, uncore)

The A6 native supervisor is now REALLY wired into the production serial
loop. When the RSS loop yields `parallel.handoff` / `subagent.handoff`
(only after the A4 delegation gate approves — `approval_mode`
auto/manual require a durable approval for the execute-class
`parallel.run` / `subagent.run` delegation), the embedding executes the
handoff natively and the loop continues reasoning:

- The service runs the VERIFIED-plan policies (`rss/agent/parallel.rss`,
  `rss/agent/subagents.rss`) with the real parent/child context. It never
  implements agent policy itself.
- `parallel.plan` → the native supervisor
  (`src/runtime/subagent_supervisor.rs`, `supervise_batch[_bounded]`)
  drives N REAL child runs through `AgentService::admit` with
  `parent_run_id`: bounded concurrency (the loop owns the gate: no slot
  starts past a race/fail-fast gate), ordered result slots, race
  (first success cancels losers) / fail-fast (first failure cancels
  siblings), parent-cancel propagation (a watcher mirrors the parent's
  `RunCancellation` into the shared supervision cancel), and the
  remaining run deadline as the batch bound.
- `subagent.admit` → one REAL child run: admission (isolated session,
  capacity permit, parent link), the worker is ACTUALLY spawned, then
  `subagent.started` is emitted durably; the parent awaits the child's
  durable terminal and emits `subagent.completed`; the typed child
  outcome (output text / typed cancellation / typed failure) is folded
  back. A refused admission or a policy rejection (`subagent.rejected`,
  depth/fanout/parent-terminal) NEVER starts anything and NEVER emits
  `subagent.started`.
- `subagent.cancel` (policy-decided parent-cancellation propagation)
  cancels the listed pending/active children.
- Results are backfilled into the loop state
  (`parallel_outcome` / `subagent_outcome`) and the loop folds them as
  canonical tool messages (`parallel.result` / `subagent.result`
  phases) and continues reasoning with the real results in history.
- Durable sequencing: child links (`run.link_child` /
  `run.list_children` / `run.link_state` through the A2 storage program —
  the durable link state REALLY advances: the admission transaction
  inserts `pending`, the native link step advances it to `active`, and the
  child's observed terminal advances it to `completed`/`cancelled`/`failed`
  via `run.link_state`), child lifecycle
  events (durable append + publish, never after a terminal), tool-cycle
  messages (durable-first). Child links and child events survive a
  restart.

No private host function, no direct SQL, no fabricated success, and no
`subagent.started` before a genuine admission+worker spawn. The
single `ChildExecutor` (`ServiceChildExecutor`) is the only executor;
the strengthened engine in `subagent_supervisor.rs` is reused by both
handoffs.

### Tests

- `tests/agent_loop_production_tests.rs` — loop policy suites: the
  handoff carries the batch / child descriptor + budgets; the approval
  gate (pending → durable `approval.wait`; approved resume → handoff;
  denied resume → typed `approval_denied` tool result and continue);
  the `parallel.result` / `subagent.result` phases fold ordered slot
  results / typed rejections / child outcomes and continue.
- `tests/agent_loop_e2e_tests.rs` — real service fixtures: 4 real
  children with REAL 2-concurrency on the wire (a concurrency-counting
  probe server asserts peak == 2) and ordered slots; race first-success
  cancels losers and never starts the rest; fail-fast first-failure
  cancels siblings and never starts the rest; approval park/resume
  executes children; subagent real admission (parent link, isolated
  session, started/completed exactly once); admission-refused and
  depth-rejected children never start; parent stop propagates to
  in-flight children with no post-terminal events; child links and
  child events survive a restart; the parent continuation request is
  provider-legal on EVERY direct adapter (OpenAI Chat/Responses,
  Anthropic — no dangling tool results, approved and denied paths);
  the NATIVE deny policy (configurable tools/risks and the
  `native_hard_deny` flag) denies delegation in production before any
  park or child; parallel cumulative fanout counts the authoritative
  mirror across batches; the grace-drop window cancels in-flight
  children durably and releases every permit; a stop with a queued
  slot never starts the queued child.
- `src/runtime/subagent_supervisor.rs` — engine suites: bounded
  concurrency, ordered slots, race/fail-fast gates, parent cancel, and
  the new deadline-bounded batch (`supervise_batch_bounded`) which
  cancels in-flight children and drains typed.

## 2. The remaining CORE gap (narrowed, unchanged)

The ONLY remaining A6 core gap is the **script-internal generic task
surface**: the RustScript LANGUAGE (strictly synchronous and
single-threaded, no `async`/`await`, no spawn syntax) and the
restricted inline agent registry alone expose no `task` namespace, so a
*policy script* cannot itself `spawn`/`await`/`resume` a concurrent
child run inside its own source. The policies therefore remain pure
DECISION modules (`executable:false` + typed `blocked_reason`), and the
native supervisor (uncore) executes them. This gap does NOT block the
A6 product capability: parallel execution, subagent delegation, and
bounded supervision are all delivered natively.

## 3. Minimal repro and exact failure (scoped to `task::spawn`)

`tests/fixtures/a6-core-repros/no_task_child_capability.rss` attempts
exactly ONE thing, only the surface asserted in CI: `task::spawn`.
Driving it through `AgentRunner::from_file` fails at **compile** time:

```
Compile("unknown namespace call 'task::spawn'; ... (source ...)")
```

No `task::await`/`task::await_all`/`task::cancel` or language async/await
is claimed or attempted. The CI test `a6_no_task_script_cannot_call_task_spawn`
wires this fixture into the default suite and asserts only that
`task::spawn` is absent.

## 4. Criteria matrix (updated)

| Criterion | Delivered by |
|---|---|
| Bounded concurrency, ordered results, race/fail-fast, parent cancel | Native SubagentSupervisor + plan (real children) |
| Real child admission: parent link, isolated session/context, worker spawned before `subagent.started` | `ServiceChildExecutor` through `AgentService::admit` |
| Await durable terminal; `subagent.completed` exact-once; no post-terminal side effects | Native executor + durable event append |
| Depth / fanout rejection (never started) | Policy (`subagent.rejected`) + native refusal handling |
| Admission refused → never started | Native (typed `admission_refused` slot, no event) |
| Approval-gated delegation (A4 durable park/resume) | Loop gate + existing approval bridge |
| Batch deadline / cancel propagation to in-flight children | `supervise_batch_bounded` + cancel watcher |
| Restart state (child links + child events survive) | Durable `child_run_links` + `event.append` |
| No fabricated success / no private builtin / no direct SQL | Policies are pure decisions; native composes existing capability |
| Script-internal `task::spawn` | **BLOCKED** (language/registry, narrowed; repro wired to CI) |

## 5. Final review round — the two closing P2s (fixed, amended)

### P2 #1 — pre-admission compensation watcher: no wall-clock give-up

The `AdmittedChildGuard` grace-drop watcher previously gave up after
`terminal_commit_retry_window × 5` polls of 100 ms (≈150 s with the default
300 s window) and left a late-completing admission durably `running` with a
held permit and no worker. Fixed in `src/service.rs`:

- **No wall-clock give-up.** The watcher polls the deterministic admission
  key until the detached admission appears (then cancels it, commits the
  durable terminal, and advances the link state) or the service shuts down
  (`stop_admission`, the SIGINT path) — the only termination besides process
  death. An admission that never completed has NO durable row (the admission
  commit is transactional), so restart recovery has nothing to repair; a row
  that lands in the shutdown race window is durably failed by the
  restart-recovery orphan sweep (`recovery.recover_active` on the next
  open) — no permanently-running rows on the normal recovery path.
- **Shutdown lifecycle.** The watcher polls non-blockingly
  (`store.try_read()`, never parking behind a stalled/queued writer), does
  one final lookup on halting, and exits with the service; the registration
  is removed on every exit path (`WatcherRegistration` guard).
- **Bounded task count.** One watcher per deterministic admission key
  (registry `compensation_watchers`), so a re-dropped slot never spawns a
  second watcher; the count is bounded by the admission/concurrency upper
  bound — every waiting watcher corresponds to a dropped admission that
  still holds a capacity permit, and in-flight admissions are capped by
  `max_concurrent_runs`. Observable via `compensation_watcher_count()`.

### P2 #2 — canonical `subagent.completed` append: never `let _=`-ignored

The completed-event append previously swallowed `NativeEventEmit` with
`let _ =`. Fixed in `src/service.rs`:

- **Bounded retry.** `emit_native_event` retries a failed durable append
  `terminal_persist_retries` additional times with
  `terminal_persist_retry_delay` backoff (`emit_native_event_once` holds the
  store write lock and rolls the in-memory event back on failure). No
  duplicate can arise: the storage worker either commits (Ok) or fails
  without committing; a worker that dies mid-command fails every later
  attempt too.
- **Typed parent failure.** If the append still fails past the bound, the
  slot reports `ChildOutcome::Failed("completed_event_append_failed: …")` —
  the child's outcome (and its output text) never reaches the parent's
  history before (or without) the durable event. A parent terminal stays a
  typed no-op (no post-terminal side effects).
- **Fault injection.** `GatewayPersistence::fail_next_event_appends(type, n)`
  (`#[doc(hidden)]`, test-only) fails the next `n` matching `event.append`
  commands; the durability suites prove retry-recovery (exactly one durable
  event, real output folded) and the typed-failure promotion (zero durable
  events, typed failure in the parent's history, child output absent).

### New RED→GREEN tests (`tests/agent_loop_e2e_tests.rs`)

- `e2e_admission_in_flight_drop_past_old_watcher_bound_is_still_compensated`
  — with a SHORT `terminal_commit_retry_window` (old bound = 500 ms) the
  admission is stalled 2.5 s: the child is still compensated past the old
  give-up point, the link advances, every permit is released.
- `e2e_compensation_watcher_stops_on_shutdown_and_restart_recovers` —
  storage never returns: one deduplicated watcher stays live, exits on
  `stop_admission()`, no durable child row exists while the admission never
  completed, and the late-completing row is durably failed by the
  restart-recovery sweep on the next open (no permanently-running rows).
- `e2e_compensation_watcher_count_is_bounded_by_admission_capacity` — with
  `max_concurrent_runs = 3` a 4-task batch admits 2 children; the live
  watcher count equals `capacity - 1` (refused slots spawn none) and drains
  to zero after compensation.
- `e2e_subagent_completed_append_fault_is_retried_exactly_once` — one
  injected `subagent.completed` append failure is retried: exactly one
  durable event, child output folded.
- `e2e_subagent_completed_append_failure_promotes_to_typed_parent_failure`
  — injected failures past the bound: zero durable completed events, typed
  failure in the parent's durable history, child output never precedes the
  event.

Note (observed, pre-existing): parking_lot `read()` parks behind a queued
writer, so a synchronous store read on a tokio worker (e.g. a slot's
pre-admission `run_is_stopping`) can delay the batch deadline while a
stalled admission queues on the write lock. The watcher itself never parks
behind a writer (non-blocking polling); the compensation completes the
moment storage returns.

## 6. Verification

```bash
cd /mnt/TEMP/rustscript/agent-v3-a6-wiring
export CARGO_TARGET_DIR=/mnt/TEMP/rustscript/a6-target TMPDIR=/mnt/TEMP/rustscript/a6-tmp
cargo test --locked --test a6_supervisor_bridge_tests   # native supervisor bridge
cargo test --locked --test parallel_tests               # parallel policy
cargo test --locked --test subagent_tests               # subagent policy
cargo test --locked --test agent_loop_production_tests  # serial loop + result phases
cargo test --locked --test agent_loop_e2e_tests         # real service fixtures (A5+A6)
cargo test --locked --test storage_tests                # durable storage
cargo test --locked --test gateway_tests                # gateway API surface
cargo test --locked --workspace --all-targets           # regression gate
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
git diff --check
```

All target/tmp artifacts live under `/mnt/TEMP/rustscript/`. The
review-fix round AMENDS the original commit on `feat/agent-a6-wiring`
(no push).

## 7. Third review round — all A6 P1/P2 items (fixed, amended)

Closed in this round (each with a focused unit or durable E2E gate):

1. **Approval resolve / run.transition ambiguous-success recovery + no
   park-drop on ProgramUnavailable.** `resolve_parked_approval` now checks
   program availability BEFORE consuming the park (a missing program never
   eats the park and leaves the run durably `running` with no worker), and a
   transition that reports ambiguous success but whose DURABLE status is
   already `running` (only when the park records a resolved bridge outcome)
   recovers by resuming instead of re-looping `waiting -> running`.
2. **Parallel multi-batch identity.** Each parallel handoff advances a
   parent-global ordinal base from the authoritative cumulative fanout
   mirror, so child/slot/tool_call/idempotency identities are NEVER reused
   across batches of the same run, and the mirror stays consistent.
3. **Admission parent-active (both stores).** The durable admission
   transaction rejects a child under a terminal/stopping parent
   (`parent_not_active`) and the in-memory mirror enforces the same guard
   (`AdmitError::ParentNotActive`, typed API `parent_run_not_active`); a
   child/link/event is never inserted beneath a finished parent.
4. **Compensation watcher link ordering.** The watcher never writes a
   terminal link before the child reaches a real durable terminal;
   `terminal_pending` keeps waiting (no premature link).
5. **`terminal_retry_expired` durable single-terminal path.** The expiry
   now commits a real `run.terminal` (`run.failed` with
   `terminal_retry_expired`) instead of a bare ignored transition; on
   failure the run stays observably `terminal_pending` (no
   memory/durable fork) and the bounded retry stops.
6. **Restart-bounded retention.** `load.all` prunes each run's reloaded
   events to `max_events` while preserving the terminal, so a restart stays
   bounded.
7. **Approval cancellation retryable.** The once-cell entry is removed after
   each cancellation attempt, so a failure is genuinely retried and the map
   stays bounded (no permanent error caching).
8. **Responses empty `call_id` consistent ordinal.** Buffered and streamed
   fallbacks both use the function-call ordinal (not the output-array index),
   so reasoning/interleave never shifts them and buffered/stream agree.
9. **Child cancellation real reason.** Deadline-bounded batches propagate
   `CancellationReason::Deadline` to children; parent stops use `Requested`.
10. **Durable E2E / unit gates.** Added unit tests proving parallel
    multi-batch identity uniqueness and `observed_link_state` None-before-
    durable-terminal; the durable restart-retention E2E and the approval
    ambiguous-recovery E2E stay green. Full `--workspace --all-targets`,
    `fmt`, and strict `clippy -D warnings` all pass.

All target/tmp artifacts live under `/mnt/TEMP/rustscript/`. The
review-fix round AMENDS the original commit on `feat/agent-a6-wiring` (no
push).

## 8. P2 close-out round (2026-08-17) — durable link/parent terminal + grace-drop + canonical expiry

Fixed and gated this round (strict TDD RED→GREEN; each with a durable/unit gate):

1. **Durable link-terminal convergence (P2).** `update_child_link_state_native`
   no longer SILENTLY drops a terminal `run.link_state` advance after the inline
   retry budget is exhausted. When the desired link state is a REAL child
   terminal and the parent is still live, the advance is handed to a
   capacity-bounded (`MAX_PENDING_LINK_TERMINALS`), lifecycle-managed janitor
   (`link_terminal_retry_loop`, at most ONE task) that re-derives the child's
   REAL observed durable terminal (`observed_link_state`: `None` while the child
   is still `terminal_pending`, so it is NEVER prematurely written as a
   terminal link) and writes DURABLY before updating the mirror, so the current
   process converges once storage recovers (no restart needed). Entries whose
   parent reaches a real terminal are dropped (restart recovery reconciles the
   `pending`/`active` link). Exposed via `pending_link_terminal_count()`.
   Gate: `gateway_tests::durable_link_state_budget_exhaustion_converges_in_current_process`.
2. **Bounded grace-drop real-terminal folding (P2).** The `supervise_batch_bounded`
   fallback now queries the executor's `observed_terminal_outcome(slot)` (new
   `ChildExecutor` method; the real `ServiceChildExecutor` derives it from the
   child's durable status/output) BEFORE falling back to a typed cancellation.
   A child that ALREADY durably completed (e.g. `subagent.completed` appended
   but the outcome not yet folded into the shared buffer) is folded to its REAL
   `Completed`/`Failed`/`Cancelled`, never a spurious `Cancelled`. Only truly
   unterminal slots use the cancel reason. Gate: supervisor unit
   `bounded_grace_drop_folds_slots_with_observed_real_terminal`.
3. **Single canonical terminal for expiry (P2).** `terminal_retry_expired` is no
   longer a distinct mirror status: the expiry commit writes the canonical
   `failed` terminal in BOTH the in-memory mirror and the durable row, with the
   typed reason carried in the terminal event's `error_code=terminal_retry_expired`
   (a legacy durable `terminal_retry_expired` row maps to `failed` on load).
   This removes the pre-restart memory/durable status fork. Gate
   `terminal_retry_expired_is_canonical_failed_with_typed_reason`.
4. **Real coverage (P2):** 601+ child-run links paginate completely across the
   512-row `run.list_children_page` boundary and the authoritative fanout
   mirror does NOT undercount them (`durable_child_links_pagination_reads_all_601_children_and_fanout_does_not_undercount`);
   the DURABLE parent ordinal allocator returns DISJOINT ranges under
   concurrent allocation (`concurrent_parent_ordinal_allocations_return_disjoint_ranges`).

All target/tmp artifacts live under `/mnt/TEMP/rustscript/`. Final
`--workspace --all-targets`, `fmt`, and strict `clippy -D warnings` pass.
