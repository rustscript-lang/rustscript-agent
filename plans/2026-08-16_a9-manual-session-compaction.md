# A9 Manual Session Compaction — API + Telegram Real Compaction (TDD)

Date: 2026-08-16
Branch: `feat/agent-manual-compact`
Base: `f352f69a61b479c43da2344347802facc0d72026` (clean worktree
`/mnt/TEMP/rustscript/agent-v3-compact`)

## 1. Goal

Turn `POST /api/sessions/{id}/compact` and Telegram `/compact` from the
typed-unavailable answers into REAL manual session compaction, composed as a
single `AgentService::compact_session` entry:

- RSS `compact.rss` decides the pair-preserving prefix; native Rust only
  orchestrates generic storage commands (no policy rewrite, no direct SQL,
  no private host).
- No active/waiting/compacting run → the service creates a bounded auditable
  maintenance run (durable, terminal in the same request) and executes
  `compaction.start → message.compact → compaction.commit` (or the typed
  failure path) with generation advance, exact-once events and terminal
  state.
- Active/waiting/compacting run → typed 409, never a concurrent double
  compact. Idempotent retry / restart recovery safe.
- API returns the real compaction id/generation/range/status; Telegram
  echoes the real result. Auth/session/actor isolation does not regress.

## 2. Audit result (A5 compact planner/service/storage contracts)

### `rss/agent/compact.rss` (policy — already real, unchanged)

Exported `run(context)` returns `compact.plan` (with `commands[3]`) or
`compact.skip` (`history_within_window` | `history_within_retained_tail` |
`invalid_config`). Context: `session_id`, `run_id`, `compaction_id`,
`generation`, `messages` (canonical `{ordinal, role, tool_call_id,
content}`), `config` (`max_context_messages`, `retained_tail`, `now_ms`,
`model`, `token_estimate`). The plan targets `generation + 1`.

### `rss/storage/compactions.rss` (storage contract — already real, unchanged)

- `compaction.start` guards: session + run exist, `runs.status =
  'compacting'`, `sessions.generation + 1 = plan generation`, range ordered
  with `retained_tail_ordinal` inside, message endpoints exist; same-payload
  pending row → idempotent resume; pending row with different payload →
  `compaction_pending_conflict`; committed row → `compaction_already_committed`;
  failed row with same id → guarded insert resets to pending (retry path);
  failed row with different id → `compaction_failed_conflict`.
- `message.compact` is a guarded no-op before commit.
- `compaction.commit` is one atomic transaction (pending → committed, range
  marked, `sessions.generation = MAX(generation, ?)` advanced) guarded on
  the run still being `compacting` and `sessions.generation = plan_gen - 1`.
- `compaction.fail` is best-effort pending → failed.

### `rss/storage/runs.rss` (run lifecycle contract — unchanged)

- `run.create` inserts `status = 'queued'`.
- `run.transition` allows queued → running/cancelled/failed; running →
  waiting_approval/compacting/terminal; compacting → running/completed/
  failed/cancelled. Matched transitions insert `run.status_changed` events
  exactly once, in the same transaction.
- Restart recovery (`run.recover_active`) fails every queued/running/
  waiting_approval/compacting run with `gateway_restart` and the
  unconditional compaction fail-sweep fails every pending compaction.

### Service (`src/service.rs`)

`execute_compaction` (loop path, unchanged) already executes the planned
commands while the run is durably `compacting`, canonicalizes the compaction
id to `compact:{session}:{generation}`, mirrors the committed range in
memory, and fails a pending row on step failure. `build_production_loop_context`
already renders the canonical message list (`ordinal = position + 1`,
message-level `tool_call_id`, content parts).

### Transport layer (today)

- `src/gateway/api_server.rs` `session_compact_handler`: 501
  `compaction_unavailable` for every session (typed-unavailable; honest but
  not a real trigger).
- `src/gateway/telegram.rs` `cmd_compact`: typed availability answers only
  (loop-managed for an active run, "nothing to compact" otherwise).
- `src/gateway/store.rs` `GatewayPersistence`: has `compaction_*`,
  `run_transition`, `event_append` — but NO `run.create` wrapper (needed to
  create the maintenance run through the typed worker; the RSS `run.create`
  op already exists).

## 3. Design — single `AgentService::compact_session` composition

New public surface (service-owned, transport maps without string matching):

```rust
pub enum CompactSessionOutcome {
    Committed { compaction_id, run_id, generation, source_start_ordinal,
                source_end_ordinal, retained_tail_ordinal },
    Skipped { reason: String },            // compact.skip reasons
    Conflict { kind: CompactConflict, run_id: Option<String>, status: Option<String> },
}
pub enum CompactConflict { ActiveRun, CompactionInProgress }
pub enum CompactSessionError { SessionNotFound, NoDurableStorage,
                               Halting, Plan(String), Storage(String) }
pub async fn compact_session(&self, session_id: &str, actor: &str)
    -> Result<CompactSessionOutcome, CompactSessionError>
```

Composition (whole body on `spawn_blocking`; storage worker round-trips never
occupy Tokio threads):

1. Halting gate → `Halting`. Session must exist in the store mirror →
   `SessionNotFound`.
2. In-process race guard: `compacting_sessions: Mutex<HashSet<String>>` on
   the service; a second concurrent `compact_session` for the same session →
   `Conflict { CompactionInProgress }` (a scope guard removes the entry on
   every exit).
3. Durable active-run gate (authoritative, restart-safe): `run.list(session,
   "")` — any row with status `queued`/`running`/`waiting_approval`/
   `compacting` → `Conflict { ActiveRun }` with the real run id/status.
4. Plan: render the canonical message list from the mirror (same shape as
   `build_production_loop_context`), invoke the precompiled `compact.rss`
   runner with `{session_id, run_id: <maintenance run id>, compaction_id:
   compact:{session}:{gen+1}, generation, messages, config}` (model from the
   session view, `token_estimate: 0` — the same value the loop passes).
   `compact.skip` → `Skipped { reason }` (no durable writes at all).
5. Maintenance run (bounded, auditable): id
   `compact-run:{session}:{gen}:{8-hex-uuid}`; `run.create` with
   `input_json` = `{"kind":"session_compaction","actor":...,"session_id":...,
   "target_generation":...}` (durable audit trail), `script_hash =
   "compact"`; then `run.transition` queued → running → compacting. Any
   failure here durably fails the run (queued/running → failed) and returns a
   typed error — no orphan non-terminal run is ever left behind.
6. Events: `compact.started` appended durably via `event.append` (bounded
   payload: compaction id, generation, range) before the first command.
7. Execute the plan commands with the loop path's exact command runner
   semantics (canonicalized ids, typed `compaction_command_ok`):
   - success → `compact.completed {ok:true,...}` + `run.transition`
     compacting → completed (terminal, `finished_at_ms` set, `run.status_changed`
     event exactly once).
   - storage failure after `compaction.start` → best-effort `compaction.fail`
     + `compact.completed {ok:false,error}` + run compacting → failed; typed
     `Storage` error. History untouched (A2 contract).
   - `compaction_start_rejected`/`compaction_id_conflict` → same failure path
     (typed `Storage` error; no row was fabricated).
   - `compaction_pending_conflict`/`compaction_failed_conflict` →
     cross-process double compact already in flight → run compacting →
     failed, `Conflict { CompactionInProgress }`.
   - `compaction_already_committed` → the OTHER request already committed
     this exact (session, generation) — idempotent answer: read the committed
     row via `compaction.get` and return `Committed` with its real values.
8. Mirror (durable-before-visible): on success mark the covered range
   compacted in memory, advance `session.view.generation`, and insert the
   maintenance run into `store.runs` with status `completed` (or `failed` on
   the failure path) plus the two compact events, so `/status`, run views,
   and the session-active checks never see a fabricated or stale state.

Restart safety falls out of the unchanged A2 contract: a crash mid-flight
leaves the maintenance run + pending row to restart recovery (run → failed,
row → failed); the retry reuses the SAME canonical compaction id
(`compact:{session}:{gen}`), which the storage layer's failed-row reset
accepts, and the session generation never advanced, so the retry commits.

## 4. Transport wiring

### API (`session_compact_handler`)

`state.service().compact_session(session_id, "api_server")`; unknown session
→ 404 `session_not_found` (kept). Outcome → response:
- `Committed` → 200 `{"object":"hermes.compaction","compaction_id",
  "run_id","session_id","generation","source_start_ordinal",
  "source_end_ordinal","retained_tail_ordinal","status":"committed"}`
- `Skipped` → 200 same object, `"status":"skipped"`, `"reason"`
- `Conflict{ActiveRun}` → 409 `run_active_conflict`
- `Conflict{CompactionInProgress}` → 409 `compaction_in_progress`
- `Plan` → 503 `compaction_policy_unavailable`; `Storage` → 503
  `persistence_unavailable`; `NoDurableStorage` → 503; `Halting` → 503.

### Telegram (`cmd_compact`)

Keeps the no-session answer and the active-run fast path (gate +
started/stopping mirror), then calls the service on a blocking thread with
actor `telegram:<user_id>`:
- `Committed` → `Compaction committed: <id> (generation <gen>), range
  [<start>, <end>], retained tail <tail>.`
- `Skipped` → `No compaction needed: <mapped reason>.`
- `Conflict` → typed refusal text; errors → `Could not compact this
  conversation: <error>.`

## 5. TDD scope (RED first)

New `tests/a9_manual_compact_tests.rs` (real router, real SQLite, real
`compact.rss` + storage program; deterministic history seeding by appending
durably in a phase-1 gateway and reopening so `load()` hydrates the mirror):

1. pair boundary: 8-message history with an assistant tool-call at the naive
   boundary → committed range pushed past it (end = 7, not 6); real id
   `compact:{session}:2`, generation 2, retained tail 7.
2. full-compaction rule: 7-message history, tool result last → end = 7, empty
   tail (documented compact.rss boundary).
3. within-window / empty history → `skipped` (`history_within_window`), zero
   durable rows, zero runs.
4. active run (real parked waiting_approval run) → 409 `run_active_conflict`,
   run untouched.
5. durable compacting run (crafted through `run.create` + transitions) →
   409 `run_active_conflict`.
6. double-request race: two concurrent POSTs → exactly one committed, one
   `compaction_in_progress` (or skipped — sequential interleaving), exactly
   one durable row, generation advanced once.
7. storage failure pre-flight (`persistence.shutdown()`) → 503
   `persistence_unavailable`, no run/row created.
8. retry after durable failure: failed pending row + failed run (as the
   failure path leaves them) → next POST reuses the SAME compaction id and
   commits (generation 2).
9. restart after start: compacting run + pending row, gateway reopened →
   restart recovery fails both → POST commits.
10. auth: no bearer → 401; unknown session → 404; foreign session id →
    404 (boundary holds).
11. Telegram e2e: seeded over-window telegram session → `/compact` replies
    with the REAL compaction id/generation/range; second `/compact` →
    skipped reply; chat without a session → "No conversation yet".

Stale assertions updated: a7 compact typed-unavailable test (rewritten to the
real contract), telegram typed-availability tests (new reply texts).

## 6. Verification gates

```bash
export CARGO_TARGET_DIR=/mnt/TEMP/rustscript/a9-target TMPDIR=/mnt/TEMP/rustscript/a9-tmp
cargo test --locked --test a9_manual_compact_tests
cargo test --locked --test agent_loop_production_tests   # A5 loop compaction regression
cargo test --locked --test a7_api_wiring_tests
cargo test --locked --test telegram_tests
cargo test --locked --test storage_tests
cargo test --locked --test gateway_tests
cargo test --locked --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
git diff --check
```

### Results

- `a9_manual_compact_tests` 11/11, `a7_api_wiring_tests` 11/11, `storage_tests`
  27/27, `gateway_tests` 64/64, `agent_loop_production_tests` 22/22,
  `telegram_tests` 51/51, `docs_consistency_tests` 9/9 — all green.
- `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`,
  and `git diff --check` are clean.
- `cargo test --locked --workspace --all-targets` (default parallel binaries)
  intermittently flakes on PRE-EXISTING wall-clock timing tests
  (`b1_stop_before_the_approval_park_never_wedges_the_run`,
  `e2e_approval_request_pending_never_blocks_tokio_workers`,
  `e2e_stop_racing_the_park_insert_cancels_typed_without_a_post_stop_event`,
  `e2e_drain_timeout_writes_truncation_marker_before_terminal`,
  `e2e_deadline_orphaned_approval_is_compensated_immediately`,
  `request_runtime_stays_responsive_during_storage_stall`) under CPU
  contention. Baseline evidence: the SAME runs on the untouched base commit
  `f352f69` (separate worktree + target dir) flake with the same signature —
  the full workspace run AND the isolated `agent_loop_e2e_tests` suite both
  fail with 2 timing tests. Every flaky test passes when run individually
  (e.g. `b1_stop_before_the_approval_park…` 5/5, and all targeted suites
  green in isolation: a9 11/11, a7 11/11, storage 27/27, gateway 64/64,
  agent_loop_production 22/22, telegram 51/51).

## 7. Commit

Independent commit on `feat/agent-manual-compact` (no amend, no push).

## 8. Review follow-up (amended into the same commit)

Manual review findings, all addressed in this revision:

- **P2 — already_committed fall-through (fixed)**: after a typed
  `compaction_already_committed`, a failed/empty `compaction.get` read is a
  typed `Storage` error (503 `persistence_unavailable`) routed through the
  durable failure path — the request can never fall through to the success
  path and fabricate a completed attribution / run ownership. The typed
  storage layer reports guard conflicts as `Err(StorageError { code })`
  (never an ok envelope), so the conflict dispatch now lives in the
  command loop's error arm; the old `Ok(value)` code match was dead code
  that silently answered 503 for durable conflicts instead of the typed
  409 / idempotent answer. Fault-injection fixture
  `a9_compact_already_committed_read_failure_is_typed_storage_error`
  (test-only `GatewayPersistence::inject_storage_failure` hook).
- **P2 — event append is true exact-once (closed)**: `storage_event_append`
  was a blind INSERT that failed on `UNIQUE(event_id)`. With the maintenance
  run's fixed `compact.started` / `compact.completed` event_ids, an ambiguous
  commit (SQLite committed but the store response was lost / timed out) made
  the retry hit UNIQUE(event_id) → treated as failure → the completed
  terminal could park `terminal_pending` until restart, and the started
  event could misjudge the compaction as aborted. The fix gives
  `event.append` exact-once semantics at the storage layer: it re-reads the
  durable row by event_id and reconciles — same run_id + content replays the
  pre-existing durable event as success (no second row, seq untouched, no
  re-publish), while the same event_id with a different run/kind/payload is
  a typed `event_id_conflict` (never a silent swallow). A guarded
  `WHERE NOT EXISTS` insert plus read-after-write reconciliation closes the
  cross-process race. The maintenance started + completed retries now
  converge exactly once.
- **P2 — terminal writes are durable-first, never `let _ =` (fixed)**:
  every maintenance-run terminal (conflict / error / already_committed /
  could-not-reach-compacting / success) commits through
  `commit_maintenance_terminal`: bounded in-process retries (the A5
  `terminal_persist_retries` / `terminal_persist_retry_delay` knobs), then
  the terminal is parked observably `terminal_pending` in the SAME bounded
  retry loop as A5 (new `PendingTerminalKind::Maintenance` commits via
  `run.transition` + `event.append` + best-effort `compaction.fail`, since
  `run.terminal` only accepts `running` runs). A maintenance run is never
  left durably `compacting` without an owned retry; the same process
  commits the exact terminal once storage recovers, and restart recovery
  repairs the durable side after the window expires. The `compact.started`
  event is durable before any command (abort-and-fail otherwise).
  Continuous-failure fixture
  `a9_compact_continuous_transition_failure_parks_terminal_and_recovers`
  (parked → storage recovers in-process → terminal committed by the retry
  loop → the compact retry commits), plus conflict / commit-step fixtures
  (`a9_compact_failed_row_conflict_fails_maintenance_run_durably`,
  `a9_compact_commit_step_failure_fails_pending_row_and_run_durably`).
- **P3 — mirror semantics**: `compact.started`/`compact.completed` mirror
  payloads carry the same fields as the durable trail (range / id /
  generation; asserted via the SSE replay in
  `a9_compact_canonical_content_and_mirror_events_match_durable`); the
  cross-process already_committed answer refreshes the mirror from the
  committed durable row (compacted range + generation,
  `a9_compact_already_committed_returns_committed_row_and_refreshes_mirror`);
  the compaction context canonicalizes message content exactly like
  `build_production_loop_context`; docs and the build comment now state
  that a missing/uncompilable `compact.rss` is a typed construction error
  (the `compaction_policy_unavailable` 503 is for no-durable-storage
  configurations and runtime policy failures).

Verification (this revision): a9 19/19 (11 original + 8 review fixtures),
agent_loop_production 22/22, a7 11/11, telegram 51/51, storage 28/28,
gateway 64/64, `cargo test --locked --workspace --all-features --all-targets`,
`cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D
warnings`, `git diff --check` — all clean; amended into
`54a5040` (no push).
