# A8 Telegram → A5 Real Loop/Approval/Compaction Wiring — Completed Scope

Date: 2026-08-16
Branch: `feat/agent-a8-telegram`
Base / integration HEAD: `e70db495bdf07593346f09ede250a7a4ce28bde5`

## 1. Goal

Wire the Telegram adapter's commands to the REAL A5 production serial loop
(the built-in `rss/agent/main.rss` driven by `AgentService`): real admission
and worker spawn for `/run`, the typed cancellation for `/stop`, durable
state for `/status`, session mapping for `/new`, the real A5 approval bridge
for `/approve`/`/deny` (actor/reason persisted, typed no-resume failures),
and an accurate typed availability answer for `/compact` (compaction is
planned and executed by the active loop; there is no manual trigger on the
service). No API/A7 changes, no provider wire parsing, no A5 rewrite.

## 2. Audit result (before this change)

| Command | Before | Gap closed here |
|---|---|---|
| plain text | real admit + spawn worker + renderer (durable idempotency) | unchanged |
| `/run` | NOT a command — treated as conversation text (the `/run` prefix went into the run input) | canonical command: real admit + worker + renderer, echoes the durable run id and admission status |
| `/stop` | real typed cancel through `AgentService::stop` (first-wins, parked runs typed-cancelled) | unchanged |
| `/status` | reads the durable-hydrated store mirror | unchanged code; restart fixture added proving durable reads |
| `/new` | typed cancel + bounded wait + cascade delete + recreate + epoch bump | unchanged |
| `/compact` | stale text ("blocked until the A5 integration lands") | accurate typed availability: loop-managed answer for an active run, no-run answer otherwise; never claims a manual compaction |
| `/approve` / `/deny` | NOT commands — the text `/approve <id>` admitted a run as input | canonical commands resolving ONE explicit durable approval id through `resolve_run_approval_as` |
| renderer | `approval.required` line without the id | line now carries the real approval id and the `/approve`/`/deny` commands |

## 3. What was actually completed

### `src/gateway/telegram.rs`

- `parse_command` recognizes `run`, `approve`, `deny` in addition to
  `new`/`stop`/`status`/`compact` (unknown `/x` stays conversation text).
- `admit_and_spawn` (extracted from `admit_text`, behavior unchanged):
  gate check → durable idempotency key → real `AgentService::admit` →
  worker + renderer spawn; returns the `AdmittedRun` on a fresh admission.
  `admit_text` is now a thin wrapper (no identity echo).
- `cmd_run`: real admit + spawn, then replies
  `Run <run_id> started (status: started).` — the durable run id and the
  admission status, no secrets.
- `cmd_approval` (`/approve` / `/deny <approval_id>`): exactly one
  whitespace-delimited id; durable `approval.get` on a blocking thread;
  typed replies (never a resume) for: missing id (usage), multi-token id
  (usage), unknown id, approval whose durable session differs from the
  chat's session (isolation/permission), already-resolved row
  (`state != pending`), park consumed by a stop
  (`no pending approval is parked`), and bridge unavailability. Success
  resolves through `AgentService::resolve_run_approval_as` on a blocking
  thread with actor `telegram:<user_id>` and reason
  `approved|denied via telegram message <chat:message>` persisted on the
  durable row (`resolver` / `decision_reason` columns), then replies
  `Approval <id> approved|denied; the run continues.`
- `cmd_compact`: no session → "no conversation yet"; active run (gate or
  store started/stopping) → the typed loop-managed answer (no manual
  trigger — the service has no manual compaction entry, compaction is
  loop-planned and service-executed); no active run → "nothing to compact".
- The update handler dispatches the new commands; allowlists, dedup,
  chat/thread/session isolation, bounded reply routing, and the delivery
  renderer are unchanged.

### `src/gateway/telegram_render.rs`

- `approval.required` renders
  `[approval] <tool> requires approval (pending) — /approve <id> or /deny <id>`
  when the payload carries the real bridge-generated `approval_id` (the
  previous id-less line is kept when the id is absent).

### `src/service.rs`

- `resolve_run_approval` now delegates to the new
  `resolve_run_approval_as(run_id, approve, actor, reason)`, which passes
  the actor/reason through to the bridge. The generic path keeps the exact
  previous strings (`gateway`, `approved by resolver` / `denied by
  resolver`); all park/resume/AlreadyResolved semantics are unchanged.

### `src/runtime/approval_bridge.rs`

- `resolve` delegates to the new `resolve_with_reason(approval_id, approve,
  resolver, decision_reason, now_ms)`; the generic path keeps the previous
  hardcoded reasons.

### Tests (all RED first, then GREEN)

- `src/gateway/telegram.rs` unit test: `run`/`approve`/`deny` parsing.
- `src/gateway/telegram_render.rs` unit test: approval.required line with
  the id and the commands.
- `tests/telegram_tests.rs` (real Telegram update fixture + SQLite +
  service worker):
  - `/run` admits a real run, echoes the durable run id/status, the
    command argument reaches the run input, the run completes durably;
  - duplicate `/run` update admits exactly one run (dedup + durable
    idempotency);
  - `/approve` resolves a REAL parked approval of the production loop:
    durable row `approved`, actor `telegram:555`, reason
    `approved via telegram message 555:111`, the approved `file.write`
    really executes, the run completes, and a second `/approve` is a typed
    no-op that never resumes (provider request count unchanged);
  - `/deny` folds the typed denial, the tool never executes, the row
    records `denied` with the actor/reason, the loop continues;
  - typed approval errors never resume: missing id, unknown id,
    multi-token id, and a foreign-chat `/approve` (session isolation —
    row stays pending, run stays parked, the owning chat can still
    resolve);
  - stop/approval race: `/stop` cancels the parked run, a late `/approve`
    of the same durable id is a typed no-op, the run stays cancelled, no
    tool round starts;
  - `/compact` active-run answer (loop-managed, no manual trigger) and
    terminal-run answer (nothing to compact), never claiming completion;
  - `/status` reflects the durable state across a gateway restart.
  - the existing commands fixture asserts the new `/compact` no-run text.

## 4. Honest boundaries

- `/compact` does NOT trigger a compaction: the service exposes no manual
  compaction entry (compaction is planned by the loop and executed by the
  service while the run is durably `compacting`), so the adapter answers
  the typed availability truthfully and never claims a compaction ran.
- `/approve`/`/deny` resolve through the service's park machinery only;
  the adapter never writes approval rows directly.
- The legacy single-shot source path (no A5 program) keeps working; the
  wiring tests cover both the legacy path (`/run` echo) and the real A5
  production loop (approvals, compaction availability, stop race).

## 5. Verification

```bash
cd /mnt/TEMP/rustscript/agent-v2-a8-telegram
export CARGO_TARGET_DIR=/mnt/TEMP/rustscript/a5-target TMPDIR=/mnt/TEMP/rustscript/a8-tmp
cargo test --locked --test telegram_tests
cargo test --locked --test agent_loop_e2e_tests   # A5 regression
cargo test --locked --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
git diff --check
```

## 6. Review fixes (amended into this commit)

### Durable per-run origin actor (schema v5)

- `runs.origin_actor TEXT NOT NULL DEFAULT ''` is added by a REAL migration
  (`agent-storage-v5-run-origin`, `ALTER TABLE runs ADD COLUMN ...`), never
  by editing the v1 CREATE TABLE: fresh databases reach v5 through migration
  1 + 5, and released v1 databases upgrade through the same ALTER. The
  migration test crafts a genuine v1-era run row, upgrades it, and asserts
  the row survives with an EMPTY origin actor (owner-less rows are
  typed-rejected, never fabricated or fatal).
- Admission (`admission.create`) persists the origin actor; `run.get` /
  `run.list` return it as column 21. API-server admissions pass `None`
  (empty origin — those runs are owner-less and typed-rejected by the
  Telegram gate).

### `/approve` / `/deny` owner authorization (the oracle fix)

- `cmd_approval` now gates resolution on the DURABLE owner binding: the
  approval must belong to the chat's session AND the sender must equal the
  run's durable `origin_actor` (`telegram:<user_id>`). The allowlist is
  only the entry permission.
- A foreign chat, a non-owner allowlisted sender in the same chat, an
  owner-less pre-v5 row, and an id that never existed all produce the
  BYTE-IDENTICAL `No such approval: <id>.` reply — existence and state
  never leak, the park is never consumed, and the owner can still resolve.
- The owner binding survives restarts because it is durable (never an
  in-memory-only map): the restart test parks in phase 1, reopens the same
  database in phase 2, and asserts the same contract.

### Bare `/run` and stop cleanup

- A bare `/run` (no input text) is a usage error: it replies
  `Usage: /run <text>.` and NEVER admits a run (no durable run, no worker).
- A `/stop` that consumes a parked approval now cancels the durable
  approval row immediately via the A5 `approval.cancel` op (resolver
  `gateway-stop`, pending-only so a landed resolve is never downgraded)
  instead of leaving the row pending for the default TTL sweep.

### Compatibility guarantees

- `AdmitRunRequest` gains `origin_actor: Option<String>` (Default-compatible);
  every construction site is updated, the A7 API server passes `None`, and
  no A7 route semantics changed.
- Storage test payloads carry the new admission field; the released-v1
  upgrade test covers old-row survival.
