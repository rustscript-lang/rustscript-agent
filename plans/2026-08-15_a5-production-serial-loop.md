# A5 Production Serial Agent Loop — Design and Scope

Date: 2026-08-15
Branch: `feat/agent-a5-production`
Base / integration HEAD: `dda102c`
Core pinned: `rustscript-lang/rustscript@fd4b570d08d7cc90cc29e3b05df59c9e9bf3b88e` (unchanged)

## 1. Goal

Replace the A5 policy-only skeleton (`rss/agent/main.rss` returns typed
BLOCKED capability decisions) with a **production serial agent loop** that
AgentService actually drives: model → tool → result → final rounds against
real provider adapters, durable events, durable approvals with exact-once
wait/resume, real durable compaction, and honest typed handling of the
terminal-tool core gap and the parallel/task handoff. No policy-only blocked
provider/tool capability remains.

## 2. Ownership (unchanged from the gateway-api plan §1)

- **RSS owns**: the serial loop state machine, canonical LlmRequest
  construction, provider/profile dispatch, tool registry/approval/compaction
  policy, storage command execution (compaction), and every script-visible
  event (`stream::emit`).
- **Rust owns**: lifecycle (timeout, cancel, retry sleep, run/approval
  transitions), capability composition (http/io/sqlite policy), and durable
  sequencing (event delivery, approval bridge persistence, terminal commit).
  Rust never parses provider wire and never writes agent policy.

## 3. Loop shape: one step-function invocation per external wait

`main.rss::run(context)` is a **step function**: one typed context map in,
one discriminated decision map out. The loop runs internally across provider
calls and tool rounds; it yields a decision ONLY when an external service
side effect is required:

| Decision | Service side effect |
|---|---|
| `run.completed` (carries final text) | durable terminal commit (`run.completed`, exact-once) |
| `run.failed` (carries typed ProviderError + reason) | durable terminal commit (`run.failed`, exact-once) |
| `retry` (delay_ms, state) | sleep `min(delay, remaining deadline)`, re-invoke with state |
| `approval.wait` (approval + state) | re-check cancellation, bridge `approval.request` (durable), emit `approval.required` with the REAL bridge id (exactly once), run → `waiting_approval`, park (with the original run deadline) |
| `compact` (plan + state) | re-check cancellation, run → `compacting`, execute the planned commands (`compaction.start` → `message.compact` → `compaction.commit`, or `compaction.fail`), run → `running`, re-invoke `phase:"compact.result"` with `compact_ok`/`compact_error`; on success refresh `generation`/`compaction_id`/`message_count` so the SAME run can compact again |
| `compact.result` (state) | the loop emits `compact.completed`, trims the compacted prefix on success, and continues with the provider call |
| `parallel.handoff` / `subagent.handoff` | typed terminal failure (`parallel_execution_unavailable` / `task_execution_unavailable`) — the A6 native supervisor needs the A7 run-admission interface; the loop never fabricates parallel/subagent outcomes (see §7) |
| `rejected` / unknown | typed terminal failure |

Loop state (messages, turn, retry_count, last_text, pending tool-call cycle)
round-trips inside the decision maps; the service copies typed fields, never
parses provider wire.

## 4. Loop policy (`rss/agent/main.rss` rewrite)

Context (flat, typed): `run_id`, `session_id`, `phase` (`start` |
`approval.resume` | `compacting`), `turn`, `retry_count`, `max_turns`,
`max_retries`, `model`, `provider`, `provider_options`, `system_prompt`,
`messages`, `config` (`base_retry_delay_ms`, `max_retry_delay_ms`,
`max_context_messages`, `retained_tail`, `approval_mode`, `native_hard_deny`,
`stream`, `parallel`, `task`, `max_output_tokens`, `now_ms`, `generation`,
`message_count`, `compaction_id`),
plus per-phase `approval` / `tool_calls` / `tool_index` / `plan` fields.

### 4.1 Phase `start`

1. `turn >= max_turns` → `run.completed` (carries `last_text`; the run is
   bounded — the max-turn runaway fixture terminates here).
2. Compaction gate (only when `retry_count == 0` and
   `max_context_messages > 0` and the seeded history exceeds the window):
   the SERVICE seeds the loop context from the durable session
   (`build_production_loop_context`) — there is NO `message.list` read gate;
   the loop plans with `compact.rss` (pair-preserving prefix) over the
   seeded history and yields `compact` carrying the plan. Ordinals align
   with the DB because the seeded entries mirror the durable message
   ordinals and tool messages carry the message-level `tool_call_id`
   (the durable `messages.tool_call_id` column mirror), so the pair
   fixpoint stays correct across reloads.
3. Otherwise: if `retry_count == 0` emit `model.started {turn, model}`; build
   the canonical LlmRequest (system prompt as a system message, registry tool
   schemas via `rss/harness/registry.rss`, `provider_options` from the
   context); dispatch by provider name to `openai_chat` /
   `openai_responses` / `anthropic_messages` adapters or `openrouter` /
   `deepseek` / `opencode_zen` / `opencode_go` / `custom` profile modules
   (buffered or `stream: true` — the adapters aggregate; the loop emits one
   canonical `model.delta` with the text, then `model.completed`).
4. On `ok`: emit `model.delta` + `model.completed {turn, text,
   tool_calls: N}`; no tool calls → `run.completed` (final text; the service
   appends the assistant message at terminal); tool calls → append the
   assistant message (text + `tool_call` parts) to the in-run messages and
   enter the tool cycle.
5. On typed error: non-retryable → `run.failed {reason: "non_retryable"}`;
   retries exhausted → `run.failed {reason: "max_retries_exceeded"}`;
   otherwise `retry {delay_ms: backoff(base, retry_count, cap)}` (same turn,
   `retry_count + 1`).

### 4.2 Tool cycle (one call at a time, inline across calls)

For each `{id, name, arguments}` call:

1. Emit `tool.started {tool_call_id, name}`.
2. `registry.rss` describe → unknown tool → typed `is_error` tool result.
3. `approval.rss` decide with the config approval mode and the native
   hard-deny flag:
   - `approve` → dispatch the bounded capability module: `file.rss`
     (`read`/`write`), `patch.rss` (`apply`), `terminal.rss` (`run` — the
     confirmed core gap returns the typed `capability_unavailable` /
     `process_timeout_unavailable`, never a fabricated success);
   - `deny` → typed `is_error` tool result (`approval_denied`);
   - `pending` → yield `approval.wait` carrying the call + the remaining
     cycle state. The loop does NOT emit `approval.required`: the SERVICE
     persists the approval through the bridge and emits the event with the
     bridge-generated id (durable-first, exactly once per park). An
     unrecognized policy action is a typed `run.failed`
     (`invalid_approval_action`) — never a silent deny and never a pending.
4. Append the canonical tool message
   `{role: "tool", content: [{type: "tool_result", tool_call_id, content,
   is_error}]}` to the in-run messages; emit `tool.completed`; continue.
5. Cycle end → `turn + 1`: `turn + 1 >= max_turns` → `run.completed`
   (carries `last_text`), else `next.turn` (service re-invokes
   `phase:"start"` with the state).

### 4.3 Phase `approval.resume`

Emit `approval.resolved {approval_id, tool_call_id, resolved}`; dispatch the
pending call when `resolved` (exactly-once by the durable bridge — the
service only resumes on `Resolution::Resumed`), or produce the typed
`is_error` tool result when denied/expired — the resume context carries the
typed `outcome` (`approved` | `denied` | `expired`) so the loop selects the
`approval_denied` / `approval_expired` code; continue the remaining cycle
inline. An approval envelope missing the `action` key is a typed
`invalid_approval_action` failure, never a silent deny (see §4.2).

### 4.4 Phase `compact.result`

The LOOP plans the compaction (compaction gate at the start of a turn when
`retry_count == 0` and the durable history exceeds the window) and yields
`compact` carrying the typed A2 command sequence. The SERVICE executes
the commands (`compaction.start` → `message.compact` → `compaction.commit`, or
`compaction.fail` on any typed rejection — including an unknown command in
the plan, which is a typed failure, never a silent continue) while the run
is durably `compacting`, then re-invokes
`phase:"compact.result"`. The loop emits `compact.completed {ok, error}`; on
success it trims the compacted prefix from the in-run message list and the
service refreshes the base config (`generation`, `compaction_id`,
`message_count`) so a SECOND compaction in the same run targets the next
generation. On failure the history is untouched and the run continues
(recoverable).

Pair preservation is enforced by `compact.rss`'s prefix fixpoint over
message-level pair ids: the loop's in-run tool messages and the service's
seeded context entries both carry the message-level `tool_call_id` (the
durable `messages.tool_call_id` column mirror), and `compact.rss` falls
back to the `tool_result` content part when the message-level id is absent
— a prefix boundary can never separate an assistant tool-call message from
its tool results, so the provider never sees a dangling `tool_result`.

## 5. Service driver (`src/service.rs`)

`run_worker` gains the production path when an `AgentRunner` program (the
built-in `rss/agent/main.rss`) is configured:

- one run-level deadline (`run_timeout`); the deadline is created once at
  admission and CARRIED by the park: a resume after an approval passes the
  ORIGINAL deadline back, so park time counts against the run wall clock and
  a parked run whose deadline passed cancels with the typed `deadline`
  reason on resume. Each invocation is bounded by the remaining time; on
  expiry the typed deadline cancellation path commits `run.cancelled`
  exactly once (a stop that raced the deadline keeps its own typed reason);
- every re-invocation creates a fresh bounded delivery channel + worker
  (events stay durably appended before publish; subscribers keep the run's
  broadcast sender while parked);
- `approval.wait` → cancellation re-check (no durable approval row may be
  created after a stop/cancel), `ApprovalBridge::request_pending` (durable),
  the `approval.required` event is appended durably and published with the
  REAL bridge-generated id (exactly once per park), run transition
  `running → waiting_approval` (durable), park the state WITH the original
  deadline; the run handle stays alive and holds its capacity permit;
- `AgentService::resolve_run_approval(run_id, approve)` (the approval id
  rides in the park): bridge resolve → `Resumed` → transition
  `waiting_approval → running` and resume with `phase:"approval.resume"` +
  resolution + the parked deadline; `AlreadyResolved` → a strict typed
  no-op (the park is restored for the expiry resume path; the call NEVER
  resumes with `resolved:false`); `Terminal` (deny/expire, typed code) →
  transition back to `running` and resume with `resolved:false` and the
  typed outcome (the loop folds the `approval_denied` / `approval_expired`
  tool result). Once the bridge durably resolves the row, the OUTCOME is
  recorded on the park: a transition failure restores the park WITH the
  recorded decision, so a retry never re-resolves the durable row and never
  downgrades an approve to a deny. A bridge/storage/transition failure
  NEVER drops the park while the run is active: it is restored so a retry,
  the expiry sweep, or a stop stays reachable (no permanent wedge);
- expire sweep for parked runs (janitor cadence): the WHOLE sweep — the
  typed `approval.expire` command plus the per-run storage reads — runs on a
  blocking worker (never on a Tokio thread); expired rows resume with
  `resolved:false`;
- **deadline-orphan approval compensation (final P2)**: the durable
  `approval.request` runs on a blocking thread bounded by the remaining run
  deadline with the approval id known BEFORE the request starts (passed
  idempotently — the storage layer `INSERT OR IGNOREs` by id, so a retry can
  never duplicate the row). The JoinHandle is KEPT: when the deadline fires
  first, the background request still completes — and if its insert wins the
  lock race, a pending row would exist with NO park and NO
  `approval.required` event. A compensation watcher awaits the join and
  durably cancels (expires, pending-only) THAT SPECIFIC row the moment the
  request completes (`approval.cancel`), so no park-less orphan can wait out
  the approval_timeout sweep. The cancel is targeted by id: a legitimate
  park's row (a different id) is never touched, and a missing row is a typed
  no-op. On gateway shutdown/restart the recovery contract covers the crash
  window: restart recovery expires EVERY pending approval whose run is
  already terminal (a pending row on a terminal run is by definition an
  orphan — the park sequence never runs after a terminal commit), mirroring
  the unconditional compaction fail-sweep;
- every step's bounded delivery drain: when the drain cannot finish within
  `cancellation_grace` (a runaway worker keeps the bounded channel fed while
  the delivery task is stalled — e.g. on a storage stall), the tail is NOT
  silently dropped: the service durably appends the typed `run.truncated`
  marker (reason + drain bounds only — `grace_ms`, `channel_capacity`,
  `dropped:true`, never event payloads or tool arguments) BEFORE the
  terminal, so a replay always sees the truncation boundary (marker seq <
  terminal seq, no event after the terminal). If even the marker cannot be
  persisted, the run fails with the typed `persistence_unavailable`
  contract — never a silent tail drop (same contract on the legacy
  single-shot drain);
- `compact` / `compact.result` → durable run transitions
  `running ↔ compacting` around the service's execution of the loop-planned
  commands; a stop/cancel is re-checked before the transition AND inside the
  execution worker, so no compaction row is ever created after a stop; on
  success the in-memory session marks the range compacted and advances the
  session generation (new runs filter the compacted rows even within the
  window);
- every tool cycle's assistant (tool-call) and tool-result messages are
  persisted durably (message.append, durable-first) before the loop
  continues, parks, or commits a terminal — the max-turn terminal carries
  the current round's REAL text (never a stale or empty assistant);
- handoff/rejected decisions → typed terminal failure payloads, never
  fabricated success.

`build_run_context` gains `provider_options` (config), the loop `limits`
(max_turns, max_retries, backoff, approval mode, compaction window, stream),
and the durable seeding of the loop context from the loaded session; the
loop VM is configured with the SQLite root of the state DB and the
configured `IoPolicy`/`HttpConfig`. The loop context carries no `state_db`
key: the loop plans compaction and the SERVICE executes the typed storage
commands through the persistence handle (the script never reads a DB file
name).

## 6. Gateway default loading and configuration

- `AgentGatewayState` keeps the legacy `with_agent_source` (inline single
  source) path for existing lifecycle tests; a new default
  `with_default_agent_program()` compiles `rss/agent/main.rss` (module graph)
  from the crate and is used by `rustscript-agent-gateway` when
  `RUSTSCRIPT_AGENT_SCRIPT` is unset — the built-in agent is available in the
  real gateway without test injection.
- New `AgentGatewayConfig` fields: `provider_options` (JSON), `max_turns`,
  `max_retries`, `base_retry_delay_ms`, `max_retry_delay_ms`,
  `approval_mode`, `approval_timeout`, `max_context_messages`,
  `retained_tail`, `stream`, `parallel`, `task`; new env vars
  `RUSTSCRIPT_AGENT_PROVIDER_BASE_URL`, `RUSTSCRIPT_AGENT_PROVIDER_API_KEY`,
  `RUSTSCRIPT_AGENT_PROVIDER_MODEL`, `RUSTSCRIPT_AGENT_MAX_TURNS`,
  `RUSTSCRIPT_AGENT_MAX_RETRIES`, `RUSTSCRIPT_AGENT_APPROVAL_MODE`,
  `RUSTSCRIPT_AGENT_APPROVAL_TIMEOUT_SECS`,
  `RUSTSCRIPT_AGENT_MAX_CONTEXT_MESSAGES`, `RUSTSCRIPT_AGENT_RETAINED_TAIL`,
  `RUSTSCRIPT_AGENT_STREAM` — all documented in `docs/configuration.md`
  (the docs-consistency guards enforce this).

## 7. A6 handoff: honest, no fabrication

The serial loop yields the typed `parallel.handoff` / `subagent.handoff`
decisions (with `executable:false` + `blocked_reason`) exactly as before; the
service answers them with a typed terminal failure. The A6 native supervisor
(`src/runtime/subagent_supervisor.rs`) is proven ready, but wiring it to real
child runs requires the A7 run-admission interface (the route that carries
`parent_run_id` and manages child-run lifecycle/results) — that is out of A5
scope per the task ("或明确证明仍需A7接口"). A dedicated test scans loop
decisions for fabricated parallel/subagent actions and asserts the typed
terminal handling.

## 8. Confirmed core gaps (unchanged, honest)

- **Bounded foreground terminal**: `io::popen` at `fd4b570` has no
  per-invocation timeout and no argv form → `terminal.rss` returns the typed
  `capability_unavailable` / `process_timeout_unavailable`; the loop folds it
  into a typed `is_error` tool result. No private host function.
- **Script-internal task surface**: no `task::spawn` → handoff is typed and
  non-executable (see §7).
- **Multi-module exported entry collision**: the pinned core flattens every
  merged module's exported callables into one name-keyed table, so a
  multi-module program cannot expose a root entry named `run` (the
  harness/storage modules export `run` themselves); the production loop's
  entry is the unique `agent_run` and the embedding resolves it explicitly.
- **Script-to-script `StorageCommand` construction**: the loop cannot build
  the A2 `StorageCommand` struct value across module boundaries (struct
  constructor gap), so the loop PLANS typed command payloads and the service
  EXECUTES them through the storage program — durable sequencing stays the
  service's ownership lane (see §4.4).

## 9. End-to-end fixtures (new, all through the real service + default program)

1. text-only round: `model.started → model.delta → model.completed →
   run.completed`, assistant message appended, events durable.
2. tool round: `file.write` executes against a real io root; typed tool
   result backfilled; second provider call completes.
3. provider retry: 429 ×2 → backoff sleeps → success (turn/retry accounting).
4. provider non-retryable error: `run.failed` with the typed ProviderError.
5. cancel mid-run: typed `run.cancelled`, exact-once.
6. approval wait/resume: park (`waiting_approval` durable), resolve approve →
   exact-once resume → tool executes → completes; second resolve is a no-op.
7. approval deny: typed `is_error` tool result; loop continues.
8. max-turn runaway: provider always tool-calls; bounded by `max_turns`.
9. compaction: seeded durable history → loop plans + executes
   start→mark→commit; committed row, prefix marked, generation advanced;
   failure path records `compaction.fail` and the run continues recoverably.
10. handoff: `config.parallel`/`config.task` → typed terminal, no fabricated
    outcome.
11. review-fix fixtures (A5 findings A–J): resolve fault recovery keeps the
    park retryable and stop reachable; stop racing the approval park or the
    compaction never wedges the run and creates no post-stop approval/
    compaction rows; park time counts against the run deadline; the expiry
    sweep durably expires rows and resumes typed; a second compaction in the
    same run commits with a refreshed generation; tool-cycle messages are
    durable-first and the max-turn terminal carries the current round's real
    text; new-run history filters compacted rows; `approval.required`
    carries the real bridge id exactly once; the legacy run context carries
    the inbound platform; the built-in storage program load is fallible
    without a source tree.
12. review-round-two fixtures (A5 findings K–P, 2026-08-16): the compaction
    pair boundary — a seeded tool pair straddling the naive boundary is
    never split (committed range covers the result; the provider request
    contains no dangling `tool_result`) and the pair ids survive a reload
    (message-level `tool_call_id` in the durable column → loop context);
    an approval envelope missing the `action` key fails typed
    (`invalid_approval_action`, never a silent deny); the expired resume
    folds the typed `approval_expired` tool result (deny stays
    `approval_denied`); a bridge resolve whose run transition fails restores
    the park WITH the recorded durable outcome so the retry never
    re-resolves and never downgrades an approve to a deny (the approved
    file.write really executes); `AlreadyResolved` is a strict typed no-op
    that never resumes with `resolved:false` (the expiry resume path still
    works); an unknown compaction command in the plan is a typed failure
    and the run continues with no compaction row.
13. review-round-three fixtures (final P1/P2 close-out, 2026-08-16): the
    Anthropic wire is legal — a canonical `tool`-role message becomes the
    Messages API's `user` role with a `tool_result` block carrying the
    official `tool_use_id` (same path through the custom profile adapter);
    the E2E dangling-result probe understands the OpenAI Chat
    (role=tool/content string/tool_call_id), OpenAI Responses
    (`function_call_output` items), and Anthropic (user/tool_result)
    wire shapes (self-tested), and the compaction E2Es exercise it with the
    retained pair on the wire; every `invoke_loop_step` cancel/error/join/
    timeout branch drains the fresh delivery path BEFORE the typed terminal
    (tail events durable and replayed before the terminal; the delivery
    outcome is checked on the error branches too); `park_for_approval`
    re-checks stopping atomically AFTER the park insert (and the
    approval.required append rejects a stopping run), so a stop racing the
    park insert cancels typed immediately — never a 600s parked wedge and
    never a post-stop approval.required event (controllable SQLite-lock
    race fixture); `bridge.request_pending` runs on a blocking thread
    bounded by the remaining run deadline (a single Tokio worker stays
    responsive while SQLite stalls); `compact.rss`'s content-part fallback
    takes the FIRST `tool_result` id (multi-part tool message test,
    consistent with the Rust mirror); in-memory-only mode mirrors the
    tool-cycle messages into the session so a second run on the same
    session never silently loses the first run's tool history.
14. final-P2 close-out fixtures (2026-08-16): the deadline-orphan approval
    race — the blocking `approval.request` is stalled past the run deadline
    (controllable RESERVED hold), the run cancels typed (`deadline`), and
    the late request's insert either loses the lock race (the storage guard
    rejects it — no row) or wins it (the compensation durably cancels that
    specific row the moment the request completes); in a SHORT window no
    pending orphan row exists and no `approval.required` event is emitted
    (janitor disabled so the expiry sweep can never be the cleaner); the
    pre-known approval id is idempotent (a retry never duplicates the row);
    `approval.cancel` expires exactly the target pending row, never a
    legitimate park's row, and is a typed no-op on missing/resolved rows;
    gateway reopen expires an orphaned pending approval whose run is
    already terminal; the drain-truncation race — a runaway emitter fills
    the bounded channel while the delivery task is stalled, the step
    deadline + both grace windows elapse under the hold, and the drain
    times out: the typed `run.truncated` marker is durably recorded BEFORE
    `run.cancelled`, no event replays after the terminal, and the truncated
    tail is never silently delivered in full.

## 10. Verification

```bash
cd /mnt/TEMP/rustscript/agent-v2-a5
export CARGO_TARGET_DIR=/mnt/TEMP/rustscript/a5-target TMPDIR=/mnt/TEMP/rustscript/a5-tmp
cargo test --locked --test agent_loop_production_tests   # policy suites
cargo test --locked --test agent_loop_e2e_tests          # service fixtures
cargo test --locked --workspace --all-targets            # regression gate
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
git diff --check
```

All target/tmp artifacts live under `/mnt/TEMP/rustscript/`. No A7 HTTP
routes and no A8 Telegram code are touched.
