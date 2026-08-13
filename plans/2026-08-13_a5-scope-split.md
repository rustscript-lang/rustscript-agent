# A5 Scope Split: Serial Loop Policy Skeleton and Durable Compaction Policy

Date: 2026-08-13
Branch: `scope/agent-a5-partial`
Base / integration HEAD: `1299300`
Core checkout: `/mnt/TEMP/rustscript/agent-roadmap/rustscript` at `06b37fd` (pinned)

## 1. Goal and boundary

A5 in the agent roadmap is "script-owned serial agent loop with durable
compaction". This commit series delivers the **independently shippable**
parts of A5 as pure-RSS decision policies with executable tests, while the
parts that depend on the A3 core blocker or on the user-excluded A4/A6
scopes stay out of this branch.

### Delivered (green)

| Deliverable | Files | Commit |
|---|---|---|
| Serial loop policy skeleton | `rss/agent/main.rss` | `feat(agent): add serial loop policy skeleton` |
| Durable compaction policy | `rss/agent/compact.rss` | `feat(agent): add durable compaction policy` |
| Executable policy suites (pure + durable) | `tests/agent_loop_tests.rs` | with the two commits above |
| Canonical context fixtures | `tests/fixtures/agent/loop_context.json`, `tests/fixtures/agent/compaction_context.json` | with the two commits above |
| This scope-split document | `plans/2026-08-13_a5-scope-split.md` | `plan(agent): ...` |
| Two stale SSE capability comments corrected | `src/runtime/rss_runner.rs`, `rss/llm/openai_chat.rss` | `docs(agent): ...` |

### Not delivered (blocked / excluded)

- **A3 core blocker (blocks):** provider adapters' buffered response parsing,
  streaming aggregation, and `http::client::sse` exposure — see
  `plans/2026-08-13_a3-provider-core-blocker.md`. The serial policy never
  calls a provider; a provider call that would succeed is returned as a
  typed blocked capability instead of fabricated success.
- **A4 (user-excluded):** full test harness / approval machinery — no
  `rss/agent/harness.rss`, no approval bridge, no registry/approval wiring.
- **A6 (user-excluded):** parallel/subagent/task execution. The serial
  policy rejects `parallel`/`task` configuration with typed errors and never
  invents parallel or subagent actions.

## 2. Serial loop policy (`rss/agent/main.rss`)

`pub fn run(context: map) -> map` is a state-machine step function: ONE typed
context map in, ONE discriminated decision map out, executed on synthetic
typed inputs (no provider transport, no storage, no tool runner).

Context:

```
turn: int            completed turns so far (0 initially)
max_turns: int       turns allowed before the run terminates
retry_count: int     retries already consumed on the current turn
max_retries: int     retries allowed per turn
phase: string        "start" | "provider_result"
model: string        model name carried by model.* event descriptors
provider: map        canonical {ok, response, error} call result
                     (rss/llm/types.rss shape); ignored in phase "start"
config: map          {base_retry_delay_ms, max_retry_delay_ms,
                      parallel, task}
```

Decisions (kind discriminator; every decision carries an `events` array):

```
blocked       capability "provider.call" | "tool.dispatch" + typed reason
retry         delay_ms (min(base * 2^retry_count, cap)), retry_count+1,
              turn unchanged (a retry does not consume a turn)
next.turn     turn + 1 (a turn without tool calls completed)
run.completed terminal decision after the last allowed turn
run.failed    terminal decision carrying the typed ProviderError
              {status, type, code, message, param, request_id} and reason
              "non_retryable" | "max_retries_exceeded"
rejected      typed rejection: parallel_not_supported, task_not_supported,
              unknown_phase
```

Canonical event descriptors (script-visible events per `src/events.rs`):

```
model.started:   {type: "model.started", turn, model}
model.completed: {type: "model.completed", turn, text, tool_calls}
```

`run.failed` / `run.completed` are SERVICE-OWNED event types; the policy only
describes the terminal decision and never emits them.

Retryability: 429, 408, 5xx, `rate_limit_error`, `server_error` are
retryable; everything else (including the typed `invalid_request_error`
family and `malformed_payload`) is non-retryable.

## 3. Durable compaction policy (`rss/agent/compact.rss`)

`pub fn run(context: map) -> map` plans a compaction from the message
history and returns the exact typed A2 storage command sequence
`compaction.start -> message.compact -> compaction.commit`; with
`command: "fail"` in the context it returns the typed
`{op: "compaction.fail", payload: {id, error_message, completed_at_ms}}`
command for any failure in the sequence.

Context:

```
session_id, run_id, compaction_id: string
generation: int      CURRENT session generation; the plan targets
                     generation + 1 (A2 guards sessions.generation + 1)
messages: array      ordered history, each entry
                     {ordinal, role, tool_call_id, content: array}
                     content parts follow the canonical shapes
                     ({type: "text"|"tool_call"|"tool_result", ...})
config: map          {max_context_messages, retained_tail, now_ms,
                      model, token_estimate}
```

Decisions:

```
compact.plan -> generation, source_start_ordinal, source_end_ordinal,
                retained_tail_ordinal, summary_json, commands[3]
compact.skip -> reason "history_within_window" |
                "history_within_retained_tail" | "invalid_config"
```

### Prefix selection

With `n` messages the naive boundary is `n - retained_tail`; the boundary
is then pushed forward **to a fixpoint** so that NO assistant tool-call
message inside the prefix is separated from its tool-result messages (tool
results always follow their assistant message, so a pushed boundary can
only pull tool messages into the prefix and the loop terminates). The
retained tail is every message AFTER the adjusted boundary.

### A2 storage contract conformance (immutable, not modified)

The A2 storage layer (`rss/storage/compactions.rss`, `messages.rss`) is the
fixed contract; the policy conforms to it exactly:

- `compaction.start` guards: session + run exist, run status is
  `compacting`, `sessions.generation + 1 = generation`,
  `source_start <= retained_tail_ordinal <= source_end`, and messages exist
  at both range endpoints. The retained-tail marker is therefore recorded
  as `retained_tail_ordinal = source_end_ordinal` (the tail is everything
  AFTER the compacted range).
- `message.compact` is a guarded no-op until a committed compaction covers
  the range, so in the prescribed pre-commit position it is an idempotent
  sweep that only a hard failure can reject.
- `compaction.commit` is one atomic transaction: it flips the compaction to
  `committed` (guarded by `source_end_ordinal = end_ordinal`, run still
  `compacting`, session generation unchanged), marks exactly
  `[source_start_ordinal, source_end_ordinal]` compacted, and advances the
  session generation. The harness treats a commit that matched no row
  (`rows_affected == 0`) as a failure and routes it to `compaction.fail`.
- Any failure at any step leaves every message untouched and the session
  generation unchanged: the original history is fully recoverable, and a
  failed compaction is durably recorded with its typed error message.

The execution tests drive the plan through the production A2 storage
service (`rss/storage/main.rss` via the existing `AgentRunner` + typed
command envelope harness) and assert the durable outcome: committed row,
prefix marked compacted, retained tail untouched, generation advanced
exactly once (happy path); `failed` row with the typed error, no message
compacted, generation unchanged (failure path).

## 4. A3 core blocker (unchanged, referenced)

The committed core blocker plan stands:
`plans/2026-08-13_a3-provider-core-blocker.md`. Unblock conditions (all in
the pinned core, out of this repository's scope):

1. `TypeSchema::Callable` for every script prototype must match the declared
   parameter/return types regardless of call-site inference in non-root
   modules (statement-if calls, cross-module accessor arrays).
2. Annotated lets inside tail-position expression-if branches must resolve
   to their declared schema.
3. Closures must be able to by-value-capture locals without forcing `Move`
   on the source (shared-accumulator pattern) to unblock the SSE callback
   aggregation.
4. `json::encode` accepts only struct-shaped values (P3 marker-splice
   surface documented in the blocker plan).

Neither policy module touches the provider adapters, the core, or the
restricted registry; the registry is not extended.

## 5. A4 / A6 exclusions

- A4 full harness and approval machinery: excluded by the user. The
  policies are exercised through the existing test harness pattern only
  (runner + typed contexts + typed storage commands); no approval flow, no
  harness module, no registry changes.
- A6 parallel/subagents: excluded by the user. `main.rss` rejects
  `config.parallel` / `config.task` with typed errors
  (`parallel_not_supported`, `task_not_supported`) and the decision protocol
  contains no parallel/subagent/task action; a dedicated test scans the
  decisions for such constructs.

## 6. Criteria matrix

| Criterion | Status |
|---|---|
| Serial loop: single context map input, discriminated decision output | GREEN (`loop_*` suites, 15 tests) |
| turn/max_turns accounting, turn increments across steps | GREEN (`loop_full_serial_run_advances_turns_and_completes`, `loop_max_turns_terminates_run_completed`) |
| Typed ProviderError retry/backoff decision (429/408/5xx/rate_limit/server_error vs 4xx/invalid_request) | GREEN (`loop_retryable_error_retries_with_backoff`, `loop_backoff_doubles_then_caps`, `loop_nonretryable_error_fails_run`, `loop_max_retries_exceeded_fails_run`) |
| Canonical model.started / model.completed event descriptors and run.failed terminal descriptor | GREEN (`loop_canonical_event_shapes`) |
| Provider call / tool dispatch as typed blocked capability, no fabricated success, no new builtins | GREEN (`loop_start_phase...`, `loop_success_with_tool_calls...`, `loop_decisions_never_invent_parallel_or_subagent_actions`) |
| No parallel/task actions | GREEN (typed rejections + decision scan) |
| Compaction: complete-prefix selection, tool-call/tool-result pairs never split, retained window | GREEN (`compact_plan_*`, 8 pure tests) |
| Compaction executes start -> message.compact -> commit via A2 typed storage; failure -> compaction.fail; no half-commit, history recoverable | GREEN (`compaction_flow_commits_durably_and_retains_tail`, `compaction_failure_marks_failed_and_preserves_history`) |
| No modification of provider adapters / core / registry to work around the A3 blocker | GREEN (no such files touched) |
| No A4 harness/approval, no A6 parallel/subagent scaffolding | GREEN (no such files created) |
| A3 provider parse/stream path | BLOCKED (core, see §4) |
| Full script-owned runner loop (A7/A8 wiring) | NOT IN SCOPE (blocked by A3; later scope) |

## 7. Verification commands (run in the a5 worktree)

```bash
cd /mnt/TEMP/rustscript/agent-roadmap/a5
export CARGO_TARGET_DIR=/mnt/TEMP/rustscript/target-a5
cargo test --locked --test agent_loop_tests          # 25 passed
cargo test --locked --test storage_tests             # A2 regression
cargo test --locked --test runner_tests              # A0/A1 regression
cargo test --locked --all-targets                    # full default scope
cargo test --locked --test core_repro_driver -- --ignored   # A3 repros still failing as documented
cargo test --locked --test provider_tests -- --ignored      # A3 streaming suites still blocked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
git diff --check
```

All temp/target/log artifacts live under `/mnt/TEMP/rustscript/`
(`target-a5`, `agent-tests/`).
