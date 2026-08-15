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
| `approval.wait` (approval + state) | bridge `approval.request` (durable), run → `waiting_approval`, park |
| `compact` (plan + state) | run → `compacting`, re-invoke `phase:"compacting"` |
| `compacted` / `compact.failed` (state) | run → `running`, re-invoke `phase:"start"` |
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
`stream`, `parallel`, `task`, `max_output_tokens`, `state_db`, `now_ms`),
plus per-phase `approval` / `tool_calls` / `tool_index` / `plan` fields.

### 4.1 Phase `start`

1. `turn >= max_turns` → `run.completed` (carries `last_text`; the run is
   bounded — the max-turn runaway fixture terminates here).
2. Compaction gate (only when `retry_count == 0` and
   `max_context_messages > 0` and durable history exceeds the window): the
   loop reads the durable history with ordinals via the storage program
   (`message.list`), plans with `compact.rss` (pair-preserving prefix), and
   yields `compact` carrying the plan. Ordinals align with the DB because the
   plan is computed over the durable list.
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
   - `pending` → emit `approval.required`, yield `approval.wait` carrying the
     call + the remaining cycle state.
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
`is_error` tool result when denied/expired (`approval_denied` /
`approval_expired` + reason); continue the remaining cycle inline.

### 4.4 Phase `compacting`

Emit `compact.started`; execute the plan commands through the storage
program (`compaction.start` → `message.compact` → `compaction.commit`),
checking each typed result; on success emit `compact.completed` and yield
`compacted` (state carries the trimmed message list — the prefix is dropped
from the in-run array); on any failure build and execute the typed
`compaction.fail` command and yield `compact.failed` (history untouched, run
continues with the full history — recoverable).

## 5. Service driver (`src/service.rs`)

`run_worker` gains the production path when an `AgentRunner` program (the
built-in `rss/agent/main.rss`) is configured:

- one run-level deadline (`run_timeout`); each invocation is bounded by the
  remaining time; on expiry the typed deadline cancellation path commits
  `run.cancelled` exactly once;
- every re-invocation creates a fresh bounded delivery channel + worker
  (events stay durably appended before publish; subscribers keep the run's
  broadcast sender while parked);
- `approval.wait` → `ApprovalBridge::request_pending` (durable), run
  transition `running → waiting_approval` (durable), park the state; the run
  handle stays alive and holds its capacity permit;
- new `AgentService::resolve_approval(run_id, approval_id, approve)`:
  bridge resolve → `Resumed` → transition `waiting_approval → running` and
  resume with `phase:"approval.resume"` + resolution; `AlreadyResolved` →
  no-op (exact-once); `Terminal` (deny/expire) → transition back to
  `running` and resume with `resolved:false` (typed tool result path);
- expire sweep for parked runs (janitor cadence + explicit call): resolve
  `false` per parked approval → `Terminal` → resume with `resolved:false`;
- `compact` / `compacted` / `compact.failed` → durable run transitions
  `running ↔ compacting` around the loop's storage execution;
- terminal decisions (completed/failed) go through the existing
  exact-once durable terminal commits; `run.cancelled` on cancel/timeout
  (a parked/compacting run is transitioned back to `running` first so the
  A2 `run.terminal` guard matches);
- handoff/rejected decisions → typed terminal failure payloads, never
  fabricated success.

`build_run_context` gains `provider_options` (config), the loop `limits`
(max_turns, max_retries, backoff, approval mode, compaction window, stream),
and the `state_db` file name (for the loop's storage commands); the loop VM
is configured with the SQLite root of the state DB and the configured
`IoPolicy`/`HttpConfig`.

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
