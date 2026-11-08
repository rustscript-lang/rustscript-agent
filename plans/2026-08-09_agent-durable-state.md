# Durable state, run lifecycle, and compaction design

**Status:** current design

This document describes the durable storage model, the exported-run invocation
contract, and the serial agent-loop/compaction policy in this revision. It
consolidates the earlier durable-state, run-lifecycle, and A5 scope documents;
their milestone schedules and verification records are not retained here.

## 1. Architecture

A dedicated storage worker owns one SQLite connection and executes typed
commands produced by RSS storage programs (`rss/storage/*.rss`) through the
generic `sqlite::*` host capability. Mutations commit durably before they are
published to the in-memory store, event subscribers, or API responses. A
failed commit returns a typed error and leaves no visible partial mutation.

The storage worker runs off the Tokio request threads. The gateway passes it a
single-connection policy: `busy_timeout_ms = 5000`, `max_connections = 1`,
`max_statements = 64`, `max_transaction_ms = 5000`, and the configured page
bounds for rows and bytes.

Native Rust contains no SQL statement and no direct SQLite execution path.
Schema, migrations, and business queries are owned by RSS.

## 2. Schema

`schema_migrations` records applied schema versions. The normalized tables are:

| Table | Purpose |
| --- | --- |
| `sessions` | Durable session identity, selected model/provider, workspace binding, generation, end reason |
| `messages` | Ordered conversation rows with role, content JSON, tool-call ID, parent message ID, compacted flag, token estimate |
| `runs` | Run status, parent link, input, model/provider, idempotency identity, turn/token counters, typed error and recovery reason |
| `run_events` | Durable event rows keyed by `(run_id, seq)` with a unique event ID |
| `run_retention` | First retained sequence and high-water mark per run |
| `approvals` | Pending/resolved approval records bound to run, tool call, risk class, expiry, resolver |
| `compactions` | Pending/committed/failed compaction rows keyed by session generation |
| `provider_usage` | Per-run provider/model request and token counters |
| `child_run_links` | Parent/child run relation, ordinal, and state |
| `delivery_cursors` | Per-session consumer delivery cursor |
| `idempotency_records` / `idempotency_claims` / `idempotency_claim_history` | Retry-safe request claims, results, and claim history |
| `recovery_records` | Interrupted-run recovery transitions |
| `jobs` | Durable job records (CRUD only; no scheduler) |
| `plugin_graph_locks`, `plugin_package_refs`, `plugin_activation`, `plugin_activation_history`, `plugin_graph_refs`, `plugin_graph_revocations`, `plugin_graph_pin_requirements`, `plugin_control_guard` | Plugin graph, activation, retention, revocation, and run-pin records |
| `managed_effect_calls` and the managed workspace/effect tables | Native effect journal, checkpoint, publication, and workspace head records |

Every table has explicit keys, timestamps, bounded payload fields, and
foreign-key behavior. Run event identity is `(run_id, seq)`.

## 3. Run lifecycle and invocation stream

The gateway exports one agent entry per RSS source:
`pub fn run(context) -> value`. The structured run context enters RSS as the
sole function argument; RSS never reads ambient runtime input.

```text
RSS entry
  pub fn run(context) -> value

Core invocation items
  Event(value)
  Complete(value)
  Error(runtime_error)
  End

Agent handling
  Event    -> validate -> assign run seq -> durable append -> live delivery
  Complete -> commit run.completed with the returned value
  Error    -> commit run.cancelled or run.failed from the typed code
  End      -> legal only after one terminal item
```

Rules:

- Every accepted run consumes zero or more `Event` items, then exactly one
  `Complete` or typed error, then end-of-stream.
- AgentService owns run identity, event names, timestamps, sequence numbers,
  retention, replay, and delivery.
- The worker stops polling when its bounded delivery path cannot accept
  another event, so execution cannot outrun delivery.
- RSS uses exported callable arguments, ordinary return values, and
  `stream::emit(value)` only.
- Admission reserves capacity, session, run ID, cancellation, and delivery
  state in one operation. Rejection creates no session or run.
- Stop, timeout, disconnect, parent stop, and gateway shutdown map to typed
  cancellation reasons and share the run token with provider calls and owned
  process children.
- A worker that exits without a terminal commits `run.failed` exactly once.

## 4. Event sequencing, retention, and replay

Events append incrementally with a transactionally allocated per-run sequence.
Retained history may begin at `first_seq > 1`; validation starts from the
stored first sequence, not from one. `run_retention` persists the first
retained sequence and high-water mark.

SSE replay uses an exclusive `after_seq` cursor. A cursor older than the
retained history answers `event_cursor_too_old` with the earliest available
sequence. Terminal recovery events use `last_seq + 1`, never retained length.
Event count, payload bytes, and terminal-run TTL are bounded by native
configuration.

Delivery is at-least-once: a subscriber may see the same durable event more
than once and reconnects with `after_seq` for a gap-free replay. Exactly-once
delivery to an external receiver is not claimed.

## 5. Restart recovery

On startup the gateway migrates the schema, then loads bounded indexes and
history. Recovery runs as one typed transaction:

1. Every run in `queued`, `running`, `waiting_approval`, or `compacting`
   becomes `failed` with `error_code = gateway_restart` and
   `recovery_reason = gateway_restart`; one `run.failed` event is appended per
   interrupted run.
2. Every pending approval of a recovered run is expired.
3. Every pending compaction is failed, even when its run is already terminal,
   covering the crash window between the run terminal commit and
   `compaction.fail`.
4. Claimed run idempotency records are expired.
5. Prior events, parent/child links, usage, and messages remain readable.

No prior side effect is resumed automatically. A pending terminal commit is
retried within `terminal_commit_retry_window` (default 300 s), and
`/health/detailed` exposes the pending count as `terminal_pending`.

## 6. Serial agent loop

`rss/agent/main.rss` implements the bundled coding loop:

- single typed context in, one discriminated decision map out;
- `model.started` / `model.completed` event descriptors; terminal
  `run.completed` / `run.failed` decisions are service-owned;
- turn accounting bounded by `max_turns`; tool calls bounded by
  `max_tool_calls`; tool output bounded by `max_tool_output_bytes`;
- retry/backoff only for retryable provider/network errors, bounded by the
  configured base/cap delays and per-turn retry count;
- completed tool effects are never repeated on retry;
- `parallel` and `task`/subagent execution are rejected with
  `unsupported_parallel` / `unsupported_task`;
- tool calls dispatch serially through `rss/tools/dispatch.rss`.

The gateway captures these limits at admission (`RunLimits`) and freezes the
run workspace. The per-run wall-clock deadline is not reset per provider or
tool call.

## 7. Compaction policy

`rss/agent/compact.rss` plans a compaction from ordered history and returns
the typed command sequence:

```text
compaction.start -> message.compact -> compaction.commit
```

On failure it returns the typed `compaction.fail` command.

Context:

```text
session_id, run_id, compaction_id
generation            current session generation; the plan targets +1
messages              ordered {ordinal, role, tool_call_id, content}
config                {max_context_messages, retained_tail, now_ms,
                       model, token_estimate}
```

Decisions:

```text
compact.plan -> generation, source_start_ordinal, source_end_ordinal,
                retained_tail_ordinal, summary_json, commands[3]
compact.skip -> reason "history_within_window" |
                "history_within_retained_tail" | "invalid_config"
```

With `n` messages the naive boundary is `n - retained_tail`; the boundary is
then pushed forward to a fixpoint so no assistant tool-call message inside the
prefix is separated from its tool-result messages. The retained tail is every
message after the adjusted boundary. The fixpoint reaches the last message
only in the forced case where the last message is a tool result whose call
sits in the prefix; histories are bounded by `max_context_messages`, so the
worst-case scan is bounded.

Durable properties:

- `compaction.start` is idempotent for the same session/generation/payload and
  returns typed conflicts for a different payload, an already committed
  generation, or a reused id.
- `message.compact` is a guarded no-op until a committed compaction covers the
  range.
- `compaction.commit` flips the compaction to committed, marks exactly the
  covered ordinal range as compacted, and advances the session generation in
  one transaction.
- Any failure leaves all messages untouched and the generation unchanged;
  the original history stays readable and a failed row records the typed
  error.
- Restart recovery fails every pending compaction; a retry with the original
  id can resume, while a different id is a typed conflict.
- The next provider request uses the committed summary plus the retained
  history tail. Tool-call/tool-result pairs are never split.

Explicit compaction is exposed by `POST /v1/sessions/{session_id}/compact` and
by the Telegram command surface; automatic compaction triggers before a
provider request when the configured message bound is crossed.

## 8. Verification anchors

Storage and lifecycle behavior is covered by `tests/storage_tests.rs`,
`tests/runner_tests.rs`, `tests/gateway_tests.rs`,
`tests/agent_loop_tests.rs`, `tests/run_lifecycle_tests.rs`,
`tests/effect_commit_recovery_tests.rs`, and the gateway reopen paths that
exercise restart recovery. Compaction pair preservation and generation
advancement are covered by the agent-loop and storage suites.
