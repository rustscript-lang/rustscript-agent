# Agent Run Lifecycle and Invocation Item Stream Plan

**Goal:** Give every agent run one authoritative lifecycle by invoking exported RSS `run(input)` functions and consuming a small Rust-like item stream with live events and one terminal result.

**Architecture:** AgentService reserves a run atomically, passes the structured run context as the sole argument to the exported RSS entry function, and drives the core invocation stream. `Event(Value)` items are validated, sequenced, persisted, and delivered by AgentService; `Complete(Value)` commits success; a typed error commits cancellation or failure. A bounded delivery channel controls polling and therefore provides backpressure without a second event buffer in core.

**Tech Stack:** Rust 2024, Tokio/Axum, RustScript exported callables, core invocation item stream, generic cancellation and capability profiles.

---

## 1. Independence and dependency

- Independent of durable schema design except for terminal/event persistence hooks.
- Depends on the core invocation item stream and unified cancellation lifecycle.
- API Server and Telegram both consume the same AgentService.

## 2. Scope boundary

### In scope

- Exported `run(input)` entry contract.
- Ordered consumption of `Event` and `Complete` stream items.
- Live bounded event delivery.
- Atomic admission/session reservation.
- Stop, timeout, disconnect, CPU budget, and worker-exit semantics.
- One terminal transition and bounded in-memory lifecycle.

### Out of scope

- VM internal implementation.
- Generator syntax or resume-value semantics.
- Provider protocol parsing.
- Durable SQL/schema details.
- Job/cron execution.
- Platform-specific rendering.

## 3. Agent-side stream contract

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
  Complete -> commit run.completed with returned value
  Error    -> commit run.cancelled or run.failed from typed code
  End      -> legal only after one terminal item
```

Rules:

- Structured input enters RSS only as the exported function argument.
- Event items never carry terminal output.
- AgentService owns run identity, event names, timestamps, sequence numbers, retention, replay, and delivery.
- The worker stops polling when its bounded delivery path cannot accept another event; core execution therefore cannot outrun delivery.
- RSS uses only exported callable arguments, ordinary return values, and `stream::emit(value)`; no ambient-input or JSON-specific emit builtin, `RunOutcome`, terminal future, event receipt, or stack/event fallback is used.

## 4. Implementation route

### Milestone 1: Add failing lifecycle and ordering tests

**Files:**
- Modify: `tests/runner_tests.rs`
- Modify: `tests/gateway_tests.rs`
- Add race/timeout fixtures under `tests/fixtures/`

Required cases:

1. The exact structured context reaches exported `run(input)` unchanged.
2. `Event(a)`, `Event(b)`, `Complete(c)`, `End` preserves order and returns `c`.
3. `Complete(c)`, `End` works with zero events.
4. An event is observable before RSS completion.
5. An early stream end without `Complete` or typed error fails the run.
6. A duplicate terminal item is rejected.
7. Concurrent admission at capacity admits exactly the configured count.
8. Rejected admission leaves no empty session/run.
9. Stop and timeout wait for bounded worker exit.
10. A pure CPU loop reaches terminal cancellation within the configured bound.
11. Event and terminal-run memory obey configured limits and TTL.

### Milestone 2: Consume the exported invocation stream

**Files:**
- Modify: `src/lib.rs`
- Create/refine: `src/runtime/rss_runner.rs`

1. Compile/cache RSS per script version and initialize one isolated VM per active run.
2. Resolve the exported `run` callable and reject missing or incompatible entry signatures.
3. Pass the canonical run context as one `Value` argument.
4. Drive the core invocation until `Pending`, `Event`, `Complete`, or typed error.
5. Return only the value carried by `Complete`.
6. Remove ambient-input builtins, event sink collection, `events.last()`, and `vm.stack().last()`.
7. Preserve typed terminal errors and cancellation reasons without string comparison.

### Milestone 3: Deliver event items with bounded backpressure

**Files:**
- Create/refine: `src/events.rs`
- Create/refine: `src/runtime/delivery.rs`
- Modify gateway SSE paths

1. Validate each `Event(Value)` against the canonical agent event schema.
2. Allocate one monotonic per-run sequence at the AgentService boundary.
3. Append the event durably before publishing it to live subscribers.
4. Send through a bounded Tokio channel.
5. Stop polling the invocation while the bounded path is full; resume after capacity returns.
6. Treat subscriber lag according to replay/cursor policy without changing core stream semantics.
7. Keep platform rendering outside the event service.

### Milestone 4: Make admission atomic

**Files:**
- Create/refine: `src/service.rs`
- Modify run/session creation handlers

1. In one reservation, validate capacity, resolve/create session, reserve run ID, and install cancellation/delivery state.
2. Publish the run only after reservation succeeds.
3. Roll back every intermediate state on failure.
4. Use semaphores/reservation tokens instead of count-then-insert phases.

### Milestone 5: Make cancellation authoritative

**Files:**
- Modify: `src/runtime/rss_runner.rs`
- Modify: `src/service.rs`
- Test: lifecycle cancellation fixtures

1. Map client stop, disconnect, timeout, CPU budget, parent stop, and gateway shutdown to typed core cancellation reasons.
2. Cancel the active invocation and its owned host operations.
3. Wait only for the configured grace period.
4. Stop accepting event items after AgentService commits a terminal state.
5. Commit one `run.cancelled` or `run.failed` transition from the typed error item.
6. Confirm no child/capability side effect continues after terminal parent state.

### Milestone 6: Bound lifecycle memory

1. Remove terminal task/channel entries after subscribers and replay handoff complete.
2. Configure terminal-run TTL, active-run cap, and delivery-channel capacity.
3. Keep durable replay in storage rather than process memory.
4. Expose run timeout, concurrency, delivery capacity, and cancellation grace period in validated config.
5. Do not add a second core/runner event queue.

### Milestone 7: Verification

```bash
cargo fmt --all -- --check
cargo test --locked --test runner_tests
cargo test --locked --test gateway_tests
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
git diff --check
```

## 5. Target criteria

- RSS receives input through `run(input)` arguments only.
- Every accepted run consumes zero or more `Event` items, then one `Complete` or typed error, then end-of-stream.
- Event delivery is live and backpressured by polling.
- AgentService alone assigns durable sequence and replay metadata.
- Capacity rejection creates no session or run.
- Stop, timeout, disconnect, and CPU budget finish within documented bounds.
- No worker publishes state or events after terminal completion.
- Active/terminal run and channel memory are bounded and configurable.
- No generator syntax, terminal future, `RunOutcome`, ambient runtime input, or stack/event result inference remains.
