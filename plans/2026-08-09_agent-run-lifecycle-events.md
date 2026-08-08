# Agent Run Lifecycle and Live Event Plan

**Goal:** Give every agent run one authoritative lifecycle with structured input, separate return/events, live delivery, atomic admission, and bounded cancellation/timeout completion.

**Architecture:** AgentService reserves a run atomically, executes RSS through the core structured run API, streams events through a bounded channel, and commits one terminal transition after worker exit or bounded isolation failure. Platform handlers observe the same run service.

**Tech Stack:** Rust 2024, Tokio/Axum, RustScript AgentRunner, core RunOutcome/event/cancellation contracts.

---

## Independence and dependency

- Independent of durable schema design except for terminal/event persistence hooks.
- Depends on the core RunOutcome/event/error contract and cancellation lifecycle.
- API Server and Telegram both consume this plan.

## Scope boundary

### In scope

- AgentRunner return/event separation.
- Structured run input.
- Live bounded events.
- Atomic admission/session reservation.
- Stop, timeout, disconnect, CPU budget, and worker-exit semantics.
- One terminal transition and bounded in-memory lifecycle.

### Out of scope

- VM internal implementation.
- Provider protocol parsing.
- Durable SQL/schema details.
- Job/cron execution.
- Platform-specific rendering.

## Implementation route

### Milestone 1: Add failing lifecycle tests

**Files:**
- Modify: `tests/runner_tests.rs`
- Modify: `tests/gateway_tests.rs`
- Add race/timeout fixtures under `tests/fixtures/`

Required cases:

- RSS emits an event and returns a different value;
- event is observable before RSS completion;
- structured history/instructions/model/provider reach RSS unchanged;
- unsupported fields receive typed rejection;
- concurrent admission at capacity admits exactly the configured count;
- rejected admission leaves no empty session/run;
- stop and timeout wait for bounded worker exit;
- pure CPU loop reaches terminal state within the configured bound;
- terminal run stop returns its actual state/conflict;
- event and run memory obey retention/TTL.

### Milestone 2: Consume the core structured run contract

**Files:**
- Modify: `src/lib.rs`
- Create/refine: `src/runtime/rss_runner.rs`

1. Return `RunOutcome.return_value` directly.
2. Remove `events.last().or_else(stack.last())` result inference.
3. Pass structured run context through `runtime::input`.
4. Preserve typed terminal errors/cancellation reasons.
5. Compile/cache RSS per script version and create isolated run contexts.

### Milestone 3: Add live event delivery

**Files:**
- Create/refine: `src/events.rs`
- Create/refine: `src/runtime/delivery.rs`
- Modify gateway SSE paths

1. Connect the core event sink to a bounded Tokio channel.
2. Validate canonical agent event shape before publication.
3. Publish runtime events while the worker is active.
4. Allocate one monotonic per-run sequence at the event service boundary.
5. Define backpressure/overflow behavior; silent loss is prohibited.
6. Keep durable append hooks separate from platform rendering.

### Milestone 4: Make admission atomic

**Files:**
- Create/refine: `src/service.rs`
- Modify run/session creation handlers

1. In one service transaction/reservation, validate capacity, resolve/create session, reserve run ID, and install cancellation/event state.
2. Publish the run only after reservation succeeds.
3. Roll back every intermediate state on failure.
4. Use semaphores/reservation tokens instead of count-then-insert phases.

### Milestone 5: Make timeout and cancellation authoritative

1. Define cancellation sources: client stop, client disconnect, run timeout, CPU budget, parent stop, gateway shutdown.
2. Signal the core run token.
3. Wait only for a configured grace period.
4. If an in-process blocking worker cannot exit, mark an explicit isolation failure and prevent further state/event publication from that worker; process isolation is required for capabilities that cannot satisfy this rule.
5. Commit terminal state only once.
6. Confirm no child/capability side effect continues after terminal parent state.

### Milestone 6: Bound lifecycle memory

1. Remove terminal broadcaster/task entries after subscribers and replay handoff are complete.
2. Configure terminal-run TTL and active/event channel caps.
3. Keep durable replay in the storage service, not indefinitely in process memory.
4. Expose run timeout, concurrency, event capacity, and grace period in validated config.

### Milestone 7: Verification

```bash
cargo fmt --all -- --check
cargo test --locked --test runner_tests
cargo test --locked --test gateway_tests
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
git diff --check
```

## Target criteria

- RSS events never replace the RSS return value.
- Events reach subscribers before run completion.
- Every accepted request has one run reservation and one terminal transition.
- Capacity rejection creates no session or run.
- Structured run fields reach RSS or receive explicit typed rejection.
- Stop/timeout/disconnect/CPU budget complete within documented bounds.
- No worker can publish state or events after terminal completion.
- Active/terminal run and broadcaster memory are bounded and configurable.
