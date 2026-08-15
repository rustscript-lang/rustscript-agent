# A6 Narrowed Core Blocker: Script-Internal Task Surface Absent in RustScript

**Date:** 2026-08-15 (narrowed after review)
**Branch:** `feat/agent-a6-subagents`
**Base / integration HEAD:** `300114df834685ce0a102daa1aae5a882a6aed7a`
**Core pinned:** `rustscript-lang/rustscript@fd4b570d08d7cc90cc29e3b05df59c9e9bf3b88e`
(pd-vm, per Cargo.toml)

## 1. What is blocked (the capability) — NARROWED

The ONLY remaining core gap for A6 is a **script-internal generic task
surface**: the RustScript LANGUAGE (strictly synchronous and single-threaded,
no `async`/`await`, no spawn syntax) and the restricted inline agent registry
alone expose no `task` namespace, so a *policy script* cannot itself
`spawn`/`await`/`resume` a concurrent child run inside its own source. There
is no way for the script to drive N concurrent child `run(context)`
invocations itself.

That is a scripting-language limitation only. It does NOT block the
**native/embedding supervision layer** (uncore), which this report shares in
the crate: a native `SubagentSupervisor` drives child runs, consumes the RSS
policy plans (`parallel.rss`/`subagents.rss`) and the existing
`AgentService` semaphore / `AdmitRunRequest.parent_run_id` / tokio worker /
`RunCancellation` / child links to run N child runs concurrently with bounded
concurrency, ordered results, race/fail-fast sibling cancellation, parent
cancellation propagation, depth/fanout budgets, and isolated child sessions.
So the blocker no longer gates the A6 product capability.

## 2. Minimal repro and exact failure (scoped to `task::spawn`)

`tests/fixtures/a6-core-repros/no_task_child_capability.rss` attempts exactly
ONE thing, only the surface asserted in CI: `task::spawn`. Driving it
through `AgentRunner::from_file` fails at **compile** time:

```
Compile("unknown namespace call 'task::spawn'; ... (source ...)")
```

No `task::await`/`task::await_all`/`task::cancel` or language async/await is
claimed or attempted. The CI test `a6_no_task_script_cannot_call_task_spawn`
wires this fixture into the default suite and asserts only that
`task::spawn` is absent.

## 3. What this scope delivers

| Deliverable | Files | Tests |
|---|---|---|
| Parallel execution policy (bounded windows, ordered result slots, race/fail-fast rules, depth/fanout) — pure decision + explicit `executable` handling, native supervisor is the executor | `rss/agent/parallel.rss` | `tests/parallel_tests.rs` |
| Subagent supervision policy (admit eligibility, isolation, parent-cancel propagation, terminal refusal) — decision only | `rss/agent/subagents.rss` | `tests/subagent_tests.rs` |
| Native SubagentSupervisor (uncore): consumes the plan, drives real concurrent child runs | `src/runtime/subagent_supervisor.rs` | new native supervisor tests |
| Serial loop handoff defers with honest `executable:false`/`blocked_reason` | `rss/agent/main.rss` | `tests/agent_loop_tests.rs` |
| Durable child links / list_children / parent identity | re-used | `tests/storage_tests.rs` |
| Narrowed blocker plan + scoped repro wired into CI | this plan + `tests/core_repro_driver.rs` | — |

## 4. The policy never fabricates success

`subagent.admit` in this scope does **not** invent a `subagent.started`
event or a fabricated `run.link_child` before a child is really admitted.
The policy returns a typed plan; the native supervisor produces the
lifecycle event/link only after the child is genuinely admitted (or the
policy stays `executable:false`/`blocked_reason`/`events:[]` while the
executor isn't invoked). No private host function and no direct SQL is
introduced.

## 5. Criteria matrix

| Criterion | Delivered by |
|---|---|
| Bounded concurrency, ordered results, race/fail-fast, parent cancel | Native SubagentSupervisor + plan |
| Depth / fanout rejection | Policy |
| Isolated child sessions/state | Native supervisor (separate child runs) |
| No post-terminal side effects | Policy + native supervisor |
| No fabricated success / no private builtin / no direct SQL | Policies are pure decisions |
| Script-internal `task::spawn` | BLOCKED (language/registry, narrowed; repro wired to CI) |